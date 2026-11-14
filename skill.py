#!/usr/bin/env python3
"""TP-Link TL-WR740N region unlocker -- firmware patch + upload helper.

Stdlib only, so it runs anywhere Python 3.9+ does, including a phone-termux
shell with nothing but the interpreter installed.

Subcommands
-----------
  info     report digest slots, rehash convention and header strings
  dump     hexdump part of the image
  diff     list byte ranges that differ between two images (find the region field)
  patch    apply byte/string edits and repair the MD5 digests
  upload   preflight, then POST the image to the router's web UI
  fetch    authenticated GET of any path (config backup etc.)
  selftest run built-in checks on a synthetic image, no router needed

Safety: `upload` is a dry run unless --yes is passed. `patch` never writes to
the input file. Nothing here needs root on your machine -- and nothing here can
un-brick a router, so read SKILL.md before flashing.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

import tplink_fw as fw

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_FIRMWARE = 2
EXIT_SAFETY = 3


class SkillError(Exception):
    """Anything the user can fix: bad credentials, unreachable router, ..."""


# --------------------------------------------------------------------------- #
# HTTP plumbing (urllib, no requests)
# --------------------------------------------------------------------------- #


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _basic(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def _request(
    method: str,
    url: str,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30,
    follow: bool = True,
) -> tuple[int, object, bytes]:
    handlers = [urllib.request.HTTPRedirectHandler()] if follow else [_NoRedirect()]
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "Mozilla/5.0 (tplink-region-unlocker)")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()
    except urllib.error.URLError as exc:
        raise SkillError(f"cannot reach {url}: {exc.reason}") from exc
    except OSError as exc:
        raise SkillError(f"network error talking to {url}: {exc}") from exc


def build_multipart(
    field: str, filename: str, content: bytes
) -> tuple[bytes, str]:
    boundary = "----TplinkUnlocker" + hashlib.md5(content).hexdigest()[:20]
    head = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + content + tail, f"multipart/form-data; boundary={boundary}"


def device_banner(router: str, user: str, password: str, timeout: float) -> str:
    """Best-effort model/version string from the login page."""
    base = f"http://{router}"
    status, _, body = _request("GET", base + "/", headers={"Authorization": _basic(user, password)}, timeout=timeout)
    if status == 401:
        raise SkillError(f"{router} rejected the credentials (401)")
    text = body.decode("utf-8", "replace")
    title = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
    model = re.search(r"(?:model|prodname)[^A-Za-z0-9]{0,12}([A-Za-z0-9\-]{4,20})", text, re.I)
    bits = [f"HTTP {status}"]
    if title:
        bits.append(title.group(1).strip()[:80])
    if model:
        bits.append(f"model~{model.group(1)}")
    return " | ".join(bits)


def upload_legacy(
    router: str,
    user: str,
    password: str,
    image: bytes,
    filename: str,
    field: str,
    timeout: float,
    path: str,
) -> tuple[int, bytes]:
    base = f"http://{router}"
    auth = _basic(user, password)
    body, ctype = build_multipart(field, filename, image)
    headers = {
        "Authorization": auth,
        "Content-Type": ctype,
        "Referer": base + "/",
        "Cookie": "Authorization=" + urllib.parse.quote(auth),
    }
    return _request("POST", base + path, data=body, headers=headers, timeout=timeout)[::2]


def luci_session(router: str, user: str, password: str, timeout: float) -> tuple[str, str]:
    """Log in to the LuCI web UI; returns (cookie header, stok)."""
    base = f"http://{router}"
    payload = urllib.parse.urlencode({"username": user, "password": password}).encode()
    status, headers, body = _request(
        "POST",
        base + "/cgi-bin/luci",
        data=payload,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": base + "/",
        },
        timeout=timeout,
        follow=False,
    )
    if status not in (301, 302, 303):
        snippet = body.decode("utf-8", "replace")[:200]
        raise SkillError(f"login did not redirect (HTTP {status}); response: {snippet!r}")

    cookie = ""
    for raw in headers.get_all("Set-Cookie") or []:
        match = re.search(r"sysauth[^=]*=[^;]+", raw)
        if match:
            cookie = match.group(0)
            break
    location = headers.get("Location") or ""
    stok = None
    match = re.search(r"stok=([0-9a-fA-F]+)", location)
    if match:
        stok = match.group(1)
    else:
        match = re.search(rb"stok=([0-9a-fA-F]+)", body)
        if match:
            stok = match.group(1).decode()
    if not stok:
        raise SkillError(
            "logged in but no ;stok= token was returned -- this firmware may use "
            "the legacy upload path; retry with --method legacy"
        )
    return cookie, stok


def upload_luci(
    router: str,
    user: str,
    password: str,
    image: bytes,
    filename: str,
    field: str,
    timeout: float,
    path: str,
) -> tuple[int, bytes]:
    base = f"http://{router}"
    cookie, stok = luci_session(router, user, password, timeout)
    page = base + path.replace("{stok}", stok) if "{stok}" in path else f"{base}{path}"
    if ";stok=" not in page:
        page = f"{base}/cgi-bin/luci/;stok={stok}{path}"
    headers = {"Cookie": cookie} if cookie else {}
    status, _, _ = _request("GET", page, headers=headers, timeout=timeout)
    if status != 200:
        raise SkillError(f"firmware page returned HTTP {status}; aborting before upload")
    body, ctype = build_multipart(field, filename, image)
    headers = dict(headers)
    headers["Content-Type"] = ctype
    headers["Referer"] = page
    return _request("POST", page, data=body, headers=headers, timeout=timeout)[::2]


# --------------------------------------------------------------------------- #
# Arg helpers
# --------------------------------------------------------------------------- #


def parse_offset(text: str) -> int:
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise SkillError(f"bad offset {text!r}: use 0x1234 or 1234") from exc
    if value < 0:
        raise SkillError(f"offset {text!r} is negative")
    return value


def parse_byte_value(text: str) -> bytes:
    out = bytearray()
    for token in text.replace(" ", ",").split(","):
        token = token.strip()
        if not token:
            continue
        if token.lower().startswith("0x"):
            token = token[2:]
        if len(token) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", token):
            raise SkillError(f"bad hex value {token!r}: use pairs such as 0x55 or 0x01ff")
        out += bytes.fromhex(token)
    if not out:
        raise SkillError("empty value")
    return bytes(out)


def parse_pair(text: str, sep: str, what: str) -> tuple[str, str]:
    if sep not in text:
        raise SkillError(f"{what} expects OFFSET{sep}VALUE, got {text!r}")
    left, right = text.split(sep, 1)
    return left.strip(), right.strip()


def read_password(args) -> str:
    if getattr(args, "password_stdin", False):
        return sys.stdin.readline().rstrip("\r\n")
    value = args.password or os.environ.get("ROUTER_PASSWORD")
    if not value:
        raise SkillError(
            "no password: pass --password, --password-stdin or set ROUTER_PASSWORD"
        )
    return value


def resolve_target(args) -> tuple[str, str, str]:
    router = args.router or os.environ.get("ROUTER_IP")
    user = args.user or os.environ.get("ROUTER_ADMIN")
    if not router or not user:
        raise SkillError("missing router/user: use --router/--user or ROUTER_IP/ROUTER_ADMIN")
    return router, user, read_password(args)


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #


def load_image(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise SkillError(f"cannot read {path}: {exc}") from exc
    if not data:
        raise SkillError(f"{path} is empty")
    return data


def cmd_info(args) -> int:
    data = load_image(args.image)
    try:
        report = fw.inspect(data, exhaustive=args.exhaustive)
    except fw.FirmwareError as exc:
        raise SkillError(str(exc)) from exc
    if args.json:
        print(json.dumps(report, indent=2))
        return EXIT_OK
    print(f"image        : {args.image}")
    print(f"size         : {report['size']} bytes ({report['size'] / 1024:.1f} KiB)")
    print(f"sha256       : {hashlib.sha256(data).hexdigest()}")
    print(f"model code   : {report['model_code'] or 'not found'}")
    print(f"version      : {report['version'] or 'not found'}")
    print(f"rehash mode  : {report['rehash_mode'] or 'UNKNOWN (digests do not validate!)'}")
    if report["digests"]:
        print("md5 slots:")
        for slot in report["digests"]:
            print(f"  {slot['offset_hex']}  {slot['stored']}  covers {slot['covers']}")
    else:
        print("md5 slots    : none confirmed")
        print("               a device will likely reject this image; try --exhaustive")
    print("header strings:")
    for item in report["strings"]:
        print(f"  {item['offset']:#05x}  {item['text']!r}")
    return EXIT_OK


def cmd_dump(args) -> int:
    data = load_image(args.image)
    print(fw.hexdump(data, args.start, args.length))
    return EXIT_OK


def cmd_diff(args) -> int:
    left = load_image(args.left)
    right = load_image(args.right)
    if len(left) != len(right):
        print(f"note: sizes differ ({len(left)} vs {len(right)}); tail counted as differing")
    ranges = fw.diff_ranges(left, right)
    try:
        slots = fw.detect_digests(left) + fw.detect_digests(right)
    except fw.FirmwareError:
        slots = []
    slot_offsets = {slot.offset for slot in slots}
    print(f"{len(ranges)} differing range(s):")
    for start, end in ranges:
        label = ""
        if start < fw.HEADER_SIZE:
            label = " header"
        for offset in slot_offsets:
            if start < offset + fw.DIGEST_LEN and offset < end:
                label += " (touches md5)"
        print(f"  {start:#07x}..{end:#07x}  {end - start:5d} byte(s){label}")
        if args.bytes:
            for pos in range(start, min(end, start + args.bytes)):
                print(f"    {pos:#07x}: {left[pos]:02x} -> {right[pos]:02x}")
    interesting = [
        (s, e) for s, e in ranges
        if not any(s < o + fw.DIGEST_LEN and o < e for o in slot_offsets)
    ]
    if interesting:
        print("ranges outside the digest fields (candidates for the region field):")
        for start, end in interesting:
            print(f"  {start:#07x}..{end:#07x}  {left[start:end]!r} -> {right[start:end]!r}")
    return EXIT_OK


def cmd_patch(args) -> int:
    data = load_image(args.image)
    if os.path.abspath(args.out) == os.path.abspath(args.image) and not args.force:
        raise SkillError("--out must differ from the input image (use --force to overwrite)")
    try:
        slots = fw.detect_digests(data, exhaustive=args.exhaustive)
        detected_mode = fw.detect_mode(data, slots)
    except fw.FirmwareError as exc:
        raise SkillError(str(exc)) from exc

    if detected_mode is None and not args.no_rehash:
        raise SkillError(
            "could not confirm the MD5 layout of this image, so it cannot be "
            "repaired safely. Run `info --exhaustive`, or pass --no-rehash to "
            "write a knowingly invalid image (a device will refuse it)."
        )
    if detected_mode is None:
        print("warning: digests not verified; output will need re-signing by other means")

    mode = args.rehash_mode or detected_mode or "zero"
    print(f"digest layout: {len(slots)} slot(s), rehash mode {mode}")
    for slot in slots:
        print(f"  {slot.offset:#05x} covers {slot.coverage.describe(slot.offset)}")

    edited = data
    for spec in args.set_byte:
        offset_text, value_text = parse_pair(spec, "=", "--set-byte")
        offset = parse_offset(offset_text)
        value = parse_byte_value(value_text)
        fw.assert_writable(edited, slots, offset, len(value))
        edited = fw.set_bytes(edited, offset, value)
        print(f"  set  {offset:#07x}..{offset + len(value):#07x} = {value.hex()}")
    for spec in args.set_text:
        offset_text, text = parse_pair(spec, "=", "--set-text")
        offset = parse_offset(offset_text)
        value = text.encode("ascii", "strict")
        fw.assert_writable(edited, slots, offset, len(value))
        edited = fw.set_bytes(edited, offset, value)
        print(f"  text {offset:#07x}..{offset + len(value):#07x} = {text!r}")
    for spec in args.replace_text:
        old_text, new_text = parse_pair(spec, "=", "--replace-text")
        old = old_text.encode("ascii", "strict")
        new = new_text.encode("ascii", "strict")
        hits: list[int] = []
        if args.all:
            previous = None
            while len(hits) < 4096:
                edited, found = fw.replace_text(edited, old, new, limit=1)
                if not found or found[0] == previous:
                    break
                previous = found[0]
                hits.append(found[0])
        else:
            edited, hits = fw.replace_text(edited, old, new, limit=1)
        if not hits:
            print(f"  warning: {old_text!r} not present anywhere in the image")
        for hit in hits:
            print(f"  text {hit:#07x} {old_text!r} -> {new_text!r}")

    if edited == data:
        raise SkillError("no edits applied; nothing to do")

    if not args.no_rehash:
        edited = fw.finalize(edited, slots, mode)
        results = fw.verify(edited, slots, mode)
        for slot, ok in results:
            print(f"  md5 {slot.offset:#05x}: {'OK' if ok else 'MISMATCH'} {edited[slot.offset:slot.end].hex()}")
        if not all(ok for _, ok in results):
            raise SkillError("digest repair failed; refusing to write a corrupt image")

    try:
        with open(args.out, "wb") as handle:
            handle.write(edited)
    except OSError as exc:
        raise SkillError(f"cannot write {args.out}: {exc}") from exc

    changed = sum(1 for a, b in zip(data, edited) if a != b)
    print(f"wrote {args.out}: {len(edited)} bytes, {changed} byte(s) changed")
    print(f"sha256 {hashlib.sha256(edited).hexdigest()}")
    return EXIT_OK


def _preflight(image: bytes, args) -> tuple[bytes, list[fw.DigestSlot], str | None]:
    try:
        slots = fw.detect_digests(image, exhaustive=args.exhaustive)
        mode = fw.detect_mode(image, slots)
    except fw.FirmwareError as exc:
        raise SkillError(str(exc)) from exc

    if not slots:
        message = "no MD5 slot could be confirmed in this image"
        if not args.allow_unverified:
            raise SkillError(message + "; the router will reject it. Use --allow-unverified to force.")
        print(f"warning: {message}")
    elif mode is None:
        message = "digests present but none validate"
        if not args.allow_unverified:
            raise SkillError(message + "; run `info` and patch again. Use --allow-unverified to force.")
        print(f"warning: {message}")
    else:
        print(f"digests: {len(slots)} slot(s) validated, mode {mode}")

    if args.expect_model:
        strings = fw.header_strings(image)
        model = fw.guess_model_code(strings) or ""
        blob = " ".join(text for _, text in strings)
        if args.expect_model.lower() not in (model + " " + blob).lower():
            raise SkillError(
                f"image does not look like {args.expect_model!r} "
                f"(header model code {model or 'not found'})"
            )
        print(f"model check: {args.expect_model!r} found in header")

    for slot in slots:
        print(f"  md5 {slot.offset:#05x} covers {slot.coverage.describe(slot.offset)}")
    print(f"sha256: {hashlib.sha256(image).hexdigest()}")
    return image, slots, mode


def _plan(method: str, path: str, field: str, filename: str, size: int) -> None:
    print(f"method: {method}")
    print(f"path  : {path}")
    print(f"field : {field!r}  filename {filename!r}  size {size} bytes")


def cmd_upload(args) -> int:
    image = load_image(args.image)
    _preflight(image, args)

    router = args.router or os.environ.get("ROUTER_IP") or "<router>"
    method = args.method
    if method == "auto":
        _plan("auto (legacy|luci chosen at flash time)", args.path or "/incoming/Firmware.htm", args.file_field or "auto", args.filename, len(image))
    else:
        default = "/incoming/Firmware.htm" if method == "legacy" else "/cgi-bin/luci/;stok={stok}/admin/firmware"
        _plan(method, args.path or default, args.file_field or ("filename" if method == "legacy" else "firmware"), args.filename, len(image))
    print(f"target: http://{router}")

    if not args.yes:
        print("")
        print("DRY RUN: nothing was sent and the router was not contacted. Re-run with --yes to flash.")
        print("Before you do: confirm you can recover this router without the web UI")
        print("(bootloader TFTP, or a full flash dump taken with a SPI clip).")
        return EXIT_OK

    router, user, password = resolve_target(args)
    print(f"banner: {device_banner(router, user, password, args.timeout)}")

    if method == "auto":
        status, _, body = _request(
            "GET", f"http://{router}/",
            headers={"Authorization": _basic(user, password)}, timeout=args.timeout,
        )
        probe = body.decode("utf-8", "replace").lower()
        method = "luci" if ("luci" in probe or "stok" in probe) else "legacy"
        print(f"method: {method} (auto-detected)")

    if args.path:
        path = args.path
    elif method == "luci":
        path = "/cgi-bin/luci/;stok={stok}/admin/firmware"
    else:
        path = "/incoming/Firmware.htm"
    field = args.file_field or ("filename" if method == "legacy" else "firmware")
    _plan(method, path, field, args.filename, len(image))

    print("")
    print("flashing; the router will stop responding and reboot when it accepts the image...")
    if method == "legacy":
        status, body = upload_legacy(router, user, password, image, args.filename, field, args.timeout, path)
    else:
        status, body = upload_luci(router, user, password, image, args.filename, field, args.timeout, path)

    snippet = body.decode("utf-8", "replace").strip()[:300]
    print(f"HTTP {status}")
    if snippet:
        print(f"response: {snippet}")
    if status >= 400:
        raise SkillError("device refused the upload; the image was probably rejected")
    print("upload accepted. Wait ~2 minutes, then check the router at its new firmware.")
    return EXIT_OK


def cmd_fetch(args) -> int:
    router, user, password = resolve_target(args)
    url = f"http://{router}{args.path}"
    headers = {"Authorization": _basic(user, password)}
    if args.cookie:
        headers["Cookie"] = args.cookie
    print(f"GET {url}")
    status, _, body = _request("GET", url, headers=headers, timeout=args.timeout)
    if status != 200:
        raise SkillError(f"HTTP {status} for {args.path}")
    try:
        with open(args.out, "wb") as handle:
            handle.write(body)
    except OSError as exc:
        raise SkillError(f"cannot write {args.out}: {exc}") from exc
    print(f"wrote {args.out}: {len(body)} bytes")
    return EXIT_OK


def cmd_selftest(args) -> int:
    """Prove the analyse/patch/verify round trip on a synthetic image.

    The synthetic header puts its digests at 0x80/0x90 and its region marker at
    0x60 -- offsets that deliberately match no real TP-Link layout, so a pass
    proves the tool discovers structure instead of trusting constants.
    """
    def build(region: bytes) -> bytes:
        payload = bytearray()
        seed = b"tplink-sample"
        while len(payload) < 4096:
            seed = hashlib.sha256(seed).digest()
            payload += seed
        header = bytearray(b"\x00" * fw.HEADER_SIZE)
        header[0x00:0x04] = (0x01000004).to_bytes(4, "big")
        header[0x04:0x18] = b"TP-LINK Technologies"
        header[0x20:0x40] = b"3.16.9 Build 150311 Rel.35986n"
        header[0x40:0x48] = b"07400004"
        header[0x60:0x62] = region
        image = bytes(header) + bytes(payload)
        plan = [
            fw.DigestSlot(0x80, fw.Coverage(((0, fw.HEADER_SIZE), (fw.HEADER_SIZE, len(image))))),
            fw.DigestSlot(0x90, fw.Coverage(((fw.HEADER_SIZE, len(image)),))),
        ]
        return fw.finalize(image, plan, "zero")

    failures = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal failures
        print(f"  {'PASS' if condition else 'FAIL'}  {name}{(' -- ' + detail) if detail and not condition else ''}")
        if not condition:
            failures += 1

    print("selftest: synthetic image, offsets that match no real TP-Link layout")
    image = build(b"CN")
    slots = fw.detect_digests(image)
    offsets = [slot.offset for slot in slots]
    check("finds both digests", offsets == [0x80, 0x90], f"got {[hex(o) for o in offsets]}")
    check("rehash mode is zero", fw.detect_mode(image, slots) == "zero")
    check("header strings parsed", ("07400004" == fw.guess_model_code(fw.header_strings(image))))

    patched = fw.set_bytes(image, 0x60, b"US")
    patched = fw.finalize(patched, slots, "zero")
    check("patched image verifies", all(ok for _, ok in fw.verify(patched, slots, "zero")))
    changed = {i for i in range(len(image)) if image[i] != patched[i]}
    # slot 0x90 covers the payload only, and the payload did not change, so its
    # digest must stay identical -- that is the whole point of discovery.
    check("only region byte + covering digest changed",
          changed <= {0x60, 0x61} | set(range(0x80, 0x90)), f"changed={sorted(changed)}")
    check("unaffected payload digest untouched",
          image[0x90:0xA0] == patched[0x90:0xA0])

    stale = fw.verify(fw.set_bytes(image, 0x60, b"US"), slots, "zero")
    check("digest mismatch is detected", not all(ok for _, ok in stale))

    ranges = fw.diff_ranges(image, patched)
    check("diff isolates the region bytes", (0x60, 0x62) in ranges, f"got {ranges}")

    text, hits = fw.replace_text(image, b"35986", b"35987")
    check("text replacement finds one hit", hits == [0x38] and text[0x38:0x3E] == b"35987n", f"hits={hits}")

    try:
        fw.assert_writable(image, slots, 0x84, 1)
        check("refuses to overwrite a digest", False)
    except fw.FirmwareError:
        check("refuses to overwrite a digest", True)

    multipart, ctype = build_multipart("filename", "fw.bin", b"abc")
    check("multipart body is well formed", multipart.startswith(b"--") and multipart.endswith(b"--\r\n") and "boundary=" in ctype)

    print("selftest:", "FAILED" if failures else "all checks passed")
    return EXIT_FIRMWARE if failures else EXIT_OK


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skill.py",
        description="Inspect, patch and upload TP-Link firmware images (region unlock helper).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="report digest layout and header strings")
    info.add_argument("image")
    info.add_argument("--exhaustive", action="store_true", help="skip the high-entropy prefilter")
    info.add_argument("--json", action="store_true")
    info.set_defaults(func=cmd_info)

    dump = sub.add_parser("dump", help="hexdump part of an image")
    dump.add_argument("image")
    dump.add_argument("--start", type=parse_offset, default=0)
    dump.add_argument("--length", type=parse_offset, default=0x200)
    dump.set_defaults(func=cmd_dump)

    diff = sub.add_parser("diff", help="show byte ranges that differ between two images")
    diff.add_argument("left")
    diff.add_argument("right")
    diff.add_argument("--bytes", type=int, default=0, help="also list the first N differing bytes per range")
    diff.set_defaults(func=cmd_diff)

    patch = sub.add_parser("patch", help="edit bytes and repair the MD5 digests")
    patch.add_argument("image")
    patch.add_argument("--out", required=True)
    patch.add_argument("--set-byte", action="append", default=[], metavar="OFFSET=HEX")
    patch.add_argument("--set-text", action="append", default=[], metavar="OFFSET=ASCII")
    patch.add_argument("--replace-text", action="append", default=[], metavar="OLD=NEW")
    patch.add_argument("--all", action="store_true", help="replace every occurrence")
    patch.add_argument("--no-rehash", action="store_true", help="leave digests alone (output will be rejected)")
    patch.add_argument("--rehash-mode", choices=("zero", "asis"))
    patch.add_argument("--exhaustive", action="store_true")
    patch.add_argument("--force", action="store_true", help="allow --out to be the input file")
    patch.set_defaults(func=cmd_patch)

    upload = sub.add_parser("upload", help="preflight then POST the image to the router")
    upload.add_argument("image")
    upload.add_argument("--router", help="router IP (or ROUTER_IP)")
    upload.add_argument("--user", help="admin user (or ROUTER_ADMIN)")
    upload.add_argument("--password", help="admin password (or ROUTER_PASSWORD)")
    upload.add_argument("--password-stdin", action="store_true")
    upload.add_argument("--method", choices=("auto", "legacy", "luci"), default="auto")
    upload.add_argument("--path", help="override the upload URL path")
    upload.add_argument("--file-field", help="override the multipart field name")
    upload.add_argument("--filename", default="fw.bin", help="filename announced to the router")
    upload.add_argument("--timeout", type=float, default=60.0)
    upload.add_argument("--expect-model", help="refuse unless this string is in the header")
    upload.add_argument("--allow-unverified", action="store_true")
    upload.add_argument("--exhaustive", action="store_true")
    upload.add_argument("--yes", action="store_true", help="actually flash")
    upload.set_defaults(func=cmd_upload)

    fetch = sub.add_parser("fetch", help="authenticated GET of a single path")
    fetch.add_argument("--path", required=True)
    fetch.add_argument("--out", required=True)
    fetch.add_argument("--cookie")
    fetch.add_argument("--router")
    fetch.add_argument("--user")
    fetch.add_argument("--password")
    fetch.add_argument("--password-stdin", action="store_true")
    fetch.add_argument("--timeout", type=float, default=30.0)
    fetch.set_defaults(func=cmd_fetch)

    selftest = sub.add_parser("selftest", help="run built-in checks on a synthetic image")
    selftest.set_defaults(func=cmd_selftest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SkillError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_SAFETY
    except fw.FirmwareError as exc:
        print(f"firmware error: {exc}", file=sys.stderr)
        return EXIT_FIRMWARE
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
