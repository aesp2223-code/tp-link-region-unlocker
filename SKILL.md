---
name: tp-link-region-unlocker
description: Inspect, patch and upload TP-Link TL-WR740N firmware images to change the region/regulatory field, with MD5 re-signing and brick-safety gates. Use when asked to region-unlock or de-CN a TL-WR740N, change its wireless regulatory domain, or when a hand-patched TP-Link image must pass the router's own checksum check before flashing.
---

# TP-Link TL-WR740N region unlocker

Firmware-level tooling for changing the region field in a TL-WR740N image and
re-signing it so the router accepts it. Pure Python 3, standard library only.

## The one design decision that matters

**No header offset is hardcoded.**

TP-Link reuses the same 512-byte header shape across hardware revisions but not
the same field offsets, and a wrong offset bricks the device. So this tool does
not claim to know where the MD5 digests live: it searches the header for
16-byte windows whose MD5 over a plausible byte range reproduces them, and only
calls a slot "confirmed" when that fixpoint check passes. Everything else is
reported as advisory.

| Fact | Status |
| --- | --- |
| Header is the first 0x200 bytes | assumed, stated by the vendor format |
| MD5 digest slots and what they cover | **verified per image**, at runtime |
| Rehash convention (`zero` vs `asis`) | **verified per image**, at runtime |
| Model code / firmware version strings | parsed, advisory |
| Where the region byte is | **not known a priori** -- see "Finding the region byte" |
| Whether the region lock lives only in the header | **no** -- see "What this cannot promise" |

## Commands

```bash
python skill.py info  fw.bin                       # digests, mode, header strings
python skill.py dump  fw.bin --start 0x40 --length 0x80
python skill.py diff  cn.bin us.bin --bytes 8      # locate the region field
python skill.py patch fw.bin --out out.bin --set-text 0x60=US
python skill.py patch fw.bin --out out.bin --replace-text CN=US
python skill.py upload out.bin --router 192.168.1.1 --user admin --password-stdin
python skill.py fetch  --router 192.168.1.1 --user admin --password-stdin \
                       --path /incoming/BackupCfg.htm --out cfg.bin
python skill.py selftest                           # 11 checks, no hardware
python -m unittest discover -s tests               # 17 checks, no hardware
```

Environment variables replace the flags: `ROUTER_IP`, `ROUTER_ADMIN`,
`ROUTER_PASSWORD`. Prefer `--password-stdin` or `ROUTER_PASSWORD` over
`--password`, which leaks into the process list.

`upload` is a **dry run by default**: it validates the image, prints the plan,
and does not touch the network. `--yes` is required to send anything.

## Finding the region byte

There is no universal offset for this, and guessing is how routers die. Get two
images for the same hardware revision -- a CN-market build and any international
build -- and diff them:

```bash
python skill.py diff cn.bin intl.bin --bytes 16
```

The tool separates the noise (MD5 fields, which always differ) from the signal
and prints the candidate ranges with their bytes:

```
ranges outside the digest fields (candidates for the region field):
  0x00060..0x00062  b'CN' -> b'US'
```

A two-byte ASCII marker like that is the usual culprit. If the diff shows a
single changed byte instead, patch it as one:

```bash
python skill.py patch cn.bin --out out.bin --set-byte 0x60=0x01
```

If the diff is large and scattered, stop: you are probably looking at two
different firmware *versions*, not two regions, and any patch derived from it is
meaningless.

## What `patch` guarantees

1. Every edit is bounds-checked and refused if it would land on a confirmed
   digest slot.
2. String replacements pad with `0x00` rather than shifting the image; a longer
   replacement is rejected outright, because a shifted image is a brick.
3. All confirmed digests are recomputed, then re-verified. A mismatch aborts
   before anything is written.
4. `--out` must differ from the input unless `--force` is given.

If the digest layout cannot be confirmed, `patch` refuses. That refusal is the
feature: an image whose checksums you cannot reproduce will be rejected by the
router at best, and half-flashed at worst. `--no-rehash` exists for inspection
workflows and warns loudly.

## Flashing

`upload` tries two transports and auto-detects which one the device speaks:

| Transport | Path | Multipart field |
| --- | --- | --- |
| legacy stock UI | `/incoming/Firmware.htm` | `filename` |
| LuCI | `/cgi-bin/luci/;stok=<stok>/admin/firmware` | `firmware` |

Override with `--method legacy|luci`, `--path`, `--file-field`. The `filename`
sent in the multipart part defaults to `fw.bin`; some stock UIs are picky about
seeing a `.bin` name, so keep the extension.

Gates before a byte is sent:

* digests must validate (or `--allow-unverified`);
* `--expect-model 0740` refuses an image whose header does not match;
* the device must answer with working credentials, and the LuCI firmware page
  must return HTTP 200 before the POST.

After a successful upload the router reboots and drops the connection. That is
expected, not an error.

## What this cannot promise

* **The header may not be the only lock.** These units also carry regulatory
  settings in the ART/calibration partition and gate some behaviour in the
  bootloader. A valid header patch can still be ignored, and the shortest path
  is usually a matching international stock image for the same hardware
  revision rather than a patched CN one.
* **Channel availability is regulatory, not cosmetic.** Enabling channels your
  country does not permit is your liability, and the radio calibration data may
  not have been characterised for them.
* **No hardware was used to validate this repository.** The digest discovery,
  patch, re-sign and upload paths are covered by synthetic images plus a mock
  HTTP server (`selftest`, `tests/`). Real-device verification is on you.

## Recovery, before you flash

Have one of these working *first*:

1. **Bootloader TFTP**: hold reset while powering on, set your NIC to
   `192.168.0.2/24`, then `tftp` the stock image to `192.168.0.1`. Windows:
   `tftp -i 192.168.0.1 put fw.bin`. The window is a few seconds long, so
   pre-stage it.
2. **Serial console** on the header pins at 115200 8N1, to interrupt U-Boot.
3. **Full flash dump** taken with a SPI clip before any write. A 4 MB dump is
   your only real undo button; config backups are not.

`fetch` retrieves whatever the UI exposes (config backup, for instance) but a
config archive will not restore firmware. Do not mistake one for the other.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no MD5 slot could be confirmed` | non-vendor image, stripped header, or digests not MD5 | `info --exhaustive`; confirm it is really a TP-Link image |
| `digests present but none validate` | truncated download or re-signed by another tool | re-download; or `patch --rehash-mode asis` |
| upload `HTTP 401/403` | wrong credentials, or the UI wants a session cookie | check creds; try `--method luci`/`legacy` |
| upload returns the login page | session expired between probe and POST | retry; keep `--path` explicit |
| router reboots into the old firmware | image rejected, bootloader fell back | digests are wrong -- rerun `info` on the *file you sent* |
| router dead, no web UI | bad image | bootloader TFTP, then serial |

## Scope

Only devices you own or administer. Reading and patching firmware is
interoperability work; using it to escape a lock you are contractually or
legally bound by is not something this tool should be aimed at.
