#!/usr/bin/env python3
# TP-Link TL-WR740N Region Unlocker Skill
# Automates the process of unlocking the region on a Chinese-market TL-WR740N router
# by patching the firmware header's region code and recalculating the MD5 checksum.
# 
# Requirements: requests library
# Environment variables: ROUTER_IP, ROUTER_ADMIN, ROUTER_PASSWORD
# 
# Usage: python3 skill.py --router-ip 192.168.1.1 --admin admin --password secret --region 1
import struct
import hashlib
import requests
import os
import sys
import time
import argparse
from base64 import b64encode
from urllib.parse import quote
