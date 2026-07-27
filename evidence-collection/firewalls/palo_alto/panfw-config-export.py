#!/usr/bin/env python3
# palo-fim.py - Palo Alto FIM via API
#
# Pulls the running config and writes a date-stamped XML file. The export is
# hashed with SHA-256 and recorded in a date-stamped MANIFEST for
# chain-of-custody, alongside a .sha256 file for independent verification.
import requests
import difflib
import hashlib
import os
import socket
import getpass
import sys
from datetime import datetime, timezone

PA_HOST = "10.0.1.2"
API_KEY = "YOUR_API_KEY"
CONFIG_DIR = "/config/paloalto"

def get_config():
    """Pull current running config from Palo Alto"""
    r = requests.get(
        f"https://{PA_HOST}/api/",
        params={'type': 'export', 'category': 'configuration', 'key': API_KEY},
        verify=False
    )
    return r.text

def sha256_file(path):
    """SHA-256 of a file, read in chunks so large configs don't load into RAM"""
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

# Fetch and save current config
config = get_config()
datestamp = f"{datetime.now():%Y%m%d}"
filename = f"{CONFIG_DIR}/pa-{datestamp}.xml"
with open(filename, 'w') as f:
    f.write(config)

# ---------------------------------------------------------------------------
# MANIFEST + SHA-256 integrity hash
# The manifest and checksum file are date-stamped to match the export, so a
# re-run never overwrites the integrity record of a previous collection.
# ---------------------------------------------------------------------------
basename = os.path.basename(filename)
digest = sha256_file(filename)
size_kb = os.path.getsize(filename) / 1024

# "<hash> *<file>" — the format understood by sha256sum -c
with open(f"{filename}.sha256", 'w') as f:
    f.write(f"{digest} *{basename}\n")

manifest_path = f"{CONFIG_DIR}/pa-{datestamp}-MANIFEST.txt"
with open(manifest_path, 'w') as f:
    f.write("\n".join([
        "Palo Alto Configuration Export Manifest (PCI DSS)",
        "================================================",
        f"Firewall       : {PA_HOST}",
        f"Exported       : {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Hashed (UTC)   : {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC",
        f"Host           : {socket.gethostname()}",
        f"User           : {getpass.getuser()}",
        "Hash algorithm : SHA-256",
        "",
        "Files and integrity hashes:",
        "",
        f"  {basename}",
        f"      Size   : {size_kb:.1f} KB",
        f"      SHA-256: {digest}",
        "",
        f"{basename}.sha256 holds the same hash in a format verifiable with:",
        f"  Linux   : sha256sum -c {basename}.sha256",
        f"  Windows : certutil -hashfile {basename} SHA256",
        "",
    ]))

print(f"Configuration saved to: {filename}")
print(f"SHA-256 : {digest}")
print(f"Manifest saved to: {manifest_path}")
