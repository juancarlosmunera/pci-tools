#!/usr/bin/env python3
# palo-fim.py - Palo Alto FIM via API
import requests
import difflib
import sys
from datetime import datetime

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

# Fetch and save current config
config = get_config()
filename = f"{CONFIG_DIR}/pa-{datetime.now():%Y%m%d}.xml"
with open(filename, 'w') as f:
    f.write(config)