import requests
import xml.etree.ElementTree as ET
import json
import csv
from openpyxl import Workbook
import sys

# ==========================
# CONFIG
# ==========================
HOST = "https://FW_OR_PANORAMA_IP"
USERNAME = "apiuser"
PASSWORD = "Password123"
PANOS_VERSION = "v10.2"

DEVICE_GROUP = "DG-NAME"   # None for standalone firewall
# DEVICE_GROUP = None

JSON_OUT = "audit_rules.json"
CSV_OUT = "audit_rules.csv"
XLSX_OUT = "audit_rules.xlsx"

requests.packages.urllib3.disable_warnings()


# ==========================
# AUTH
# ==========================
def get_api_key():
    r = requests.post(
        f"{HOST}/api/?type=keygen&user={USERNAME}&password={PASSWORD}",
        verify=False
    )
    root = ET.fromstring(r.text)
    return root.find(".//key").text


def api_get(path, key, params=None):
    r = requests.get(
        f"{HOST}/restapi/{PANOS_VERSION}/{path}",
        headers={"X-PAN-KEY": key},
        params=params,
        verify=False
    )
    if r.status_code != 200:
        sys.exit(r.text)
    return r.json()["result"]["entry"]


# ==========================
# FETCH
# ==========================
def get_rules(key):
    params = {}
    if DEVICE_GROUP:
        params = {"location": "device-group", "device-group": DEVICE_GROUP}
    return api_get("Policies/SecurityRules", key, params)


def get_objects(key, obj, location):
    params = {"location": location}
    if location == "device-group":
        params["device-group"] = DEVICE_GROUP
    return api_get(f"Objects/{obj}", key, params)


# ==========================
# NORMALIZATION
# ==========================
def normalize_services(services):
    out = {}
    for s in services:
        for proto in s.get("protocol", {}):
            out[s["@name"]] = {
                "protocol": proto,
                "port": s["protocol"][proto].get("port", "any")
            }
    return out


def normalize_addresses(addrs):
    out = {}
    for a in addrs:
        name = a["@name"]
        if "ip-netmask" in a:
            out[name] = a["ip-netmask"]
        elif "ip-range" in a:
            out[name] = a["ip-range"]
        elif "fqdn" in a:
            out[name] = a["fqdn"]
        else:
            out[name] = "unknown"
    return out


def normalize_groups(groups):
    return {g["@name"]: g.get("members", []) for g in groups}


# ==========================
# RESOLUTION
# ==========================
def resolve(name, objects, groups, resolved=None):
    if resolved is None:
        resolved = []

    if name in objects:
        resolved.append(objects[name])
    elif name in groups:
        for m in groups[name]:
            resolve(m, objects, groups, resolved)

    return resolved


# ==========================
# MAIN
# ==========================
def main():
    key = get_api_key()

    rules = get_rules(key)

    services = []
    svc_groups = []
    addrs = []
    addr_groups = []

    for loc in ["shared", "device-group"] if DEVICE_GROUP else ["shared"]:
        services += get_objects(key, "Services", loc)
        svc_groups += get_objects(key, "ServiceGroups", loc)
        addrs += get_objects(key, "Addresses", loc)
        addr_groups += get_objects(key, "AddressGroups", loc)

    svc_lookup = normalize_services(services)
    svc_grp_lookup = normalize_groups(svc_groups)
    addr_lookup = normalize_addresses(addrs)
    addr_grp_lookup = normalize_groups(addr_groups)

    rows = []
    json_rules = []

    for r in rules:
        src_ips = []
        dst_ips = []
        ports = []

        for s in r.get("source", []):
            src_ips += resolve(s, addr_lookup, addr_grp_lookup)

        for d in r.get("destination", []):
            dst_ips += resolve(d, addr_lookup, addr_grp_lookup)

        for svc in r.get("service", []):
            if svc in ["any", "application-default"]:
                ports.append({"protocol": svc, "port": svc})
            else:
                for name in resolve(svc, svc_lookup, svc_grp_lookup):
                    ports.append(svc_lookup[name])

        for src in src_ips or ["any"]:
            for dst in dst_ips or ["any"]:
                for p in ports:
                    rows.append([
                        r["@name"],
                        r.get("description", ""),
                        src,
                        dst,
                        p["protocol"],
                        p["port"],
                        r.get("action")
                    ])

        json_rules.append({
            "rule": r["@name"],
            "description": r.get("description", ""),
            "sources": src_ips,
            "destinations": dst_ips,
            "services": ports,
            "action": r.get("action")
        })

    # JSON
    with open(JSON_OUT, "w") as f:
        json.dump(json_rules, f, indent=2)

    # CSV
    with open(CSV_OUT, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Rule Name", "Rule Description",
            "Source IP", "Destination IP",
            "Protocol", "Port", "Action"
        ])
        writer.writerows(rows)

    # Excel
    wb = Workbook()
    ws = wb.active
    ws.append([
        "Rule Name", "Rule Description",
        "Source IP", "Destination IP",
        "Protocol", "Port", "Action"
    ])
    for r in rows:
        ws.append(r)
    wb.save(XLSX_OUT)

    print("Audit export complete")