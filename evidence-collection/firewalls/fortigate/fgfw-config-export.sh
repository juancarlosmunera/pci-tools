#!/bin/bash
# fgfw-config-export.sh — FortiGate configuration export for PCI DSS assessment
#
# Exports:
#   1. Full running config as a plain-text file (all sections, complete)
#   2. Individual JSON files for key policy/object tables (Windows-friendly)
#
# Output is a timestamped folder you can zip and hand to an assessor.
# All files open directly in VS Code or Notepad++ on Windows.

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================
FORTIGATE_IP="10.0.1.1"
API_TOKEN="YOUR_API_TOKEN"    # See README for how to generate this
VDOM="root"                   # Default VDOM for standalone FortiGate.
                              # Change if policies live in a different VDOM.
OUTPUT_BASE="/tmp/fortigate-export"
# ==============================================================================

DATE=$(date +%Y%m%d_%H%M%S)
EXPORT_DIR="${OUTPUT_BASE}/fg-${FORTIGATE_IP}-${DATE}"
BASE_URL="https://${FORTIGATE_IP}/api/v2"
AUTH_HEADER="Authorization: Bearer ${API_TOKEN}"

mkdir -p "$EXPORT_DIR"

echo "========================================"
echo "  FortiGate Configuration Export"
echo "  Target : ${FORTIGATE_IP}"
echo "  VDOM   : ${VDOM}"
echo "  Output : ${EXPORT_DIR}"
echo "========================================"

# ------------------------------------------------------------------------------
# Helper: call a CMDB API endpoint and save JSON output
# Usage: cmdb_get "/cmdb/firewall/policy" "firewall-policies.json" "label"
# ------------------------------------------------------------------------------
cmdb_get() {
    local endpoint="$1"
    local outfile="${EXPORT_DIR}/$2"
    local label="$3"

    printf "  %-35s" "${label}..."

    http_code=$(curl -k -s \
        -o "${outfile}" \
        -w "%{http_code}" \
        -H "${AUTH_HEADER}" \
        "${BASE_URL}${endpoint}?vdom=${VDOM}&format=json")

    if [ "$http_code" -ne 200 ]; then
        echo "FAILED (HTTP ${http_code})"
        return 1
    fi

    # Detect API-level errors (HTTP 200 but body is an error response)
    if grep -q '"status":"error"' "${outfile}" 2>/dev/null; then
        echo "FAILED (API returned error — check token permissions)"
        cat "${outfile}"
        return 1
    fi

    local size
    size=$(wc -c < "${outfile}")
    echo "OK (${size} bytes)"
    return 0
}

# ==============================================================================
# 1. FULL RUNNING CONFIGURATION
#    scope=global captures everything: all VDOMs, global settings, policies,
#    objects, routes, interfaces, VPN, admins, logging — the complete picture.
# ==============================================================================
echo ""
echo "[ Full running config ]"
printf "  %-35s" "full config backup..."

FULLCONF="${EXPORT_DIR}/full-config.txt"

http_code=$(curl -k -s \
    -o "${FULLCONF}" \
    -w "%{http_code}" \
    -H "${AUTH_HEADER}" \
    "${BASE_URL}/monitor/system/config/backup?scope=global")

if [ "$http_code" -ne 200 ]; then
    echo "FAILED (HTTP ${http_code}) — check IP, token, and network access"
    exit 1
fi

# Validate the output looks like a FortiGate config, not a JSON error body
if ! grep -q "^config " "${FULLCONF}"; then
    echo "FAILED — output is not a valid FortiGate config. First 5 lines:"
    head -5 "${FULLCONF}"
    exit 1
fi

line_count=$(wc -l < "${FULLCONF}")
echo "OK (${line_count} lines)"

# ==============================================================================
# 2. INDIVIDUAL JSON EXPORTS — key tables for structured Windows review
#    These are the same data as the full config above, but returned as clean
#    JSON objects by the CMDB API. Open in VS Code, Notepad++, or a browser.
# ==============================================================================
echo ""
echo "[ Structured JSON exports ]"

cmdb_get "/cmdb/firewall/policy"          "firewall-policies.json"    "Firewall policies (rulebase)"
cmdb_get "/cmdb/firewall/policy6"         "firewall-policies-ipv6.json" "Firewall policies (IPv6)"
cmdb_get "/cmdb/system/interface"         "interfaces.json"           "Interfaces"
cmdb_get "/cmdb/router/static"            "routes-static.json"        "Static routes"
cmdb_get "/cmdb/router/bgp"               "routes-bgp.json"           "BGP routing"
cmdb_get "/cmdb/router/ospf"              "routes-ospf.json"          "OSPF routing"
cmdb_get "/cmdb/firewall/address"         "address-objects.json"      "Address objects (hosts/subnets)"
cmdb_get "/cmdb/firewall/addrgrp"         "address-groups.json"       "Address groups"
cmdb_get "/cmdb/firewall.service/custom"  "service-objects.json"      "Service objects"
cmdb_get "/cmdb/firewall.service/group"   "service-groups.json"       "Service groups"
cmdb_get "/cmdb/system/admin"             "admin-accounts.json"       "Admin accounts"
cmdb_get "/cmdb/log/syslogd/setting"      "logging-syslog.json"       "Syslog settings"
cmdb_get "/cmdb/system/ntp"               "ntp.json"                  "NTP settings"

# ==============================================================================
# 3. MANIFEST — list all exported files with sizes for chain-of-custody
# ==============================================================================
echo ""
MANIFEST="${EXPORT_DIR}/MANIFEST.txt"
{
    echo "FortiGate Export Manifest"
    echo "Target   : ${FORTIGATE_IP}"
    echo "VDOM     : ${VDOM}"
    echo "Exported : $(date)"
    echo ""
    echo "Files:"
    ls -lh "${EXPORT_DIR}" | awk 'NR>1 {printf "  %-45s %s\n", $NF, $5}'
} > "${MANIFEST}"

echo "========================================"
echo "  Export complete."
echo "  Files saved to: ${EXPORT_DIR}"
echo ""
echo "  For Windows review:"
echo "  - Copy the entire folder to a USB or network share"
echo "  - Open .txt and .json files in VS Code or Notepad++"
echo "    (VS Code: Ctrl+Shift+P > Format Document for JSON pretty-print)"
echo "  - full-config.txt is the complete config — use Ctrl+F to search"
echo "    by section name, e.g. 'config firewall policy'"
echo "========================================"
