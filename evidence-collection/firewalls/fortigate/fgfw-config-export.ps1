<#
.SYNOPSIS
    Export a FortiGate firewall configuration for PCI DSS assessment.

.DESCRIPTION
    Connects to a FortiGate firewall via the REST API and exports:
      1. Full running configuration as full-config.txt (all sections, complete)
      2. Individual JSON files for key tables: rulebase, interfaces, address
         objects, service objects, routes, admin accounts, and logging config.

    All output is saved to a timestamped folder ready to hand to a PCI assessor.
    All files open directly in VS Code or Notepad++ on Windows.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.NOTES
    See fgfw-config-export_powershell_readme.txt for full setup instructions.
#>

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================
$FortiGateIP = "10.0.1.1"
$ApiToken    = "YOUR_API_TOKEN"    # See README for how to generate this
$Vdom        = "root"              # Default VDOM for a standalone FortiGate.
                                   # Change if your policies live in another VDOM.
$OutputBase  = "C:\fortigate-export"
# ==============================================================================

$Date      = Get-Date -Format "yyyyMMdd_HHmmss"
$ExportDir = Join-Path $OutputBase "fg-$FortiGateIP-$Date"
$BaseUrl   = "https://$FortiGateIP/api/v2"
$Headers   = @{ "Authorization" = "Bearer $ApiToken" }

# ---------------------------------------------------------------------------
# SSL / TLS — bypass self-signed certificate check (standard on FortiGate)
# ---------------------------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -ge 7) {
    # PowerShell 7+: apply globally for this session via default parameters
    $PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true
} else {
    # Windows PowerShell 5.1: patch the certificate validation callback
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
    [System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]::Tls12
}

New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

Write-Host "========================================"
Write-Host "  FortiGate Configuration Export"
Write-Host "  Target : $FortiGateIP"
Write-Host "  VDOM   : $Vdom"
Write-Host "  Output : $ExportDir"
Write-Host "========================================"

# ---------------------------------------------------------------------------
# Helper: call a FortiGate CMDB API endpoint and save the JSON response
# ---------------------------------------------------------------------------
function Invoke-CmdbGet {
    param(
        [string]$Endpoint,
        [string]$FileName,
        [string]$Label
    )

    $outPath = Join-Path $ExportDir $FileName
    $uri     = "${BaseUrl}${Endpoint}?vdom=${Vdom}&format=json"

    Write-Host -NoNewline ("  " + $Label.PadRight(35) + "...")

    try {
        $resp = Invoke-WebRequest `
            -Uri     $uri `
            -Headers $Headers `
            -Method  Get `
            -ErrorAction Stop

        [System.IO.File]::WriteAllText($outPath, $resp.Content, [System.Text.Encoding]::UTF8)

        # Detect API-level errors (HTTP 200 but body signals a failure)
        if ($resp.Content -match '"status"\s*:\s*"error"') {
            Write-Host " FAILED (API returned error — check token permissions)"
            Write-Host $resp.Content
            return
        }

        $sizeKB = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
        Write-Host " OK (${sizeKB} KB)"

    } catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code) {
            Write-Host " FAILED (HTTP $code)"
        } else {
            Write-Host " FAILED ($_)"
        }
    }
}

# ==============================================================================
# 1. FULL RUNNING CONFIGURATION
#    scope=global captures everything: all VDOMs, global settings, policies,
#    objects, routes, interfaces, VPN, admins, logging — the complete picture.
# ==============================================================================
Write-Host ""
Write-Host "[ Full running config ]"
Write-Host -NoNewline ("  " + "full config backup...".PadRight(35) + "...")

$fullConfPath = Join-Path $ExportDir "full-config.txt"

try {
    $resp = Invoke-WebRequest `
        -Uri     "$BaseUrl/monitor/system/config/backup?scope=global" `
        -Headers $Headers `
        -Method  Get `
        -ErrorAction Stop

    [System.IO.File]::WriteAllText($fullConfPath, $resp.Content, [System.Text.Encoding]::UTF8)

} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Write-Host " FAILED (HTTP $code) — check IP, token, and network access"
    exit 1
}

# Validate the output is a FortiGate config, not a JSON error body
$firstLines    = Get-Content $fullConfPath -TotalCount 10 -ErrorAction SilentlyContinue
$isValidConfig = $firstLines | Where-Object { $_ -match "^config " }

if (-not $isValidConfig) {
    Write-Host " FAILED — output is not a valid FortiGate config. First lines:"
    $firstLines | ForEach-Object { Write-Host "  $_" }
    Remove-Item $ExportDir -Recurse -Force
    exit 1
}

$lineCount = (Get-Content $fullConfPath).Count
Write-Host " OK ($lineCount lines)"

# ==============================================================================
# 2. INDIVIDUAL JSON EXPORTS — key tables for structured Windows review
#    Same data as the full config above, but returned as clean structured JSON
#    by the CMDB API. Open in VS Code, Notepad++, or drag into a browser tab.
# ==============================================================================
Write-Host ""
Write-Host "[ Structured JSON exports ]"

Invoke-CmdbGet "/cmdb/firewall/policy"          "firewall-policies.json"      "Firewall policies (rulebase)"
Invoke-CmdbGet "/cmdb/firewall/policy6"         "firewall-policies-ipv6.json" "Firewall policies (IPv6)"
Invoke-CmdbGet "/cmdb/system/interface"         "interfaces.json"             "Interfaces"
Invoke-CmdbGet "/cmdb/router/static"            "routes-static.json"          "Static routes"
Invoke-CmdbGet "/cmdb/router/bgp"               "routes-bgp.json"             "BGP routing"
Invoke-CmdbGet "/cmdb/router/ospf"              "routes-ospf.json"            "OSPF routing"
Invoke-CmdbGet "/cmdb/firewall/address"         "address-objects.json"        "Address objects (hosts/subnets)"
Invoke-CmdbGet "/cmdb/firewall/addrgrp"         "address-groups.json"         "Address groups"
Invoke-CmdbGet "/cmdb/firewall.service/custom"  "service-objects.json"        "Service objects"
Invoke-CmdbGet "/cmdb/firewall.service/group"   "service-groups.json"         "Service groups"
Invoke-CmdbGet "/cmdb/system/admin"             "admin-accounts.json"         "Admin accounts"
Invoke-CmdbGet "/cmdb/log/syslogd/setting"      "logging-syslog.json"         "Syslog settings"
Invoke-CmdbGet "/cmdb/system/ntp"               "ntp.json"                    "NTP settings"

# ==============================================================================
# 3. MANIFEST — list all exported files with sizes for chain-of-custody
# ==============================================================================
Write-Host ""

$manifestPath = Join-Path $ExportDir "MANIFEST.txt"
$files        = Get-ChildItem $ExportDir | Where-Object { $_.Name -ne "MANIFEST.txt" } | Sort-Object Name

$manifestLines = @(
    "FortiGate Export Manifest"
    "Target   : $FortiGateIP"
    "VDOM     : $Vdom"
    "Exported : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Host     : $env:COMPUTERNAME"
    "User     : $env:USERNAME"
    ""
    "Files:"
)
foreach ($f in $files) {
    $sizeKB = [math]::Round($f.Length / 1KB, 1)
    $manifestLines += "  {0,-48} {1} KB" -f $f.Name, $sizeKB
}
$manifestLines | Out-File -FilePath $manifestPath -Encoding UTF8

Write-Host "========================================"
Write-Host "  Export complete."
Write-Host "  Files saved to: $ExportDir"
Write-Host ""
Write-Host "  For assessor review:"
Write-Host "  - Open .txt and .json files in VS Code or Notepad++"
Write-Host "    (VS Code: Ctrl+Shift+P > Format Document for JSON pretty-print)"
Write-Host "  - full-config.txt is the complete config -- use Ctrl+F to search"
Write-Host "    by section name, e.g. 'config firewall policy'"
Write-Host "========================================"
