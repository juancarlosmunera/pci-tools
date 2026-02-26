<#
.SYNOPSIS
    Export a Palo Alto firewall running configuration via the XML API.

.DESCRIPTION
    Connects to a Palo Alto firewall using an API key and downloads the full
    running configuration as a date-stamped XML file. Intended for use by a
    sysadmin to collect evidence for a PCI DSS assessment.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.NOTES
    Prerequisites:
      - An API key for the firewall (generate via: Devices > Administrators >
        your user > Generate API Key, or use the /api/?type=keygen endpoint)
      - Network access to the firewall management interface
      - The output directory must already exist

    To generate an API key via CLI (run once, then paste the key below):
      $cred = Get-Credential
      Invoke-RestMethod "https://<FW_IP>/api/?type=keygen&user=$($cred.UserName)&password=$($cred.GetNetworkCredential().Password)" -SkipCertificateCheck
#>

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================
$PA_HOST   = "10.0.1.2"                    # Firewall management IP or hostname
$API_KEY   = "YOUR_API_KEY"                 # PAN-OS API key
$ConfigDir = "C:\PCI-Evidence\paloalto"    # Output folder (must already exist)
# ==============================================================================

# ---------------------------------------------------------------------------
# SSL / TLS — bypass self-signed certificate check (common on PAN-OS devices)
# ---------------------------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -ge 7) {
    # PowerShell 7+: use the built-in parameter (set as a preference variable
    # so the Invoke-RestMethod call below doesn't need a flag on every call)
    $PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
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

# ---------------------------------------------------------------------------
# Pull the running configuration
# ---------------------------------------------------------------------------
$uri = "https://$PA_HOST/api/"
$params = @{
    type     = "export"
    category = "configuration"
    key      = $API_KEY
}

Write-Host "Connecting to $PA_HOST ..."

try {
    $response = Invoke-RestMethod -Uri $uri -Method Get -Body $params -ErrorAction Stop
} catch {
    Write-Error "Failed to retrieve configuration: $_"
    exit 1
}

# ---------------------------------------------------------------------------
# Save to a date-stamped XML file
# ---------------------------------------------------------------------------
$datestamp = Get-Date -Format "yyyyMMdd"
$outFile   = Join-Path $ConfigDir "pa-$datestamp.xml"

try {
    # Palo Alto returns an XML document object when using Invoke-RestMethod;
    # convert it back to a formatted XML string before saving.
    $xmlString = $response.OuterXml
    if (-not $xmlString) {
        # Fallback: response may already be a raw string in some PS versions
        $xmlString = $response
    }
    [System.Xml.Linq.XDocument]::Parse($xmlString).Save($outFile)
} catch {
    # If XML pretty-printing fails, write the raw content
    $xmlString | Out-File -FilePath $outFile -Encoding UTF8
}

Write-Host "Configuration saved to: $outFile"
