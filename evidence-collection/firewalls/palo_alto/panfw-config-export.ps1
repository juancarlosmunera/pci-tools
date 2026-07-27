<#
.SYNOPSIS
    Export a Palo Alto firewall running configuration via the XML API.

.DESCRIPTION
    Connects to a Palo Alto firewall using an API key and downloads the full
    running configuration as a date-stamped XML file. Intended for use by a
    sysadmin to collect evidence for a PCI DSS assessment.

    The exported file is hashed with SHA-256 and recorded in a date-stamped
    MANIFEST for chain-of-custody and integrity verification, alongside a
    .sha256 checksum file for independent verification.

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

# ---------------------------------------------------------------------------
# MANIFEST + SHA-256 INTEGRITY HASH
# The manifest and checksum file are date-stamped to match the export, so a
# re-run never overwrites the integrity record of a previous collection.
# ---------------------------------------------------------------------------
$hash         = Get-FileHash -Path $outFile -Algorithm SHA256
$sizeKB       = [math]::Round((Get-Item $outFile).Length / 1KB, 1)
$fileName     = Split-Path $outFile -Leaf
$checksumPath = Join-Path $ConfigDir "$fileName.sha256"
$manifestPath = Join-Path $ConfigDir "pa-$datestamp-MANIFEST.txt"

# "<hash> *<file>" — the format understood by sha256sum -c
"{0} *{1}" -f $hash.Hash, $fileName | Out-File -FilePath $checksumPath -Encoding ASCII

@(
    "Palo Alto Configuration Export Manifest (PCI DSS)"
    "================================================"
    "Firewall       : $PA_HOST"
    "Exported       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Hashed (UTC)   : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    "Host           : $env:COMPUTERNAME"
    "User           : $env:USERNAME"
    "Hash algorithm : SHA-256"
    ""
    "Files and integrity hashes:"
    ""
    "  $fileName"
    "      Size   : $sizeKB KB"
    "      SHA-256: $($hash.Hash)"
    ""
    "$fileName.sha256 holds the same hash in a format verifiable with:"
    "  Windows : certutil -hashfile $fileName SHA256"
    "  Linux   : sha256sum -c $fileName.sha256"
) | Out-File -FilePath $manifestPath -Encoding UTF8

Write-Host "SHA-256 : $($hash.Hash)"
Write-Host "Manifest saved to: $manifestPath"
