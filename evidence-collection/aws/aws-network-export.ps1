<#
.SYNOPSIS
    Export AWS network security configuration for PCI DSS assessment.

.DESCRIPTION
    Connects to AWS using the AWS Tools for PowerShell and exports:
      - Security Group rules (inbound and outbound, all groups in the region)
      - Network ACL rules (per subnet association, sorted in rule priority order)
      - VPC definitions, subnet assignments, and route tables
      - AWS Network Firewall policies and stateless/stateful rule groups (if deployed)

    All output is saved to a timestamped folder as JSON files readable in
    VS Code or Notepad++ on Windows. No changes are made to AWS.

    Every exported file is hashed with SHA-256 and recorded in MANIFEST.txt for
    chain-of-custody and integrity verification, alongside a checksums.sha256
    file that can be verified independently.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.NOTES
    Requires AWS Tools for PowerShell (AWS.Tools.EC2 and AWS.Tools.NetworkFirewall).
    The script will offer to install these automatically if not found.
    See aws-network-export_powershell_readme.txt for full setup instructions.
#>

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================
$AccessKeyId     = "YOUR_ACCESS_KEY_ID"
$SecretAccessKey = "YOUR_SECRET_ACCESS_KEY"
$Region          = "us-east-1"
$OutputBase      = "C:\aws-export"

# If your organization uses AWS named profiles (AWS SSO or ~/.aws/credentials),
# set the profile name here and leave $AccessKeyId and $SecretAccessKey as "".
$ProfileName     = ""
# ==============================================================================

# ---------------------------------------------------------------------------
# AWS Module check — supports modular (AWS.Tools.*), NetCore, and Classic
# ---------------------------------------------------------------------------
$awsFlavor    = $null
$nfwAvailable = $false

if     (Get-Module -ListAvailable -Name "AWS.Tools.EC2")       { $awsFlavor = "modular" }
elseif (Get-Module -ListAvailable -Name "AWSPowerShell.NetCore") { $awsFlavor = "netcore" }
elseif (Get-Module -ListAvailable -Name "AWSPowerShell")         { $awsFlavor = "classic" }

if (-not $awsFlavor) {
    Write-Host ""
    Write-Host "  AWS Tools for PowerShell is not installed."
    Write-Host "  Required: AWS.Tools.EC2 and AWS.Tools.NetworkFirewall"
    Write-Host ""
    $answer = Read-Host "  Install from PSGallery now? (yes/no)"
    if ($answer -match "^[Yy]") {
        try {
            Write-Host "  Installing AWS.Tools.EC2 ..."
            Install-Module -Name AWS.Tools.EC2             -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "  Installing AWS.Tools.NetworkFirewall ..."
            Install-Module -Name AWS.Tools.NetworkFirewall -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "  Installing AWS.Tools.SecurityToken ..."
            Install-Module -Name AWS.Tools.SecurityToken   -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "  Modules installed successfully."
            $awsFlavor = "modular"
        } catch {
            Write-Error "  Install failed: $_"
            Write-Host "  Install manually: Install-Module -Name AWS.Tools.EC2 -Scope CurrentUser"
            exit 1
        }
    } else {
        Write-Host "  Cannot continue without AWS Tools for PowerShell. Exiting."
        exit 1
    }
}

switch ($awsFlavor) {
    "modular" {
        Import-Module AWS.Tools.EC2 -ErrorAction Stop
        if (Get-Module -ListAvailable -Name "AWS.Tools.NetworkFirewall") {
            Import-Module AWS.Tools.NetworkFirewall -ErrorAction SilentlyContinue
            $nfwAvailable = $true
        }
        if (Get-Module -ListAvailable -Name "AWS.Tools.SecurityToken") {
            Import-Module AWS.Tools.SecurityToken -ErrorAction SilentlyContinue
        }
    }
    "netcore" {
        Import-Module AWSPowerShell.NetCore -ErrorAction Stop
        $nfwAvailable = $true
    }
    "classic" {
        Import-Module AWSPowerShell -ErrorAction Stop
        $nfwAvailable = $true
    }
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
$Date      = Get-Date -Format "yyyyMMdd_HHmmss"
$ExportDir = Join-Path $OutputBase "aws-$Region-$Date"

New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

Write-Host "========================================"
Write-Host "  AWS Network Security Export"
Write-Host "  Region  : $Region"
Write-Host "  Output  : $ExportDir"
Write-Host "========================================"

# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[ Credentials ]"
Write-Host -NoNewline ("  " + "Setting AWS credentials...".PadRight(40) + "...")

try {
    if ($ProfileName) {
        Set-AWSCredential -ProfileName $ProfileName -ErrorAction Stop
    } elseif ($AccessKeyId -and $SecretAccessKey -and
              $AccessKeyId -ne "YOUR_ACCESS_KEY_ID") {
        Set-AWSCredential -AccessKey $AccessKeyId -SecretKey $SecretAccessKey -ErrorAction Stop
    }
    # else: fall through to the default credential chain
    # (environment variables, instance profile, ~/.aws/credentials default profile)

    Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
    Write-Host " OK"
} catch {
    Write-Host " FAILED ($_)"
    exit 1
}

# Retrieve account ID for the manifest (requires SecurityToken)
$AccountId = "unknown"
try {
    $callerIdentity = Get-STSCallerIdentity -ErrorAction Stop
    $AccountId      = $callerIdentity.Account
    Write-Host ("  " + "Account ID:".PadRight(40) + "  $AccountId")
} catch {
    # Module unavailable or insufficient permissions; non-fatal
}

# ---------------------------------------------------------------------------
# Helper: run a scriptblock, serialize result to JSON, save to file
# ---------------------------------------------------------------------------
function Export-AwsResource {
    param(
        [string]$Label,
        [string]$FileName,
        [scriptblock]$Fetch
    )

    $outPath = Join-Path $ExportDir $FileName
    Write-Host -NoNewline ("  " + $Label.PadRight(40) + "...")

    try {
        $data  = & $Fetch
        $items = @($data)   # coerce to array; handles $null and single objects

        # Serialize — handle PS 5.1 single-item array edge case where
        # ConvertTo-Json drops the outer [] for arrays of length 1
        $rawJson = $items | ConvertTo-Json -Depth 10

        $json = if (-not $rawJson) {
            "[]"
        } elseif ($items.Count -eq 1 -and -not $rawJson.TrimStart().StartsWith('[')) {
            "[$rawJson]"
        } else {
            $rawJson
        }

        [System.IO.File]::WriteAllText($outPath, $json, [System.Text.Encoding]::UTF8)

        $sizeKB = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
        Write-Host " OK ($($items.Count) items, ${sizeKB} KB)"

    } catch {
        Write-Host " FAILED ($_)"
        "[]" | Out-File -FilePath $outPath -Encoding UTF8
    }
}

# ==============================================================================
# 1. VPC INFRASTRUCTURE
#    VPCs, subnets, and route tables establish the network topology.
#    PCI assessors use this to understand segmentation and traffic paths.
# ==============================================================================
Write-Host ""
Write-Host "[ VPC infrastructure ]"

Export-AwsResource "VPCs" "vpcs.json" {
    Get-EC2Vpc
}

Export-AwsResource "Subnets" "subnets.json" {
    Get-EC2Subnet
}

Export-AwsResource "Route tables" "route-tables.json" {
    Get-EC2RouteTable
}

Export-AwsResource "Internet gateways" "internet-gateways.json" {
    Get-EC2InternetGateway
}

Export-AwsResource "NAT gateways" "nat-gateways.json" {
    Get-EC2NatGateway
}

Export-AwsResource "VPC peering connections" "vpc-peering.json" {
    Get-EC2VpcPeeringConnection
}

# ==============================================================================
# 2. NETWORK ACCESS CONTROLS
#    Security Groups and NACLs are the primary network traffic controls in AWS.
#    Both are required for PCI DSS network segmentation evidence.
# ==============================================================================
Write-Host ""
Write-Host "[ Network access controls ]"

Export-AwsResource "Security groups" "security-groups.json" {
    Get-EC2SecurityGroup
}

Export-AwsResource "Network ACLs (NACLs)" "network-acls.json" {
    $acls = Get-EC2NetworkAcl
    foreach ($acl in $acls) {
        # Sort entries by direction then rule number so the assessor sees
        # them in the order AWS evaluates them (lowest number wins)
        $acl.Entries = @($acl.Entries | Sort-Object Egress, RuleNumber)
    }
    $acls
}

# ==============================================================================
# 3. AWS NETWORK FIREWALL (if deployed)
#    Exports firewalls, policies, and all stateless/stateful rule groups.
#    Skipped gracefully if not deployed or module unavailable.
# ==============================================================================
Write-Host ""
Write-Host "[ AWS Network Firewall ]"

if (-not $nfwAvailable) {
    Write-Host "  AWS.Tools.NetworkFirewall module not available -- skipping"
    Write-Host "  Install with: Install-Module -Name AWS.Tools.NetworkFirewall -Scope CurrentUser"
} else {
    # Check whether any firewalls are deployed before running detailed exports
    $firewallList = @()
    try {
        $firewallList = @(Get-NFWFirewallList -ErrorAction Stop)
    } catch {
        Write-Host ("  " + "Firewall check...".PadRight(40) + "... FAILED ($_)")
    }

    if ($firewallList.Count -eq 0) {
        Write-Host "  No AWS Network Firewall resources found in region $Region"
        # Write a marker file so the assessor knows this was checked
        @{checked = $true; found = $false; region = $Region} |
            ConvertTo-Json | Out-File -FilePath (Join-Path $ExportDir "nfw-not-deployed.json") -Encoding UTF8
    } else {
        Write-Host "  $($firewallList.Count) firewall(s) found"

        Export-AwsResource "Firewalls (detail)" "nfw-firewalls.json" {
            $firewallList | ForEach-Object {
                Get-NFWFirewall -FirewallArn $_.FirewallArn
            }
        }

        Export-AwsResource "Firewall policies" "nfw-policies.json" {
            $policyList = @(Get-NFWFirewallPolicyList)
            $policyList | ForEach-Object {
                Get-NFWFirewallPolicy -FirewallPolicyArn $_.Arn
            }
        }

        # Exports both stateless and stateful rule groups with their full rule content
        Export-AwsResource "Rule groups (stateless + stateful)" "nfw-rule-groups.json" {
            $rgList = @(Get-NFWRuleGroupList)
            $rgList | ForEach-Object {
                Get-NFWRuleGroup -RuleGroupArn $_.Arn
            }
        }
    }
}

# ==============================================================================
# 4. MANIFEST + SHA-256 INTEGRITY HASHES
# Every exported file is hashed with SHA-256 and recorded in MANIFEST.txt for
# chain-of-custody, plus checksums.sha256 for independent verification.
# ==============================================================================
Write-Host ""
Write-Host -NoNewline "  Hashing evidence (SHA-256) + manifest...".PadRight(48)

$manifestPath = Join-Path $ExportDir "MANIFEST.txt"
$checksumPath = Join-Path $ExportDir "checksums.sha256"
$files        = Get-ChildItem $ExportDir -File |
                    Where-Object { $_.Name -ne "MANIFEST.txt" -and $_.Name -ne "checksums.sha256" } |
                    Sort-Object Name

$hashes = foreach ($f in $files) {
    $h = Get-FileHash -Path $f.FullName -Algorithm SHA256
    [PSCustomObject]@{ Name = $f.Name; SizeKB = [math]::Round($f.Length / 1KB, 1); SHA256 = $h.Hash }
}

# One "<hash> *<file>" line per file — the format understood by sha256sum -c
$hashes | ForEach-Object { "{0} *{1}" -f $_.SHA256, $_.Name } |
    Out-File -FilePath $checksumPath -Encoding ASCII

$manifestLines = @(
    "AWS Network Security Export Manifest"
    "==================================="
    "Account ID     : $AccountId"
    "Region         : $Region"
    "Exported       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Hashed (UTC)   : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    "Host           : $env:COMPUTERNAME"
    "User           : $env:USERNAME"
    "Hash algorithm : SHA-256"
    ""
    "Files and integrity hashes:"
    ""
)
foreach ($h in $hashes) {
    $manifestLines += ("  {0}" -f $h.Name)
    $manifestLines += ("      Size   : {0} KB" -f $h.SizeKB)
    $manifestLines += ("      SHA-256: {0}" -f $h.SHA256)
    $manifestLines += ""
}
$manifestLines += "checksums.sha256 lists all hashes in a format verifiable with:"
$manifestLines += "  Windows : certutil -hashfile <file> SHA256"
$manifestLines += "  Linux   : sha256sum -c checksums.sha256"
$manifestLines | Out-File -FilePath $manifestPath -Encoding UTF8

Write-Host " OK ($(@($hashes).Count) files)"

Write-Host "========================================"
Write-Host "  Export complete."
Write-Host "  Files saved to: $ExportDir"
Write-Host ""
Write-Host "  MANIFEST.txt records a SHA-256 hash of every file."
Write-Host "  checksums.sha256 can be verified with: sha256sum -c checksums.sha256"
Write-Host ""
Write-Host "  For assessor review:"
Write-Host "  - Open .json files in VS Code or Notepad++"
Write-Host "    (VS Code: Ctrl+Shift+P > Format Document for JSON pretty-print)"
Write-Host "  - security-groups.json  -- all inbound/outbound SG rules"
Write-Host "  - network-acls.json     -- NACL rules in evaluation priority order"
Write-Host "  - vpcs.json / subnets.json / route-tables.json  -- network topology"
Write-Host "  - nfw-*.json            -- Network Firewall rules (if deployed)"
Write-Host "========================================"
