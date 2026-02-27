<#
.SYNOPSIS
    Export a Cisco firewall, router, or switch configuration for PCI DSS assessment.

.DESCRIPTION
    Connects to a Cisco device via SSH using the Posh-SSH module and exports the
    running configuration and key show command outputs for review by a PCI DSS
    assessor. Supports Cisco IOS, IOS-XE, and ASA device types.

    All output is saved to a timestamped folder. Files are plain text and open
    directly in VS Code or Notepad++ on Windows.

    This script is read-only. It makes no changes to the device.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.NOTES
    Requires the Posh-SSH module. The script will offer to install it automatically
    if not found. See cisco-config-export_powershell_readme.txt for full instructions.
#>

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================
$DeviceIP       = "10.0.1.3"
$Username       = "admin"
$Password       = "YOUR_PASSWORD"
$EnablePassword = "YOUR_ENABLE_PASSWORD"   # Leave as "" if enable is not required
$DeviceType     = "ios"                    # Options: ios | iosxe | asa
$OutputBase     = "C:\cisco-export"
# ==============================================================================

# ---------------------------------------------------------------------------
# Posh-SSH — check and optionally install
# ---------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Host ""
    Write-Host "  Posh-SSH module is not installed."
    Write-Host "  It is required to connect to Cisco devices via SSH."
    Write-Host ""
    $answer = Read-Host "  Install Posh-SSH now from PSGallery? (yes/no)"
    if ($answer -match "^[Yy]") {
        try {
            Install-Module -Name Posh-SSH -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "  Posh-SSH installed successfully."
        } catch {
            Write-Error "  Failed to install Posh-SSH: $_"
            exit 1
        }
    } else {
        Write-Host "  Cannot continue without Posh-SSH. Exiting."
        exit 1
    }
}
Import-Module Posh-SSH -ErrorAction Stop

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
$Date      = Get-Date -Format "yyyyMMdd_HHmmss"
$ExportDir = Join-Path $OutputBase "cisco-$DeviceIP-$Date"

New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

Write-Host "========================================"
Write-Host "  Cisco Configuration Export"
Write-Host "  Target      : $DeviceIP"
Write-Host "  Device type : $DeviceType"
Write-Host "  Output      : $ExportDir"
Write-Host "========================================"

# ---------------------------------------------------------------------------
# Helper: run one show command and save output to a file
# ---------------------------------------------------------------------------
function Invoke-ShowCommand {
    param(
        [string]$Command,
        [string]$FileName,
        [string]$Label,
        [int]$TimeoutSeconds = 60
    )

    $outPath = Join-Path $ExportDir $FileName
    Write-Host -NoNewline ("  " + $Label.PadRight(38) + "...")

    $script:stream.WriteLine($Command)
    $raw = $script:stream.Expect([regex]"[>#]", [timespan]::FromSeconds($TimeoutSeconds))

    if (-not $raw) {
        Write-Host " FAILED (no response — timeout after ${TimeoutSeconds}s)"
        return
    }

    # Remove the echoed command (first line) and the trailing prompt (last line)
    $lines = ($raw -split "`n") | ForEach-Object { $_.TrimEnd("`r") }
    if ($lines.Count -ge 2) {
        $lines = $lines[1..($lines.Count - 2)]
    }
    $content = $lines -join "`n"

    [System.IO.File]::WriteAllText($outPath, $content, [System.Text.Encoding]::UTF8)

    $sizeKB = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
    Write-Host " OK (${sizeKB} KB)"
}

# ==============================================================================
# 1. SSH CONNECTION
# ==============================================================================
Write-Host ""
Write-Host "[ Connecting ]"

$securePass = ConvertTo-SecureString $Password -AsPlainText -Force
$cred       = New-Object System.Management.Automation.PSCredential($Username, $securePass)

Write-Host -NoNewline ("  " + "SSH session...".PadRight(38) + "...")
try {
    $session = New-SSHSession -ComputerName $DeviceIP -Credential $cred `
                   -AcceptKey -ErrorAction Stop
    Write-Host " OK"
} catch {
    Write-Host " FAILED ($_)"
    exit 1
}

$script:stream = New-SSHShellStream -SessionId $session.SessionId

# ==============================================================================
# 2. ENTER ENABLE MODE
# ==============================================================================
Write-Host -NoNewline ("  " + "Enable mode...".PadRight(38) + "...")

try {
    # Read initial banner and prompt (> = user exec, # = already privileged)
    $initial = $script:stream.Expect([regex]"[>#]", [timespan]::FromSeconds(15))

    if ($initial -match "#") {
        # Already in privileged mode (SSH privilege-level 15 or no enable required)
        Write-Host " OK (already privileged)"
    } else {
        $script:stream.WriteLine("enable")
        $prompt = $script:stream.Expect([regex]"(?i)password:|[>#]", [timespan]::FromSeconds(10))

        if ($prompt -match "(?i)password:") {
            $script:stream.WriteLine($EnablePassword)
            $result = $script:stream.Expect([regex]"[>#]", [timespan]::FromSeconds(10))
            if ($result -match "#") {
                Write-Host " OK"
            } else {
                Write-Host " FAILED (enable password rejected or unexpected prompt)"
                Remove-SSHSession -SessionId $session.SessionId | Out-Null
                exit 1
            }
        } elseif ($prompt -match "#") {
            Write-Host " OK"
        } else {
            Write-Host " FAILED (unexpected response)"
            Remove-SSHSession -SessionId $session.SessionId | Out-Null
            exit 1
        }
    }
} catch {
    Write-Host " FAILED ($_)"
    Remove-SSHSession -SessionId $session.SessionId | Out-Null
    exit 1
}

# ==============================================================================
# 3. DISABLE PAGINATION
# ==============================================================================
Write-Host -NoNewline ("  " + "Disable pagination...".PadRight(38) + "...")

$termCmd = if ($DeviceType -eq "asa") { "terminal pager 0" } else { "terminal length 0" }
$script:stream.WriteLine($termCmd)
$result = $script:stream.Expect([regex]"#", [timespan]::FromSeconds(10))
if ($result) { Write-Host " OK" } else { Write-Host " FAILED (timeout)" }

# ==============================================================================
# 4. COMMON EXPORTS — all device types
# ==============================================================================
Write-Host ""
Write-Host "[ Running configuration ]"

Invoke-ShowCommand "show version"         "version-info.txt"         "Device version and model"         30
Invoke-ShowCommand "show running-config"  "running-config.txt"       "Full running configuration"       120
Invoke-ShowCommand "show users"           "logged-in-users.txt"      "Currently logged-in users"        15

# ==============================================================================
# 5. DEVICE-TYPE-SPECIFIC EXPORTS
# ==============================================================================
Write-Host ""
Write-Host "[ Network security ]"

if ($DeviceType -eq "asa") {
    # ----- Cisco ASA -----
    Invoke-ShowCommand "show access-list"    "access-lists.txt"         "Access control lists (ACLs)"      60
    Invoke-ShowCommand "show route"          "routes.txt"               "Routing table"                    30
    Invoke-ShowCommand "show interface"      "interfaces.txt"           "Interfaces (full detail)"         30
    Invoke-ShowCommand "show nameif"         "interfaces-nameif.txt"    "Interface names / security levels" 15
    Invoke-ShowCommand "show object"         "address-objects.txt"      "Network and service objects"      30
    Invoke-ShowCommand "show object-group"   "object-groups.txt"        "Object groups"                    30
    Invoke-ShowCommand "show nat detail"     "nat-rules.txt"            "NAT rules"                        30
    Invoke-ShowCommand "show logging"        "logging-config.txt"       "Logging settings"                 15
    Invoke-ShowCommand "show ntp"            "ntp.txt"                  "NTP configuration"                15

} else {
    # ----- Cisco IOS / IOS-XE (routers and switches) -----
    Invoke-ShowCommand "show ip access-lists"     "access-lists.txt"       "IP access control lists (ACLs)"   60
    Invoke-ShowCommand "show ip route"            "routes.txt"             "IP routing table"                 30
    Invoke-ShowCommand "show interfaces"          "interfaces.txt"         "Interfaces (full detail)"         30
    Invoke-ShowCommand "show ip interface brief"  "interfaces-brief.txt"   "Interfaces (summary)"             15
    Invoke-ShowCommand "show vlan"                "vlans.txt"              "VLAN database"                    15
    Invoke-ShowCommand "show spanning-tree"       "spanning-tree.txt"      "Spanning tree configuration"      30
    Invoke-ShowCommand "show logging"             "logging-config.txt"     "Logging settings"                 15
    Invoke-ShowCommand "show ntp status"          "ntp-status.txt"         "NTP sync status"                  15
    Invoke-ShowCommand "show ntp associations"    "ntp-associations.txt"   "NTP associations"                 15
}

# ---------------------------------------------------------------------------
# Close SSH session
# ---------------------------------------------------------------------------
Remove-SSHSession -SessionId $session.SessionId | Out-Null

# ==============================================================================
# 6. MANIFEST
# ==============================================================================
Write-Host ""

$manifestPath = Join-Path $ExportDir "MANIFEST.txt"
$files        = Get-ChildItem $ExportDir | Where-Object { $_.Name -ne "MANIFEST.txt" } | Sort-Object Name

$manifestLines = @(
    "Cisco Configuration Export Manifest"
    "Target      : $DeviceIP"
    "Device type : $DeviceType"
    "Exported    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Host        : $env:COMPUTERNAME"
    "User        : $env:USERNAME"
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
Write-Host "  - Open .txt files in VS Code or Notepad++"
Write-Host "  - running-config.txt is the complete config -- use Ctrl+F"
Write-Host "    to search by section (e.g., 'ip access-list', 'interface')"
Write-Host "  - access-lists.txt shows all ACL rules in detail"
Write-Host "========================================"
