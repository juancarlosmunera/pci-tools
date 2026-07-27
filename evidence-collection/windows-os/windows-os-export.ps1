<#
.SYNOPSIS
    Export Windows host configuration for PCI DSS assessment -- one host or many.

.DESCRIPTION
    Collects Windows operating system configuration evidence relevant to PCI DSS
    system hardening, access control, and logging control reviews. Can run
    against the local machine, or against a list of remote hosts (one hostname
    per line in a text file) over PowerShell Remoting (WinRM) from a single
    admin workstation -- no need to log on to each server.

    For every target it collects:
      - System information (OS version, build, domain membership, uptime)
      - Local user accounts with password and logon metadata
      - Local groups and their members (including Administrators)
      - Password policy and account lockout policy (net accounts + secedit)
      - User rights assignments and security policy (secedit export)
      - Audit policy settings (auditpol) and event log retention
      - Windows Firewall profiles and rules (inbound and outbound)
      - Installed software and applied patches / hotfixes
      - Windows services with start mode and run-as account
      - Security hardening registry keys (SMBv1, RDP, UAC, LSA, etc.)
      - Antivirus / Microsoft Defender status and BitLocker status
      - Listening network ports, SMB shares, scheduled tasks, startup items
      - Time synchronization (w32tm) and effective Group Policy (gpresult)

    Each host gets its own timestamped evidence folder under a single run
    folder. Every file is hashed with SHA-256 and recorded in a per-host
    MANIFEST for chain-of-custody and integrity verification.

    This script is READ-ONLY. It makes no changes to any target system.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.NOTES
    Local collection must be run in an elevated (Administrator) PowerShell
    session. Remote collection requires PowerShell Remoting enabled on the
    targets (Enable-PSRemoting) and credentials with local administrator rights
    on each target. No external modules are required.
    See windows-os-export_powershell_readme.txt for full instructions.
#>

# ==============================================================================
# CONFIG -- update these before running
# ==============================================================================

# Path to a text file with one hostname (or IP) per line. Lines that are blank
# or start with '#' are ignored. Leave "" to collect from the local machine only.
$HostListFile = ""

# Alternatively, list hosts inline here (used only if $HostListFile is blank).
# Leave empty to collect from the local machine.
$Hosts        = @()

# Where to create the run folder on THIS (collector) machine.
$OutputBase   = "C:\windows-os-export"

# Remote credentials. $true = use the account running this script (Kerberos).
# $false = prompt once for credentials to use against all remote hosts.
$UseCurrentCredential = $true
# ==============================================================================

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Resolve the target list
# ---------------------------------------------------------------------------
$Targets = @()
if ($HostListFile) {
    if (-not (Test-Path $HostListFile)) {
        Write-Error "Host list file not found: $HostListFile"
        exit 1
    }
    $Targets = Get-Content $HostListFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith("#") }
} elseif ($Hosts.Count -gt 0) {
    $Targets = $Hosts
} else {
    $Targets = @("localhost")
}
$Targets = $Targets | Select-Object -Unique

function Test-IsLocalTarget {
    param([string]$Name)
    return @("localhost", ".", "127.0.0.1", "::1", $env:COMPUTERNAME) -contains $Name
}

$hasRemote = @($Targets | Where-Object { -not (Test-IsLocalTarget $_) }).Count -gt 0

# ---------------------------------------------------------------------------
# Collector-side setup
# ---------------------------------------------------------------------------
$Date   = Get-Date -Format "yyyyMMdd_HHmmss"
$RunDir = Join-Path $OutputBase "windows-os-run-$Date"
New-Item -ItemType Directory -Path $RunDir -Force | Out-Null

$CollectorUser = "$env:USERDOMAIN\$env:USERNAME"
$CollectorHost = $env:COMPUTERNAME

Write-Host "========================================"
Write-Host "  Windows OS Configuration Export (PCI DSS)"
Write-Host "  Collector : $CollectorHost ($CollectorUser)"
Write-Host "  Targets   : $($Targets.Count)  [$($Targets -join ', ')]"
Write-Host "  Output    : $RunDir"
Write-Host "========================================"

# Elevation only matters for LOCAL collection; remote uses the supplied credential.
$IsAdminLocal = ([Security.Principal.WindowsPrincipal] `
                 [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ((@($Targets | Where-Object { Test-IsLocalTarget $_ }).Count -gt 0) -and -not $IsAdminLocal) {
    Write-Host ""
    Write-Host "  WARNING: Local collection requested but this session is not" -ForegroundColor Yellow
    Write-Host "  elevated. Security policy, audit policy, and some firewall/"
    Write-Host "  registry evidence for the local host will be incomplete."
    Write-Host "  Re-launch PowerShell with 'Run as administrator' for a full export."
    Write-Host ""
    $answer = Read-Host "  Continue anyway? (yes/no)"
    if ($answer -notmatch "^[Yy]") { Write-Host "  Aborted."; exit 1 }
}

# Credentials for remote hosts
$Credential = $null
if ($hasRemote -and -not $UseCurrentCredential) {
    Write-Host ""
    Write-Host "  Enter credentials with local administrator rights on the target hosts."
    $Credential = Get-Credential
}

# ==============================================================================
# COLLECTION SCRIPTBLOCK
# Runs on each target (locally via '&' or remotely via Invoke-Command). Writes
# all evidence files into a folder on the TARGET and returns metadata plus the
# folder path. Hashing and the MANIFEST are produced by the collector after the
# folder is retrieved, so integrity hashes are computed on the assembled bundle.
# ==============================================================================
$CollectScript = {
    param([string]$OutBase)

    $ErrorActionPreference = "Continue"
    if (-not $OutBase) { $OutBase = Join-Path $env:TEMP "pci-windows-os" }

    $HostName  = $env:COMPUTERNAME
    $StartUTC  = (Get-Date).ToUniversalTime()
    $ExportDir = Join-Path $OutBase ("windows-os-$HostName-" + (Get-Date -Format "yyyyMMdd_HHmmss"))
    New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

    $IsAdmin = ([Security.Principal.WindowsPrincipal] `
                [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # --- local helpers (write files into $ExportDir) ---
    function Export-Json {
        param([string]$Label, [string]$FileName, [int]$Depth = 6, [scriptblock]$Fetch)
        $outPath = Join-Path $ExportDir $FileName
        Write-Host -NoNewline ("    " + $Label.PadRight(44) + "...")
        try {
            $items   = @(& $Fetch)
            $rawJson = $items | ConvertTo-Json -Depth $Depth
            $json = if (-not $rawJson) { "[]" }
                    elseif ($items.Count -eq 1 -and -not $rawJson.TrimStart().StartsWith('[')) { "[$rawJson]" }
                    else { $rawJson }
            [System.IO.File]::WriteAllText($outPath, $json, [System.Text.Encoding]::UTF8)
            $sizeKB = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
            Write-Host " OK ($($items.Count) items, ${sizeKB} KB)"
        } catch {
            Write-Host " FAILED ($_)"
            "[]" | Out-File -FilePath $outPath -Encoding UTF8
        }
    }
    function Export-Table {
        param([string]$Label, [string]$FileName, [scriptblock]$Fetch)
        $outPath = Join-Path $ExportDir $FileName
        Write-Host -NoNewline ("    " + $Label.PadRight(44) + "...")
        try {
            $data = @(& $Fetch)
            if ($data.Count -eq 0) {
                "# No records returned." | Out-File -FilePath $outPath -Encoding UTF8
                Write-Host " OK (0 items)"; return
            }
            $data | Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8
            $sizeKB = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
            Write-Host " OK ($($data.Count) items, ${sizeKB} KB)"
        } catch {
            Write-Host " FAILED ($_)"
            "# Export failed: $_" | Out-File -FilePath $outPath -Encoding UTF8
        }
    }
    function Export-Text {
        param([string]$Label, [string]$FileName, [scriptblock]$Fetch)
        $outPath = Join-Path $ExportDir $FileName
        Write-Host -NoNewline ("    " + $Label.PadRight(44) + "...")
        try {
            $text = & $Fetch | Out-String
            [System.IO.File]::WriteAllText($outPath, $text, [System.Text.Encoding]::UTF8)
            $sizeKB = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
            Write-Host " OK (${sizeKB} KB)"
        } catch {
            Write-Host " FAILED ($_)"
            "# Export failed: $_" | Out-File -FilePath $outPath -Encoding UTF8
        }
    }
    function Get-RegValue {
        param([string]$Path, [string]$Name)
        try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
        catch { return $null }
    }

    # ===== 1. SYSTEM INFORMATION =====
    Write-Host "  [ System information ]"
    Export-Json "Host and OS details" "system-info.json" 6 {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            OSCaption      = $os.Caption
            OSVersion      = $os.Version
            OSBuildNumber  = $os.BuildNumber
            OSArchitecture = $os.OSArchitecture
            InstallDate    = $os.InstallDate
            LastBootUpTime = $os.LastBootUpTime
            Manufacturer   = $cs.Manufacturer
            Model          = $cs.Model
            Domain         = $cs.Domain
            PartOfDomain   = $cs.PartOfDomain
            Workgroup      = $cs.Workgroup
            PSVersion      = $PSVersionTable.PSVersion.ToString()
            RunAsElevated  = $IsAdmin
            CollectedBy    = "$env:USERDOMAIN\$env:USERNAME"
            CollectedUTC   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
        }
    }

    # ===== 2. LOCAL USER ACCOUNTS =====
    Write-Host "  [ Local accounts and groups ]"
    Export-Table "Local user accounts" "local-users.csv" {
        try {
            Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name; Enabled = $_.Enabled; Description = $_.Description
                    PasswordRequired = $_.PasswordRequired; PasswordLastSet = $_.PasswordLastSet
                    PasswordExpires = $_.PasswordExpires; PasswordChangeableDate = $_.PasswordChangeableDate
                    UserMayChangePassword = $_.UserMayChangePassword; LastLogon = $_.LastLogon
                    AccountExpires = $_.AccountExpires; PrincipalSource = $_.PrincipalSource; SID = $_.SID.Value
                }
            }
        } catch {
            Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name; Enabled = (-not $_.Disabled); Description = $_.Description
                    PasswordRequired = $_.PasswordRequired; PasswordLastSet = $null
                    PasswordExpires = $_.PasswordExpires; PasswordChangeableDate = $null
                    UserMayChangePassword = $_.PasswordChangeable; LastLogon = $null
                    AccountExpires = $null; PrincipalSource = "Win32_UserAccount"; SID = $_.SID
                }
            }
        }
    }

    # ===== 3. LOCAL GROUPS AND MEMBERSHIP =====
    Export-Json "Local groups and members" "local-groups.json" 5 {
        try {
            Get-LocalGroup -ErrorAction Stop | ForEach-Object {
                $g = $_; $members = @()
                try {
                    $members = Get-LocalGroupMember -Group $g.Name -ErrorAction Stop | ForEach-Object {
                        [PSCustomObject]@{ Name = $_.Name; ObjectClass = $_.ObjectClass; PrincipalSource = $_.PrincipalSource; SID = $_.SID.Value }
                    }
                } catch { $members = @([PSCustomObject]@{ Name = "(unable to enumerate: $_)" }) }
                [PSCustomObject]@{ GroupName = $g.Name; Description = $g.Description; SID = $g.SID.Value; MemberCount = @($members).Count; Members = $members }
            }
        } catch {
            Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True" | ForEach-Object {
                $g = $_
                $members = Get-CimAssociatedInstance -InputObject $g -ResultClassName Win32_UserAccount -ErrorAction SilentlyContinue |
                    ForEach-Object { [PSCustomObject]@{ Name = $_.Caption; SID = $_.SID } }
                [PSCustomObject]@{ GroupName = $g.Name; Description = $g.Description; SID = $g.SID; MemberCount = @($members).Count; Members = @($members) }
            }
        }
    }

    # ===== 4. PASSWORD / LOCKOUT POLICY =====
    Write-Host "  [ Security policy ]"
    Export-Text "Password / lockout policy (net accounts)" "password-lockout-policy.txt" {
        "===== net accounts (local) ====="; net accounts 2>&1
        ""; "===== net accounts /domain ====="; net accounts /domain 2>&1
    }

    # ===== 5. SECURITY POLICY (secedit) =====
    $secPath = Join-Path $ExportDir "security-policy.inf"
    Write-Host -NoNewline ("    " + "Security policy (secedit export)".PadRight(44) + "...")
    if ($IsAdmin) {
        try {
            $null = secedit /export /cfg "$secPath" /quiet 2>&1
            if (Test-Path $secPath) { Write-Host " OK ($([math]::Round((Get-Item $secPath).Length/1KB,1)) KB)" }
            else { Write-Host " FAILED (no file produced)" }
        } catch { Write-Host " FAILED ($_)" }
    } else {
        "# secedit export requires administrator rights -- run elevated to collect." | Out-File -FilePath $secPath -Encoding UTF8
        Write-Host " SKIPPED (not elevated)"
    }

    # ===== 6. AUDIT POLICY + EVENT LOG CONFIG =====
    Write-Host "  [ Logging and audit ]"
    if ($IsAdmin) {
        Export-Text "Audit policy (auditpol, readable)" "audit-policy.txt" { auditpol /get /category:* 2>&1 }
        Export-Text "Audit policy (auditpol, CSV)"      "audit-policy.csv"  { auditpol /get /category:* /r 2>&1 }
    } else {
        "# auditpol requires administrator rights -- run elevated to collect." | Out-File -FilePath (Join-Path $ExportDir "audit-policy.txt") -Encoding UTF8
        Write-Host "    Audit policy (auditpol)                       SKIPPED (not elevated)"
    }
    Export-Table "Event log configuration" "event-log-config.csv" {
        Get-CimInstance -ClassName Win32_NTEventLogFile -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                LogFileName = $_.LogfileName; FileName = $_.Name
                MaxFileSizeKB = [math]::Round($_.MaxFileSize/1KB,0); CurrentSizeKB = [math]::Round($_.FileSize/1KB,0)
                NumberOfRecords = $_.NumberOfRecords; OverwritePolicy = $_.OverwritePolicy
            }
        }
    }

    # ===== 7. WINDOWS FIREWALL =====
    Write-Host "  [ Windows Firewall ]"
    Export-Json "Firewall profiles (on/off + defaults)" "firewall-profiles.json" 6 {
        try {
            Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Profile = $_.Name; Enabled = $_.Enabled
                    DefaultInboundAction = $_.DefaultInboundAction; DefaultOutboundAction = $_.DefaultOutboundAction
                    AllowInboundRules = $_.AllowInboundRules; LogFileName = $_.LogFileName
                    LogAllowed = $_.LogAllowed; LogBlocked = $_.LogBlocked; LogMaxSizeKilobytes = $_.LogMaxSizeKilobytes
                }
            }
        } catch { [PSCustomObject]@{ Note = "Get-NetFirewallProfile unavailable: $_" } }
    }
    Export-Table "Firewall rules (summary)" "firewall-rules.csv" {
        try {
            Get-NetFirewallRule -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    DisplayName = $_.DisplayName; Name = $_.Name; DisplayGroup = $_.DisplayGroup
                    Enabled = $_.Enabled; Direction = $_.Direction; Action = $_.Action
                    Profile = $_.Profile; EdgeTraversal = $_.EdgeTraversalPolicy
                }
            }
        } catch { @() }
    }
    Export-Text "Firewall rules (full detail, netsh)" "firewall-rules-detailed.txt" { netsh advfirewall firewall show rule name=all verbose 2>&1 }
    Export-Text "Firewall profile config (netsh)"     "firewall-config.txt"          { netsh advfirewall show allprofiles 2>&1 }

    # ===== 8. INSTALLED SOFTWARE AND PATCHES =====
    Write-Host "  [ Software and patches ]"
    Export-Table "Installed software" "installed-software.csv" {
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
            Select-Object @{N="DisplayName";E={$_.DisplayName}}, @{N="DisplayVersion";E={$_.DisplayVersion}},
                          @{N="Publisher";E={$_.Publisher}}, @{N="InstallDate";E={$_.InstallDate}} |
            Sort-Object DisplayName -Unique
    }
    Export-Table "Installed patches / hotfixes" "installed-hotfixes.csv" {
        Get-HotFix -ErrorAction SilentlyContinue |
            Select-Object HotFixID, Description, InstalledBy,
                          @{N="InstalledOn";E={ if ($_.InstalledOn) { $_.InstalledOn.ToString("yyyy-MM-dd") } }} |
            Sort-Object InstalledOn -Descending
    }
    Export-Json "Windows Update configuration" "windows-update-config.json" 4 {
        $au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $wu = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        [PSCustomObject]@{
            AUOptions = Get-RegValue $au "AUOptions"; NoAutoUpdate = Get-RegValue $au "NoAutoUpdate"
            ScheduledInstallDay = Get-RegValue $au "ScheduledInstallDay"
            WUServer = Get-RegValue $wu "WUServer"; TargetGroup = Get-RegValue $wu "TargetGroup"
        }
    }

    # ===== 9. SERVICES / TASKS / STARTUP =====
    Write-Host "  [ Services and tasks ]"
    Export-Table "Services (state + run-as account)" "services.csv" {
        Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName, Description | Sort-Object Name
    }
    Export-Table "Scheduled tasks" "scheduled-tasks.csv" {
        try {
            Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    TaskPath = $_.TaskPath; TaskName = $_.TaskName; State = $_.State
                    Author = $_.Author; RunAsUser = $_.Principal.UserId; RunLevel = $_.Principal.RunLevel
                }
            }
        } catch { @() }
    }
    Export-Table "Startup programs" "startup-programs.csv" {
        Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue | Select-Object Name, Command, Location, User
    }

    # ===== 10. HARDENING REGISTRY KEYS =====
    Write-Host "  [ Hardening ]"
    Export-Json "Security hardening registry keys" "hardening-registry.json" 4 {
        $checks = @(
            @{ Setting="SMBv1 server enabled"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="SMB1"; Recommended="0 or absent (SMBv1 disabled)"; PCI="Req 2.2.4" }
            @{ Setting="SMB signing required (server)"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name="RequireSecuritySignature"; Recommended="1 (required)"; PCI="Req 2.2.4" }
            @{ Setting="SMB signing required (client)"; Path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name="RequireSecuritySignature"; Recommended="1 (required)"; PCI="Req 2.2.4" }
            @{ Setting="RDP connections denied"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name="fDenyTSConnections"; Recommended="1 if RDP not required"; PCI="Req 2.2.4" }
            @{ Setting="RDP Network Level Authentication"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="UserAuthentication"; Recommended="1 (NLA required)"; PCI="Req 2.2.4 / 8.5" }
            @{ Setting="RDP minimum encryption level"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"; Name="MinEncryptionLevel"; Recommended="3 (High) or 4 (FIPS)"; PCI="Req 4.2 / 2.2.7" }
            @{ Setting="UAC enabled (EnableLUA)"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Recommended="1 (enabled)"; PCI="Req 7.2" }
            @{ Setting="UAC admin approval prompt"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Recommended="2 (prompt on secure desktop)"; PCI="Req 7.2" }
            @{ Setting="LSASS run as protected process"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Recommended="1 (enabled)"; PCI="Req 2.2.4 / 8.5" }
            @{ Setting="Restrict anonymous SAM enumeration"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymousSAM"; Recommended="1 (restricted)"; PCI="Req 7.2" }
            @{ Setting="Restrict anonymous access"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RestrictAnonymous"; Recommended="1 (restricted)"; PCI="Req 7.2" }
            @{ Setting="Limit local account blank password use"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Recommended="1 (enabled)"; PCI="Req 8.3.1" }
            @{ Setting="Do not store LM hash"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLMHash"; Recommended="1 (enabled)"; PCI="Req 8.3.2" }
            @{ Setting="LAN Manager authentication level"; Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Recommended="5 (NTLMv2 only)"; PCI="Req 8.3.2" }
            @{ Setting="Installer AlwaysInstallElevated"; Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"; Name="AlwaysInstallElevated"; Recommended="0 or absent"; PCI="Req 7.2" }
            @{ Setting="Autorun disabled (all drives)"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Recommended="255 (0xFF, all drives)"; PCI="Req 2.2.4" }
            @{ Setting="Inactivity lock timeout (secs)"; Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="InactivityTimeoutSecs"; Recommended="<= 900 (15 min)"; PCI="Req 8.2.8" }
        )
        foreach ($c in $checks) {
            $val = Get-RegValue $c.Path $c.Name
            [PSCustomObject]@{
                Setting = $c.Setting; RegistryPath = $c.Path; ValueName = $c.Name
                CurrentValue = $val; Present = ($null -ne $val); Recommended = $c.Recommended; PCIReference = $c.PCI
            }
        }
    }

    # ===== 11. ENDPOINT PROTECTION =====
    Write-Host "  [ Endpoint protection ]"
    Export-Json "Microsoft Defender status" "defender-status.json" 4 {
        try {
            $s = Get-MpComputerStatus -ErrorAction Stop
            [PSCustomObject]@{
                AMServiceEnabled = $s.AMServiceEnabled; AntivirusEnabled = $s.AntivirusEnabled
                RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
                AntivirusSignatureVersion = $s.AntivirusSignatureVersion; AntivirusSignatureAge = $s.AntivirusSignatureAge
                AntivirusSignatureLastUpdated = $s.AntivirusSignatureLastUpdated
                BehaviorMonitorEnabled = $s.BehaviorMonitorEnabled; IoavProtectionEnabled = $s.IoavProtectionEnabled
                TamperProtectionSource = $s.TamperProtectionSource; IsTamperProtected = $s.IsTamperProtected
            }
        } catch { [PSCustomObject]@{ Note = "Get-MpComputerStatus unavailable (non-Defender host or module missing): $_" } }
    }
    Export-Json "Registered AV products (SecurityCenter2)" "antivirus-products.json" 4 {
        try {
            Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop |
                Select-Object displayName, pathToSignedProductExe, productState, timestamp
        } catch { [PSCustomObject]@{ Note = "SecurityCenter2 not available (typical on Windows Server): $_" } }
    }
    Export-Table "BitLocker volume status" "bitlocker-status.csv" {
        try {
            Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint, VolumeType, VolumeStatus, ProtectionStatus, EncryptionPercentage, EncryptionMethod
        } catch { @([PSCustomObject]@{ MountPoint = "(Get-BitLockerVolume unavailable: $_)" }) }
    }

    # ===== 12. NETWORK EXPOSURE =====
    Write-Host "  [ Network exposure ]"
    Export-Table "Listening TCP ports" "listening-ports.csv" {
        try {
            Get-NetTCPListener -ErrorAction Stop | ForEach-Object {
                $procName = try { (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch { "" }
                [PSCustomObject]@{ LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort; State = $_.State; OwningPID = $_.OwningProcess; Process = $procName }
            } | Sort-Object LocalPort
        } catch { @() }
    }
    Export-Text "Active connections (netstat)" "netstat.txt" { netstat -ano 2>&1 }
    Export-Table "SMB shares" "smb-shares.csv" {
        try { Get-SmbShare -ErrorAction Stop | Select-Object Name, Path, Description, ShareType, CurrentUsers }
        catch { @([PSCustomObject]@{ Name = "(Get-SmbShare unavailable -- see netstat/net share)" }) }
    }

    # ===== 13. TIME SYNC =====
    Write-Host "  [ Time synchronization ]"
    Export-Text "Time sync status and config (w32tm)" "time-sync.txt" {
        "===== w32tm /query /status ====="; w32tm /query /status 2>&1
        ""; "===== w32tm /query /configuration ====="; w32tm /query /configuration 2>&1
        ""; "===== w32tm /query /peers ====="; w32tm /query /peers 2>&1
    }

    # ===== 14. GROUP POLICY RESULT =====
    Write-Host "  [ Group Policy ]"
    $gpPath = Join-Path $ExportDir "gpresult.html"
    Write-Host -NoNewline ("    " + "Effective policy report (gpresult)".PadRight(44) + "...")
    try {
        $null = gpresult /h "$gpPath" /f 2>&1
        if (Test-Path $gpPath) { Write-Host " OK ($([math]::Round((Get-Item $gpPath).Length/1KB,1)) KB)" }
        else { Write-Host " SKIPPED (standalone host or insufficient rights)" }
    } catch { Write-Host " SKIPPED ($_)" }

    # Return metadata + the folder path so the collector can retrieve and hash it.
    [PSCustomObject]@{
        ComputerName    = $HostName
        FolderPath      = $ExportDir
        Elevated        = $IsAdmin
        CollectedByTarget = "$env:USERDOMAIN\$env:USERNAME"
        CollectedUTC    = $StartUTC.ToString("yyyy-MM-dd HH:mm:ss")
    }
}

# ==============================================================================
# Collector-side: MANIFEST + SHA-256 hashes for one retrieved evidence folder
# ==============================================================================
function Write-ManifestAndHashes {
    param([string]$Folder, [psobject]$Meta)

    $files = Get-ChildItem $Folder -File |
        Where-Object { $_.Name -ne "MANIFEST.txt" -and $_.Name -ne "checksums.sha256" } |
        Sort-Object Name

    $hashes = foreach ($f in $files) {
        $h = Get-FileHash -Path $f.FullName -Algorithm SHA256
        [PSCustomObject]@{ Name = $f.Name; SizeKB = [math]::Round($f.Length/1KB,1); SHA256 = $h.Hash }
    }

    $checksumPath = Join-Path $Folder "checksums.sha256"
    (foreach ($h in $hashes) { "{0} *{1}" -f $h.SHA256, $h.Name }) | Out-File -FilePath $checksumPath -Encoding ASCII

    $manifestPath = Join-Path $Folder "MANIFEST.txt"
    $lines = @(
        "Windows OS Configuration Export Manifest (PCI DSS)"
        "=================================================="
        "Target host       : $($Meta.ComputerName)"
        "Collected (UTC)   : $($Meta.CollectedUTC) UTC"
        "Collected by      : $($Meta.CollectedByTarget)  (account used on the target)"
        "Run elevated      : $($Meta.Elevated)"
        "Retrieved/hashed by: $CollectorUser on $CollectorHost"
        "Hashed (UTC)      : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
        "Hash algorithm    : SHA-256"
        ""
        "Files and integrity hashes:"
        ""
    )
    foreach ($h in $hashes) {
        $lines += ("  {0}" -f $h.Name)
        $lines += ("      Size   : {0} KB" -f $h.SizeKB)
        $lines += ("      SHA-256: {0}" -f $h.SHA256)
        $lines += ""
    }
    $lines += "checksums.sha256 lists all hashes in a format verifiable with:"
    $lines += "  Windows : certutil -hashfile <file> SHA256"
    $lines += "  Linux   : sha256sum -c checksums.sha256"
    $lines | Out-File -FilePath $manifestPath -Encoding UTF8

    return $hashes.Count
}

# ==============================================================================
# MAIN LOOP -- collect from each target
# ==============================================================================
$summary = @()

foreach ($target in $Targets) {
    $isLocal = Test-IsLocalTarget $target
    Write-Host ""
    Write-Host "----------------------------------------"
    Write-Host "  Target: $target  ($(if ($isLocal) { 'local' } else { 'remote' }))"
    Write-Host "----------------------------------------"

    $status = "FAILED"; $localFolder = $null; $fileCount = 0; $session = $null

    try {
        if ($isLocal) {
            # Collect straight into the run folder -- no copy needed.
            $meta = & $CollectScript $RunDir
            $localFolder = $meta.FolderPath
        } else {
            # Open a remoting session, collect into the target's temp, copy back, clean up.
            $sessParams = @{ ComputerName = $target; ErrorAction = "Stop" }
            if ($Credential) { $sessParams.Credential = $Credential }

            Write-Host -NoNewline "  Opening remoting session...".PadRight(48)
            $session = New-PSSession @sessParams
            Write-Host " OK"

            $meta = Invoke-Command -Session $session -ScriptBlock $CollectScript -ArgumentList "" -ErrorAction Stop

            Write-Host -NoNewline "  Retrieving evidence (copy from host)...".PadRight(48)
            Copy-Item -FromSession $session -Path $meta.FolderPath -Destination $RunDir -Recurse -Force -ErrorAction Stop
            Write-Host " OK"
            $localFolder = Join-Path $RunDir (Split-Path $meta.FolderPath -Leaf)

            # Remove the temp evidence folder from the target
            Invoke-Command -Session $session -ScriptBlock { param($p) Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue } -ArgumentList $meta.FolderPath
            Remove-PSSession $session
        }

        Write-Host -NoNewline "  Hashing evidence (SHA-256) + manifest...".PadRight(48)
        $fileCount = Write-ManifestAndHashes -Folder $localFolder -Meta $meta
        Write-Host " OK ($fileCount files)"
        $status = "OK"
    } catch {
        Write-Host " FAILED ($_)"
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
    }

    $summary += [PSCustomObject]@{
        Target = $target
        Status = $status
        Folder = if ($localFolder) { Split-Path $localFolder -Leaf } else { "" }
        Files  = $fileCount
    }
}

# ==============================================================================
# RUN SUMMARY
# ==============================================================================
$runSummaryPath = Join-Path $RunDir "RUN-SUMMARY.txt"
$sumLines = @(
    "Windows OS Export -- Run Summary"
    "==============================="
    "Collector : $CollectorHost ($CollectorUser)"
    "Started   : $Date"
    "Targets   : $($Targets.Count)"
    ""
)
foreach ($s in $summary) {
    $sumLines += ("  {0,-30} {1,-8} {2,4} files   {3}" -f $s.Target, $s.Status, $s.Files, $s.Folder)
}
$sumLines | Out-File -FilePath $runSummaryPath -Encoding UTF8

$okCount = @($summary | Where-Object { $_.Status -eq "OK" }).Count
Write-Host ""
Write-Host "========================================"
Write-Host "  Export complete."
Write-Host "  Hosts collected: $okCount / $($Targets.Count)"
Write-Host "  Run folder     : $RunDir"
Write-Host ""
Write-Host "  Each host folder contains a MANIFEST.txt with SHA-256 integrity"
Write-Host "  hashes. RUN-SUMMARY.txt lists per-host status."
Write-Host ""
Write-Host "  Key files per host for assessor review:"
Write-Host "  - local-users.csv / local-groups.json  -- accounts + privileged groups"
Write-Host "  - security-policy.inf / audit-policy.txt -- password/lockout + audit policy"
Write-Host "  - firewall-profiles.json               -- firewall enabled per profile"
Write-Host "  - hardening-registry.json              -- current vs recommended hardening"
Write-Host "  - installed-software.csv / installed-hotfixes.csv -- patch baseline"
Write-Host "========================================"
