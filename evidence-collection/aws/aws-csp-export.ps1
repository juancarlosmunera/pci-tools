<#
.SYNOPSIS
    Export AWS cloud service provider controls for PCI DSS assessment.

.DESCRIPTION
    Connects to AWS using the AWS Tools for PowerShell and exports identity,
    access, and logging configuration relevant to PCI DSS controls, including:
      - IAM users, groups, roles, and policy attachments
      - IAM password policy and account-level MFA device inventory
      - IAM credential report: password age, MFA status, access key age and
        last-used dates for every user in the account
      - CloudTrail configuration and logging status (all trails, all regions)
      - S3 bucket inventory with public access block settings, bucket policies,
        policy public status, logging configuration, and versioning per bucket
      - AWS Config recorder status, rules, and per-rule compliance results
      - GuardDuty detector settings and active findings (if enabled)
      - Security Hub enabled standards and active failed findings (if enabled)

    All output saved to a timestamped folder as JSON and CSV files readable in
    VS Code, Notepad++, or Excel on Windows. No changes are made to AWS.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.NOTES
    Requires AWS Tools for PowerShell. The script will offer to install
    automatically if not found.
    See aws-csp-export_powershell_readme.txt for full setup instructions.
#>

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================
$AccessKeyId     = "YOUR_ACCESS_KEY_ID"
$SecretAccessKey = "YOUR_SECRET_ACCESS_KEY"
$Region          = "us-east-1"      # Region for regional services (Config,
                                    # GuardDuty, Security Hub). IAM, S3, and
                                    # CloudTrail listings are account-global.
$OutputBase      = "C:\aws-export"

# If your organization uses AWS named profiles (AWS SSO or ~/.aws/credentials),
# set the profile name here and leave $AccessKeyId and $SecretAccessKey as "".
$ProfileName     = ""
# ==============================================================================

# ---------------------------------------------------------------------------
# AWS Module check — supports modular (AWS.Tools.*), NetCore, and Classic
# ---------------------------------------------------------------------------
$awsFlavor   = $null
$gdAvailable = $false
$shAvailable = $false

if     (Get-Module -ListAvailable -Name "AWS.Tools.IdentityManagement") { $awsFlavor = "modular" }
elseif (Get-Module -ListAvailable -Name "AWSPowerShell.NetCore")         { $awsFlavor = "netcore" }
elseif (Get-Module -ListAvailable -Name "AWSPowerShell")                 { $awsFlavor = "classic" }

if (-not $awsFlavor) {
    Write-Host ""
    Write-Host "  AWS Tools for PowerShell is not installed."
    Write-Host "  Required modules:"
    Write-Host "    AWS.Tools.IdentityManagement  AWS.Tools.CloudTrail"
    Write-Host "    AWS.Tools.S3                  AWS.Tools.ConfigService"
    Write-Host "    AWS.Tools.GuardDuty            AWS.Tools.SecurityHub"
    Write-Host "    AWS.Tools.SecurityToken"
    Write-Host ""
    $answer = Read-Host "  Install from PSGallery now? (yes/no)"
    if ($answer -match "^[Yy]") {
        $modulesToInstall = @(
            "AWS.Tools.IdentityManagement",
            "AWS.Tools.CloudTrail",
            "AWS.Tools.S3",
            "AWS.Tools.ConfigService",
            "AWS.Tools.GuardDuty",
            "AWS.Tools.SecurityHub",
            "AWS.Tools.SecurityToken"
        )
        foreach ($mod in $modulesToInstall) {
            try {
                Write-Host "  Installing $mod ..."
                Install-Module -Name $mod -Scope CurrentUser -Force -ErrorAction Stop
            } catch {
                Write-Error "  Failed to install ${mod}: $_"
                exit 1
            }
        }
        Write-Host "  All modules installed successfully."
        $awsFlavor = "modular"
    } else {
        Write-Host "  Cannot continue without AWS Tools for PowerShell. Exiting."
        exit 1
    }
}

switch ($awsFlavor) {
    "modular" {
        Import-Module AWS.Tools.IdentityManagement -ErrorAction Stop
        Import-Module AWS.Tools.CloudTrail         -ErrorAction Stop
        Import-Module AWS.Tools.S3                 -ErrorAction Stop
        Import-Module AWS.Tools.ConfigService      -ErrorAction Stop
        if (Get-Module -ListAvailable -Name "AWS.Tools.SecurityToken") {
            Import-Module AWS.Tools.SecurityToken  -ErrorAction SilentlyContinue
        }
        if (Get-Module -ListAvailable -Name "AWS.Tools.GuardDuty") {
            Import-Module AWS.Tools.GuardDuty      -ErrorAction SilentlyContinue
            $gdAvailable = $true
        }
        if (Get-Module -ListAvailable -Name "AWS.Tools.SecurityHub") {
            Import-Module AWS.Tools.SecurityHub    -ErrorAction SilentlyContinue
            $shAvailable = $true
        }
    }
    "netcore" {
        Import-Module AWSPowerShell.NetCore -ErrorAction Stop
        $gdAvailable = $true; $shAvailable = $true
    }
    "classic" {
        Import-Module AWSPowerShell -ErrorAction Stop
        $gdAvailable = $true; $shAvailable = $true
    }
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
$Date      = Get-Date -Format "yyyyMMdd_HHmmss"
$ExportDir = Join-Path $OutputBase "aws-csp-$Region-$Date"

New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

Write-Host "========================================"
Write-Host "  AWS CSP Controls Export (PCI DSS)"
Write-Host "  Region  : $Region"
Write-Host "  Output  : $ExportDir"
Write-Host "========================================"

# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[ Credentials ]"
Write-Host -NoNewline ("  " + "Setting AWS credentials...".PadRight(42) + "...")

try {
    if ($ProfileName) {
        Set-AWSCredential -ProfileName $ProfileName -ErrorAction Stop
    } elseif ($AccessKeyId -and $SecretAccessKey -and
              $AccessKeyId -ne "YOUR_ACCESS_KEY_ID") {
        Set-AWSCredential -AccessKey $AccessKeyId -SecretKey $SecretAccessKey -ErrorAction Stop
    }
    Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
    Write-Host " OK"
} catch {
    Write-Host " FAILED ($_)"
    exit 1
}

$AccountId = "unknown"
try {
    $AccountId = (Get-STSCallerIdentity -ErrorAction Stop).Account
    Write-Host ("  " + "Account ID:".PadRight(42) + "  $AccountId")
} catch { }

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
    Write-Host -NoNewline ("  " + $Label.PadRight(42) + "...")

    try {
        $data  = & $Fetch
        $items = @($data)

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
# 1. IAM — IDENTITY AND ACCESS MANAGEMENT
#    IAM is account-global (not regional). All users, groups, roles, and
#    policies apply to the entire AWS account regardless of region.
# ==============================================================================
Write-Host ""
Write-Host "[ IAM — Identity and Access Management ]"

Export-AwsResource "Password policy" "iam-password-policy.json" {
    # Single object — wraps complexity, check, length, reuse, expiry settings
    Get-IAMAccountPasswordPolicy
}

# Credential report — the most important single artifact for PCI IAM review.
# Covers every IAM user: password age, MFA enrolled (yes/no), access key ages,
# access key last-used dates, and last console login. Saved as CSV.
Write-Host -NoNewline ("  " + "Credential report (MFA + key ages)...".PadRight(42) + "...")
$credReportPath = Join-Path $ExportDir "iam-credential-report.csv"
try {
    $null = Request-IAMCredentialReport -ErrorAction Stop
    # Poll until the report is ready (usually 3-10 seconds)
    $report = $null
    for ($attempt = 1; $attempt -le 8; $attempt++) {
        Start-Sleep -Seconds 5
        try {
            $report = Get-IAMCredentialReport -ErrorAction Stop
            break
        } catch {
            if ($attempt -eq 8) { throw }
        }
    }
    $reader = New-Object System.IO.StreamReader($report.Content)
    $csv    = $reader.ReadToEnd()
    $reader.Close()
    [System.IO.File]::WriteAllText($credReportPath, $csv, [System.Text.Encoding]::UTF8)
    $userCount = ($csv -split "`n").Count - 2   # subtract header and trailing blank
    Write-Host " OK ($userCount users)"
} catch {
    Write-Host " FAILED ($_)"
    "# Credential report generation failed: $_" |
        Out-File -FilePath $credReportPath -Encoding UTF8
}

Export-AwsResource "IAM users (with groups + policy attachments)" "iam-users.json" {
    Get-IAMUserList | ForEach-Object {
        $u = $_
        [PSCustomObject]@{
            UserName                = $u.UserName
            UserId                  = $u.UserId
            Arn                     = $u.Arn
            CreateDate              = $u.CreateDate
            PasswordLastUsed        = $u.PasswordLastUsed
            Path                    = $u.Path
            AttachedManagedPolicies = @(Get-IAMAttachedUserPolicyList -UserName $u.UserName  -ErrorAction SilentlyContinue)
            InlinePolicyNames       = @(Get-IAMUserPolicyList         -UserName $u.UserName  -ErrorAction SilentlyContinue)
            Groups                  = @(Get-IAMGroupForUser            -UserName $u.UserName  -ErrorAction SilentlyContinue)
        }
    }
}

Export-AwsResource "IAM groups (with policy attachments)" "iam-groups.json" {
    Get-IAMGroupList | ForEach-Object {
        $g = $_
        [PSCustomObject]@{
            GroupName               = $g.GroupName
            GroupId                 = $g.GroupId
            Arn                     = $g.Arn
            CreateDate              = $g.CreateDate
            Path                    = $g.Path
            AttachedManagedPolicies = @(Get-IAMAttachedGroupPolicyList -GroupName $g.GroupName -ErrorAction SilentlyContinue)
            InlinePolicyNames       = @(Get-IAMGroupPolicyList          -GroupName $g.GroupName -ErrorAction SilentlyContinue)
        }
    }
}

Export-AwsResource "IAM roles (with trust + policy attachments)" "iam-roles.json" {
    Get-IAMRoleList | ForEach-Object {
        $r = $_
        [PSCustomObject]@{
            RoleName                = $r.RoleName
            RoleId                  = $r.RoleId
            Arn                     = $r.Arn
            CreateDate              = $r.CreateDate
            Description             = $r.Description
            Path                    = $r.Path
            # AssumeRolePolicyDocument contains who/what can assume this role
            TrustPolicy             = [System.Uri]::UnescapeDataString($r.AssumeRolePolicyDocument)
            AttachedManagedPolicies = @(Get-IAMAttachedRolePolicyList -RoleName $r.RoleName -ErrorAction SilentlyContinue)
            InlinePolicyNames       = @(Get-IAMRolePolicyList          -RoleName $r.RoleName -ErrorAction SilentlyContinue)
        }
    }
}

Export-AwsResource "MFA devices (all users)" "iam-mfa-devices.json" {
    # Returns all virtual and hardware MFA devices with the username they belong to
    Get-IAMMFADeviceList
}

# ==============================================================================
# 2. CLOUDTRAIL — AUDIT LOGGING
#    CloudTrail records all API calls across the account. PCI requires logging
#    to be enabled and protected. Multi-region trails appear in all regions
#    via -IncludeShadowTrails. Status is retrieved for trails home to $Region.
# ==============================================================================
Write-Host ""
Write-Host "[ CloudTrail ]"

Export-AwsResource "Trails and logging status" "cloudtrail-trails.json" {
    $trails = @(Get-CTTrailList -IncludeShadowTrails $true)
    $trails | ForEach-Object {
        $t      = $_
        $status = $null
        $note   = $null
        if ($t.HomeRegion -eq $Region) {
            try { $status = Get-CTTrailStatus -Name $t.TrailARN -ErrorAction Stop }
            catch { $note = "Status retrieval failed: $_" }
        } else {
            $note = "Trail home region is $($t.HomeRegion) — run script in that region for status"
        }
        [PSCustomObject]@{
            Trail          = $t
            LoggingStatus  = $status
            Note           = $note
        }
    }
}

# ==============================================================================
# 3. S3 — STORAGE ACCESS AND LOGGING
#    S3 is account-global. This exports every bucket with its public access
#    block configuration, bucket policy, public status, logging target,
#    and versioning — the full picture for PCI log integrity and data exposure.
# ==============================================================================
Write-Host ""
Write-Host "[ S3 — Storage ]"

Export-AwsResource "Buckets (policy + public access + logging)" "s3-buckets.json" {
    @(Get-S3Bucket) | ForEach-Object {
        $bn    = $_.BucketName
        $entry = [PSCustomObject]@{
            BucketName        = $bn
            CreationDate      = $_.CreationDate
            Region            = $null
            PublicAccessBlock = $null   # BlockPublicAcls, IgnorePublicAcls,
                                        # BlockPublicPolicy, RestrictPublicBuckets
            Policy            = $null   # Raw bucket policy JSON (if any)
            IsPublicViaPolicy = $null   # AWS evaluation: is bucket public?
            Logging           = $null   # Log target bucket and prefix
            Versioning        = $null   # Enabled / Suspended / Off
        }
        try { $entry.Region            = (Get-S3BucketLocation          -BucketName $bn -ErrorAction Stop).Value } catch {}
        try { $entry.PublicAccessBlock = Get-S3BucketPublicAccessBlock   -BucketName $bn -ErrorAction Stop        } catch {}
        try { $entry.Policy            = Get-S3BucketPolicy              -BucketName $bn -ErrorAction Stop        } catch {}
        try { $entry.IsPublicViaPolicy = (Get-S3BucketPolicyStatus       -BucketName $bn -ErrorAction Stop).PolicyStatus.IsPublic } catch {}
        try { $entry.Logging           = Get-S3BucketLogging             -BucketName $bn -ErrorAction Stop        } catch {}
        try { $entry.Versioning        = (Get-S3BucketVersioning         -BucketName $bn -ErrorAction Stop).Status } catch {}
        $entry
    }
}

# ==============================================================================
# 4. AWS CONFIG — CONFIGURATION COMPLIANCE
#    AWS Config evaluates resources against rules continuously. PCI requires
#    Config to be enabled and compliant rules to validate specific controls.
#    Results shown here are for the configured region only.
# ==============================================================================
Write-Host ""
Write-Host "[ AWS Config ]"

Export-AwsResource "Configuration recorders" "config-recorders.json" {
    $recorders = @(Get-CFGConfigurationRecorder)
    $recorders | ForEach-Object {
        $r = $_
        $status = $null
        try { $status = Get-CFGConfigurationRecorderStatus -ConfigurationRecorderName $r.Name -ErrorAction Stop }
        catch {}
        [PSCustomObject]@{
            Recorder = $r
            Status   = $status
        }
    }
}

Export-AwsResource "Config rules and compliance" "config-rules-compliance.json" {
    $rules = @(Get-CFGConfigRule)
    $rules | ForEach-Object {
        $r = $_
        $compliance = $null
        try { $compliance = Get-CFGComplianceDetailsByConfigRule -ConfigRuleName $r.ConfigRuleName -ErrorAction Stop }
        catch {}
        [PSCustomObject]@{
            RuleName          = $r.ConfigRuleName
            Source            = $r.Source
            Scope             = $r.Scope
            MaxExecutionFreq  = $r.MaximumExecutionFrequency
            ConfigRuleState   = $r.ConfigRuleState
            ComplianceDetails = $compliance
        }
    }
}

# ==============================================================================
# 5. GUARDDUTY — THREAT DETECTION
#    GuardDuty detects malicious activity and unauthorized behavior. Active
#    findings indicate potential threats that may be relevant to PCI scope.
#    Results are for the configured region. Run per-region if GuardDuty is
#    enabled in multiple regions.
# ==============================================================================
Write-Host ""
Write-Host "[ GuardDuty ]"

if (-not $gdAvailable) {
    Write-Host "  AWS.Tools.GuardDuty not available -- skipping"
    Write-Host "  Install with: Install-Module -Name AWS.Tools.GuardDuty -Scope CurrentUser"
} else {
    $detectorIds = @()
    try { $detectorIds = @(Get-GDDetectorList -ErrorAction Stop) } catch { }

    if ($detectorIds.Count -eq 0) {
        Write-Host "  GuardDuty is not enabled in region $Region"
        @{ checked = $true; enabled = $false; region = $Region } |
            ConvertTo-Json | Out-File -FilePath (Join-Path $ExportDir "guardduty-not-enabled.json") -Encoding UTF8
    } else {
        Export-AwsResource "GuardDuty detectors" "guardduty-detectors.json" {
            $detectorIds | ForEach-Object { Get-GDDetector -DetectorId $_ }
        }

        Export-AwsResource "GuardDuty findings (active)" "guardduty-findings.json" {
            $detectorIds | ForEach-Object {
                $did      = $_
                # Retrieve active (non-archived) finding IDs then fetch details
                $findingIds = @(Get-GDFindingList -DetectorId $did `
                    -FindingCriteria_Criterion @{
                        "service.archived" = @{ Eq = @("false") }
                    } -ErrorAction Stop)
                if ($findingIds.Count -gt 0) {
                    # GetFindings accepts up to 50 IDs at a time
                    $chunks = [System.Linq.Enumerable]::Chunk($findingIds, 50)
                    foreach ($chunk in $chunks) {
                        Get-GDFinding -DetectorId $did -FindingId $chunk -ErrorAction SilentlyContinue
                    }
                }
            }
        }
    }
}

# ==============================================================================
# 6. SECURITY HUB — COMPLIANCE POSTURE
#    Security Hub aggregates findings from AWS services and partner tools,
#    and evaluates against standards including PCI DSS. Active FAILED findings
#    against enabled standards are exported here.
#    Results are for the configured region.
# ==============================================================================
Write-Host ""
Write-Host "[ Security Hub ]"

if (-not $shAvailable) {
    Write-Host "  AWS.Tools.SecurityHub not available -- skipping"
    Write-Host "  Install with: Install-Module -Name AWS.Tools.SecurityHub -Scope CurrentUser"
} else {
    $hubEnabled = $false
    try {
        $hub = Get-SHUBHub -ErrorAction Stop
        $hubEnabled = $true
    } catch {
        # SecurityHub throws InvalidAccessException if not enabled
    }

    if (-not $hubEnabled) {
        Write-Host "  Security Hub is not enabled in region $Region"
        @{ checked = $true; enabled = $false; region = $Region } |
            ConvertTo-Json | Out-File -FilePath (Join-Path $ExportDir "securityhub-not-enabled.json") -Encoding UTF8
    } else {
        Export-AwsResource "Security Hub overview + standards" "securityhub-overview.json" {
            $standards = @(Get-SHUBEnabledStandardList -ErrorAction SilentlyContinue)
            [PSCustomObject]@{
                Hub              = $hub
                EnabledStandards = $standards
            }
        }

        # Export active FAILED findings — these are the non-compliant controls
        # that require remediation. Filtered to FAILED compliance status and
        # ACTIVE record state (excludes resolved and suppressed findings).
        Export-AwsResource "Security Hub findings (active / failed)" "securityhub-findings.json" {
            Get-SHUBFindingList `
                -Filter_RecordState    @(@{ Value = "ACTIVE";  Comparison = "EQUALS" }) `
                -Filter_ComplianceStatus @(@{ Value = "FAILED"; Comparison = "EQUALS" }) `
                -ErrorAction Stop
        }
    }
}

# ==============================================================================
# 7. MANIFEST
# ==============================================================================
Write-Host ""

$manifestPath = Join-Path $ExportDir "MANIFEST.txt"
$files        = Get-ChildItem $ExportDir |
                    Where-Object { $_.Name -ne "MANIFEST.txt" } |
                    Sort-Object Name

$manifestLines = @(
    "AWS CSP Controls Export Manifest (PCI DSS)"
    "Account ID : $AccountId"
    "Region     : $Region"
    "Exported   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Host       : $env:COMPUTERNAME"
    "User       : $env:USERNAME"
    ""
    "Files:"
)
foreach ($f in $files) {
    $sizeKB = [math]::Round($f.Length / 1KB, 1)
    $manifestLines += "  {0,-52} {1} KB" -f $f.Name, $sizeKB
}
$manifestLines | Out-File -FilePath $manifestPath -Encoding UTF8

Write-Host "========================================"
Write-Host "  Export complete."
Write-Host "  Files saved to: $ExportDir"
Write-Host ""
Write-Host "  For assessor review:"
Write-Host "  - iam-credential-report.csv  -- open in Excel; check mfa_active,"
Write-Host "    password_last_used, access_key_1_last_used_date columns"
Write-Host "  - iam-password-policy.json   -- verify complexity requirements"
Write-Host "  - cloudtrail-trails.json     -- confirm IsLogging = true on all trails"
Write-Host "  - s3-buckets.json            -- check IsPublicViaPolicy and PublicAccessBlock"
Write-Host "  - config-rules-compliance.json -- look for NON_COMPLIANT rules"
Write-Host "  - securityhub-findings.json  -- active failed PCI DSS controls"
Write-Host "========================================"
