<#
.SYNOPSIS
    Export Azure cloud service provider controls for PCI DSS assessment.

.DESCRIPTION
    Connects to Microsoft Entra ID (through Microsoft Graph) and to Azure
    Resource Manager and exports identity, access, and logging configuration
    relevant to PCI DSS controls, including:
      - Entra ID users with MFA registration status, last sign-in, and
        password age — one row per user, in a CSV ready for Excel
      - Directory role assignments (active and PIM-eligible), members of
        privileged groups, and PIM activation settings per role
      - Conditional Access policies, security defaults, authentication methods
        policy, smart lockout settings, and domain password expiry
      - App registration secrets and certificates with expiry dates
      - Entra ID sign-in and audit log export (diagnostic settings)
      - Azure RBAC role assignments (active and PIM-eligible) and custom roles
      - Activity log export, resource diagnostic settings, Log Analytics
        retention per table, and SQL server auditing
      - Storage account access settings and blob container public access
      - Key Vault protection settings
      - Microsoft Defender for Cloud plans, recommendations, secure score,
        security contacts, and PCI DSS regulatory compliance results
      - Azure Policy assignments and non-compliant resources

    pci-checks.csv summarises the results as a scorecard (current value vs.
    expected value, with the PCI DSS requirement) and is the file to read first.

    All output is saved to a timestamped folder as JSON and CSV files readable
    in VS Code, Notepad++, or Excel. No changes are made to Entra ID or Azure.

    Every exported file is hashed with SHA-256 and recorded in MANIFEST.txt for
    chain-of-custody and integrity verification, alongside a checksums.sha256
    file that can be verified independently.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.NOTES
    Requires the Az.Accounts and Microsoft.Graph.Authentication PowerShell
    modules. The script will offer to install these automatically if not found.

    Entra ID collection runs in a second PowerShell process that the script
    starts itself, so the two modules never load into the same session (their
    sign-in libraries can conflict on Windows PowerShell 5.1).

    See azure-csp-export_powershell_readme.txt for full setup instructions.
#>

param(
    # Internal: the script re-launches itself with -Phase Entra to collect
    # Entra ID data in a separate process. Run the script without parameters.
    [ValidateSet("All", "Entra")]
    [string]$Phase  = "All",
    [string]$RunDir = ""
)

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================
$TenantId        = "YOUR_TENANT_ID"          # Entra ID Tenant ID (GUID)

# Subscriptions to export. List every subscription that hosts in-scope (CDE or
# connected) resources. Leave empty — @() — to export every enabled
# subscription the account can see in this tenant.
$SubscriptionIds = @("YOUR_SUBSCRIPTION_ID")

# Service Principal credentials — for non-interactive / scripted use.
# Leave both as "" to use interactive browser sign-in instead.
$ClientId        = ""                         # App Registration Application (client) ID
$ClientSecret    = ""                         # App Registration client secret

$OutputBase      = "C:\azure-export"

$CollectEntra    = $true    # Entra ID: users, MFA, roles, Conditional Access
$CollectAzure    = $true    # Subscriptions: RBAC, logging, storage, Defender, Policy
$InactiveDays    = 90       # PCI DSS 8.2.6 inactive account threshold (days)
# ==============================================================================

$UseServicePrincipal = [bool]($ClientId -and $ClientSecret)
$Inv    = [System.Globalization.CultureInfo]::InvariantCulture
$NowUtc = (Get-Date).ToUniversalTime()

# Microsoft Graph permissions. Requested as delegated scopes for interactive
# sign-in; grant the same names as application permissions to a service
# principal. All are read-only.
$GraphScopes = @(
    "Directory.Read.All",
    "AuditLog.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.Directory",
    "RoleManagementPolicy.Read.Directory",
    "UserAuthenticationMethod.Read.All"
)

# Roles treated as privileged for the scorecard checks
$PrivilegedEntraRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "User Administrator",
    "Authentication Administrator",
    "Helpdesk Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Hybrid Identity Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Intune Administrator"
)
$PrivilegedAzureRoles = @(
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Role Based Access Control Administrator"
)
$GlobalAdminTemplateId = "62e90394-69f5-4237-9190-012177145e10"

$Checks     = New-Object System.Collections.ArrayList
$LogScope   = "Tenant"
$OutDir     = $RunDir
$LastExportOk = $true

# ==============================================================================
# HELPERS (shared by both phases)
# ==============================================================================

function Write-Status([string]$Label) {
    Write-Host -NoNewline ("  " + $Label.PadRight(46) + "...")
}

# One line per collected item in collection-log.txt, so a partial collection
# is visible in the evidence itself and not only on the console
function Write-Log([string]$Status, [string]$Item, [string]$Detail = "") {
    $line = "{0} UTC  {1,-7} {2,-34} {3}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", $Inv), $Status, $LogScope, $Item
    if ($Detail) { $line += "  -- $Detail" }
    Add-Content -Path (Join-Path $RunDir "collection-log.txt") -Value $line -Encoding UTF8
}

# Scorecard row. Status is PASS, FAIL, REVIEW, INFO, or UNKNOWN (not collected)
function Add-Check([string]$Scope, [string]$Area, [string]$Check, [string]$Status,
                   [string]$Current, [string]$Expected, [string]$Pci, [string]$Evidence) {
    [void]$script:Checks.Add([PSCustomObject]@{
        Scope        = $Scope
        Area         = $Area
        Check        = $Check
        Status       = $Status
        Current      = $Current
        Expected     = $Expected
        PciDss       = $Pci
        EvidenceFile = $Evidence
    })
}

# Always returns an array (empty for $null) without nesting
function Get-Items($Value) {
    if ($null -eq $Value) { return ,@() }
    return ,@($Value)
}

function Test-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function Get-Value($Object, [string]$Name) {
    if (Test-Prop $Object $Name) { return $Object.$Name }
    return $null
}

# ConvertFrom-Json fails on keys that differ only in case (common in resource
# tags, e.g. "Env" and "env"). PowerShell 7 can still read those payloads as
# hashtables; Windows PowerShell 5.1 retries with the tag blocks removed (tags
# are labels, not evidence).
function ConvertFrom-JsonSafe([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        return ($Text | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            return ($Text | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
        }
        $noTags = $Text -replace '"tags"\s*:\s*\{[^{}]*\}', '"tags":null'
        return ($noTags | ConvertFrom-Json -ErrorAction Stop)
    }
}

function ConvertTo-UtcDate($Value) {
    if ($null -eq $Value -or "$Value" -eq "") { return $null }
    if ($Value -is [datetime])       { return $Value.ToUniversalTime() }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]"AdjustToUniversal, AssumeUniversal"
    if ([datetime]::TryParse("$Value", $Inv, $styles, [ref]$d)) { return $d }
    return $null
}

function Format-Date($Date) {
    if ($null -eq $Date) { return "" }
    return $Date.ToString("yyyy-MM-dd HH:mm", $Inv)
}

function Get-DaysSince($Date) {
    if ($null -eq $Date) { return $null }
    return [int][math]::Floor(($NowUtc - $Date).TotalDays)
}

function Join-List($Values) {
    return ((Get-Items $Values) | Where-Object { "$_" -ne "" }) -join "; "
}

function Get-NameFromId([string]$Id) {
    if (-not $Id) { return "" }
    return ($Id.TrimEnd('/') -split '/')[-1]
}

function Get-ResourceGroupFromId([string]$Id) {
    if ($Id -match '/resourceGroups/([^/]+)') { return $matches[1] }
    return ""
}

function Get-ScopeLevel([string]$Scope) {
    if ($Scope -eq "/")                                         { return "Root" }
    if ($Scope -match '/managementGroups/[^/]+$')               { return "Management group" }
    if ($Scope -match '^/subscriptions/[^/]+$')                 { return "Subscription" }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return "Resource group" }
    return "Resource"
}

# Pulls "code: message" out of Graph / ARM error responses
function Get-ErrorText($ErrorRecord) {
    $text = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
    if ($text -match '"code"\s*:\s*"([^"]+)"[\s\S]*?"message"\s*:\s*"([^"]+)"') {
        $text = "$($matches[1]): $($matches[2])"
    } else {
        $text = "$($ErrorRecord.Exception.Message)"
    }
    $text = ($text -replace '\s+', ' ').Trim()
    if ($text.Length -gt 300) { $text = $text.Substring(0, 300) + "..." }
    return $text
}

# Run a fetch scriptblock and save the result as JSON. Returns the data (an
# array, or an object with -Single). On failure writes a marker file saying
# the item was not collected, sets $LastExportOk to $false, and returns an
# empty array (or $null with -Single).
function Export-Data {
    param(
        [string]$Label,
        [string]$File,
        [scriptblock]$Fetch,
        [switch]$Single
    )

    $outPath = Join-Path $OutDir $File
    Write-Status $Label

    try {
        $data = & $Fetch
        if ($Single) {
            $json    = if ($null -eq $data) { "{}" } else { ConvertTo-Json -InputObject $data -Depth 20 }
            $summary = "1 object"
        } else {
            $items   = Get-Items $data
            $json    = if ($items.Count -eq 0) { "[]" } else { ConvertTo-Json -InputObject $items -Depth 20 }
            $summary = "$($items.Count) items"
        }
        [System.IO.File]::WriteAllText($outPath, $json, [System.Text.Encoding]::UTF8)

        $sizeKB = [math]::Round((Get-Item $outPath).Length / 1KB, 1)
        Write-Host " OK ($summary, ${sizeKB} KB)"
        Write-Log "OK" $File $summary
        $script:LastExportOk = $true
        if ($Single) { return $data }
        return ,$items

    } catch {
        $msg = Get-ErrorText $_
        Write-Host " FAILED ($msg)"
        Write-Log "FAILED" $File $msg
        $marker = [PSCustomObject]@{ collected = $false; item = $Label; error = $msg }
        [System.IO.File]::WriteAllText($outPath, (ConvertTo-Json -InputObject $marker), [System.Text.Encoding]::UTF8)
        $script:LastExportOk = $false
        if ($Single) { return $null }
        return ,@()
    }
}

# Build rows with a scriptblock and save them as CSV (opens directly in Excel)
function Export-Rows {
    param(
        [string]$Label,
        [string]$File,
        [scriptblock]$Build
    )

    $outPath = Join-Path $OutDir $File
    Write-Status $Label

    try {
        $rows = Get-Items (& $Build)
        if ($rows.Count -eq 0) {
            [System.IO.File]::WriteAllText($outPath, "No records returned`r`n", [System.Text.Encoding]::UTF8)
        } else {
            $rows | Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8
        }
        Write-Host " OK ($($rows.Count) rows)"
        Write-Log "OK" $File "$($rows.Count) rows"
        return ,$rows
    } catch {
        $msg = Get-ErrorText $_
        Write-Host " FAILED ($msg)"
        Write-Log "FAILED" $File $msg
        [System.IO.File]::WriteAllText($outPath, "Not collected: $msg`r`n", [System.Text.Encoding]::UTF8)
        return ,@()
    }
}

# ==============================================================================
# PHASE: ENTRA ID (runs in its own PowerShell process — see .NOTES)
# ==============================================================================
if ($Phase -eq "Entra") {

    $LogScope   = "Tenant"
    $CheckScope = "Tenant"
    $OutDir     = Join-Path $RunDir "tenant"
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

    # GET a Microsoft Graph URI. Collections are followed through every page
    # and emitted item by item; single objects are emitted as-is.
    function Invoke-Graph([string]$Uri) {
        $next = $Uri
        while ($next) {
            $text = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Json -ErrorAction Stop
            $resp = ConvertFrom-JsonSafe $text
            if (-not (Test-Prop $resp "value")) { return $resp }
            foreach ($v in (Get-Items $resp.value)) { $v }
            $next = Get-Value $resp "@odata.nextLink"
        }
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    Write-Host ""
    Write-Host "[ Connecting to Microsoft Graph (Entra ID) ]"
    Write-Status "Authenticating"
    try {
        $mg = @{ TenantId = $TenantId; ErrorAction = "Stop" }
        if ($UseServicePrincipal) {
            $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $mg.ClientSecretCredential = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
        } else {
            $mg.Scopes = $GraphScopes
        }
        if ((Get-Command Connect-MgGraph).Parameters.ContainsKey("NoWelcome")) { $mg.NoWelcome = $true }
        Connect-MgGraph @mg | Out-Null
        $mgCtx = Get-MgContext
        $who   = if ($mgCtx.Account) { $mgCtx.Account } else { "service principal $($mgCtx.ClientId)" }
        Write-Host " OK"
        Write-Host ("  " + "Signed in as:".PadRight(46) + "   $who")
        Write-Log "OK" "Microsoft Graph sign-in" $who
    } catch {
        $msg = Get-ErrorText $_
        Write-Host " FAILED ($msg)"
        Write-Log "FAILED" "Microsoft Graph sign-in" $msg
        exit 1
    }

    # ==========================================================================
    # 1. TENANT
    #    Organization, licensing, and domains. Entra ID P1/P2 licensing decides
    #    whether sign-in activity, MFA registration reports, Conditional Access,
    #    and PIM are available at all.
    # ==========================================================================
    Write-Host ""
    Write-Host "[ Tenant ]"

    $org = Export-Data "Organization" "entra-organization.json" {
        Invoke-Graph "v1.0/organization"
    }
    $tenantName = ""
    foreach ($o in $org) {
        $tenantName = $o.displayName
        foreach ($d in (Get-Items $o.verifiedDomains)) { if ($d.isDefault) { $tenantName += " ($($d.name))" } }
    }
    if ($tenantName) { Write-Host ("  " + "Tenant:".PadRight(46) + "   $tenantName") }

    $skus = Export-Data "Licenses (subscribed SKUs)" "entra-licenses.json" {
        Invoke-Graph "v1.0/subscribedSkus"
    }
    $skusOk = $LastExportOk
    $planNames = @()
    foreach ($sku in $skus) {
        if ($sku.capabilityStatus -eq "Enabled") {
            foreach ($sp in (Get-Items $sku.servicePlans)) { $planNames += $sp.servicePlanName }
        }
    }
    $hasP2 = $planNames -contains "AAD_PREMIUM_P2"
    $hasP1 = $hasP2 -or ($planNames -contains "AAD_PREMIUM")

    $domains = Export-Data "Domains (federation, password expiry)" "entra-domains.json" {
        Invoke-Graph "v1.0/domains"
    }
    $domainsOk = $LastExportOk

    # ==========================================================================
    # 2. DIRECTORY OBJECTS
    #    Users (with sign-in activity where licensed), MFA registration,
    #    groups, and service principals. Sign-in activity needs Entra ID P1/P2;
    #    without it the export falls back to users without sign-in dates.
    # ==========================================================================
    Write-Host ""
    Write-Host "[ Users, groups, and MFA registration ]"

    $userSelect      = "id,displayName,userPrincipalName,mail,userType,accountEnabled,createdDateTime,lastPasswordChangeDateTime,passwordPolicies,onPremisesSyncEnabled,externalUserState,creationType"
    $signInAvailable = $true
    $users = Export-Data "Users (with sign-in activity)" "entra-users.json" {
        try {
            $r = @(Invoke-Graph ('v1.0/users?$select=' + $userSelect + ',signInActivity&$top=999'))
            $r
        } catch {
            $script:signInAvailable = $false
            Write-Log "INFO" "signInActivity" ("Not available, users exported without sign-in dates: " + (Get-ErrorText $_))
            Invoke-Graph ('v1.0/users?$select=' + $userSelect + '&$top=999')
        }
    }
    $usersOk = $LastExportOk
    if ($usersOk -and -not $signInAvailable) {
        Write-Host "    (sign-in activity unavailable: requires Entra ID P1/P2 and AuditLog.Read.All)"
    }

    $mfaReg = Export-Data "MFA registration details" "entra-mfa-registration.json" {
        Invoke-Graph "v1.0/reports/authenticationMethods/userRegistrationDetails"
    }
    $mfaRegOk = $LastExportOk

    $groups = Export-Data "Groups" "entra-groups.json" {
        Invoke-Graph 'v1.0/groups?$select=id,displayName,description,securityEnabled,mailEnabled,groupTypes,isAssignableToRole,membershipRule,onPremisesSyncEnabled,createdDateTime&$top=999'
    }

    $sps = Export-Data "Service principals (enterprise apps)" "entra-service-principals.json" {
        Invoke-Graph 'v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId&$top=999'
    }

    # Lookups used to put names on IDs throughout the rest of the export
    $userById      = @{}
    $principalById = @{}
    $spByAppId     = @{}
    $regById       = @{}
    foreach ($u in $users) {
        $userById[$u.id] = $u
        $principalById[$u.id] = [PSCustomObject]@{ Type = "User"; Name = $u.displayName; Upn = $u.userPrincipalName; UserType = $u.userType; Enabled = $u.accountEnabled }
    }
    foreach ($g in $groups) {
        $principalById[$g.id] = [PSCustomObject]@{ Type = "Group"; Name = $g.displayName; Upn = ""; UserType = ""; Enabled = "" }
    }
    foreach ($sp in $sps) {
        $principalById[$sp.id] = [PSCustomObject]@{ Type = "ServicePrincipal"; Name = $sp.displayName; Upn = $sp.appId; UserType = $sp.servicePrincipalType; Enabled = $sp.accountEnabled }
        if ($sp.appId) { $spByAppId[$sp.appId] = $sp.displayName }
    }
    foreach ($r in $mfaReg) { if ($r.id) { $regById[$r.id] = $r } }

    function Resolve-Principal([string]$Id) {
        if ($Id -and $principalById.ContainsKey($Id)) { return $principalById[$Id] }
        return [PSCustomObject]@{ Type = "Unknown"; Name = "(not found - deleted, or no read access)"; Upn = ""; UserType = ""; Enabled = "" }
    }

    # ==========================================================================
    # 3. DIRECTORY ROLES AND PIM
    #    Active assignments work on every tenant. Eligible assignments, active
    #    assignment schedules (which show expiry), and role activation settings
    #    need Privileged Identity Management (Entra ID P2).
    # ==========================================================================
    Write-Host ""
    Write-Host "[ Directory roles and PIM ]"

    $roleDefs = Export-Data "Role definitions" "entra-role-definitions.json" {
        Invoke-Graph 'v1.0/roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,isEnabled,templateId'
    }
    $roleNameById = @{}
    foreach ($d in $roleDefs) {
        $roleNameById[$d.id] = $d.displayName
        if ($d.templateId) { $roleNameById[$d.templateId] = $d.displayName }
    }

    $roleAssign = Export-Data "Active role assignments" "entra-role-assignments.json" {
        try {
            $r = @(Invoke-Graph "v1.0/roleManagement/directory/roleAssignments")
            $r
        } catch {
            # Some tenants require a filter on this endpoint — query role by role
            foreach ($d in $roleDefs) {
                Invoke-Graph ('v1.0/roleManagement/directory/roleAssignments?$filter=' + [uri]::EscapeDataString("roleDefinitionId eq '$($d.id)'"))
            }
        }
    }
    $roleAssignOk = $LastExportOk

    $pimEligible = Export-Data "PIM eligible assignments" "entra-pim-eligible.json" {
        Invoke-Graph "v1.0/roleManagement/directory/roleEligibilitySchedules"
    }
    $pimEligibleOk = $LastExportOk

    $pimActive = Export-Data "PIM active assignment schedules" "entra-pim-active-schedules.json" {
        Invoke-Graph "v1.0/roleManagement/directory/roleAssignmentSchedules"
    }
    $pimActiveOk = $LastExportOk

    $pimPolicies = Export-Data "PIM role settings (activation rules)" "entra-pim-role-settings.json" {
        Invoke-Graph ('v1.0/policies/roleManagementPolicyAssignments?$filter=' +
            [uri]::EscapeDataString("scopeId eq '/' and scopeType eq 'DirectoryRole'") +
            '&$expand=' + [uri]::EscapeDataString('policy($expand=rules)'))
    }
    $pimPoliciesOk = $LastExportOk

    # Active schedules indexed so each active assignment can show its expiry
    $schedIdx = @{}
    foreach ($s in $pimActive) {
        $schedIdx["$($s.principalId)|$($s.roleDefinitionId)|$($s.directoryScopeId)"] = $s
    }

    $roleRows = Export-Rows "Role assignments (active + eligible)" "entra-role-assignments.csv" {
        foreach ($a in $roleAssign) {
            $p       = Resolve-Principal $a.principalId
            $expires = "Unknown (PIM data unavailable)"
            $via     = "Direct"
            if ($pimActiveOk) {
                $key = "$($a.principalId)|$($a.roleDefinitionId)|$($a.directoryScopeId)"
                if ($schedIdx.ContainsKey($key)) {
                    $sch = $schedIdx[$key]
                    $end = ConvertTo-UtcDate $sch.scheduleInfo.expiration.endDateTime
                    $expires = if ($end) { Format-Date $end } else { "Never (permanent)" }
                    if ($sch.assignmentType -eq "Activated") { $via = "PIM activation" }
                } else {
                    $expires = "Never (no PIM schedule)"
                }
            }
            [PSCustomObject]@{
                Role              = $roleNameById[$a.roleDefinitionId]
                Privileged        = if ($PrivilegedEntraRoles -contains $roleNameById[$a.roleDefinitionId]) { "Yes" } else { "No" }
                State             = "Active"
                AssignedVia       = $via
                ExpiresUtc        = $expires
                PrincipalType     = $p.Type
                PrincipalName     = $p.Name
                PrincipalUPN      = $p.Upn
                PrincipalUserType = $p.UserType
                PrincipalEnabled  = $p.Enabled
                DirectoryScope    = $a.directoryScopeId
                PrincipalId       = $a.principalId
                RoleDefinitionId  = $a.roleDefinitionId
            }
        }
        foreach ($e in $pimEligible) {
            $p   = Resolve-Principal $e.principalId
            $end = ConvertTo-UtcDate $e.scheduleInfo.expiration.endDateTime
            [PSCustomObject]@{
                Role              = $roleNameById[$e.roleDefinitionId]
                Privileged        = if ($PrivilegedEntraRoles -contains $roleNameById[$e.roleDefinitionId]) { "Yes" } else { "No" }
                State             = "Eligible"
                AssignedVia       = "PIM eligibility"
                ExpiresUtc        = if ($end) { Format-Date $end } else { "Never (permanent)" }
                PrincipalType     = $p.Type
                PrincipalName     = $p.Name
                PrincipalUPN      = $p.Upn
                PrincipalUserType = $p.UserType
                PrincipalEnabled  = $p.Enabled
                DirectoryScope    = $e.directoryScopeId
                PrincipalId       = $e.principalId
                RoleDefinitionId  = $e.roleDefinitionId
            }
        }
    }

    function Get-PimRule($PolicyAssignment, [string]$RuleId) {
        foreach ($rule in (Get-Items $PolicyAssignment.policy.rules)) {
            if ($rule.id -eq $RuleId) { return $rule }
        }
        return $null
    }

    $pimRows = Export-Rows "PIM activation settings per role" "entra-pim-role-settings.csv" {
        foreach ($pa in $pimPolicies) {
            $enable  = Get-PimRule $pa "Enablement_EndUser_Assignment"
            $authCtx = Get-PimRule $pa "AuthenticationContext_EndUser_Assignment"
            $approve = Get-PimRule $pa "Approval_EndUser_Assignment"
            $actExp  = Get-PimRule $pa "Expiration_EndUser_Assignment"
            $eligExp = Get-PimRule $pa "Expiration_Admin_Eligibility"
            $asgExp  = Get-PimRule $pa "Expiration_Admin_Assignment"
            [PSCustomObject]@{
                Role                         = $roleNameById[$pa.roleDefinitionId]
                Privileged                   = if ($PrivilegedEntraRoles -contains $roleNameById[$pa.roleDefinitionId]) { "Yes" } else { "No" }
                ActivationRequiresMfa        = (Get-Items $enable.enabledRules) -contains "MultiFactorAuthentication"
                ActivationAuthContext        = if ($authCtx.isEnabled) { $authCtx.claimValue } else { "" }
                ActivationRequiresJustification = (Get-Items $enable.enabledRules) -contains "Justification"
                ActivationRequiresApproval   = [bool]$approve.setting.isApprovalRequired
                MaxActivationDuration        = $actExp.maximumDuration
                PermanentEligibleAllowed     = -not $eligExp.isExpirationRequired
                PermanentActiveAllowed       = -not $asgExp.isExpirationRequired
                RoleDefinitionId             = $pa.roleDefinitionId
            }
        }
    }

    # Members of every group that holds an Entra role, plus every group the
    # Azure phase found holding a privileged RBAC role (handed over in
    # _rbac-groups.csv). Without this, group-based admins are invisible.
    $groupAccess = @{}
    foreach ($r in $roleRows) {
        if ($r.PrincipalType -eq "Group") {
            if (-not $groupAccess.ContainsKey($r.PrincipalId)) { $groupAccess[$r.PrincipalId] = New-Object System.Collections.ArrayList }
            [void]$groupAccess[$r.PrincipalId].Add("Entra role: $($r.Role) ($($r.State))")
        }
    }
    $handoff = Join-Path $RunDir "_rbac-groups.csv"
    if (Test-Path $handoff) {
        foreach ($h in (Import-Csv $handoff)) {
            if (-not $groupAccess.ContainsKey($h.GroupId)) { $groupAccess[$h.GroupId] = New-Object System.Collections.ArrayList }
            [void]$groupAccess[$h.GroupId].Add($h.Access)
        }
    }

    $groupMemberRows = Export-Rows "Members of privileged groups" "entra-privileged-group-members.csv" {
        foreach ($gid in @($groupAccess.Keys)) {
            $gp     = Resolve-Principal $gid
            $access = ($groupAccess[$gid] | Select-Object -Unique) -join "; "
            try {
                $members = @(Invoke-Graph ('v1.0/groups/' + $gid + '/transitiveMembers?$top=999'))
            } catch {
                [PSCustomObject]@{ GroupName = $gp.Name; GrantedAccess = $access; MemberType = "ERROR"; MemberName = (Get-ErrorText $_); MemberUPN = ""; MemberUserType = ""; MemberEnabled = ""; MemberId = ""; GroupId = $gid }
                continue
            }
            if ($members.Count -eq 0) {
                [PSCustomObject]@{ GroupName = $gp.Name; GrantedAccess = $access; MemberType = "(no members)"; MemberName = ""; MemberUPN = ""; MemberUserType = ""; MemberEnabled = ""; MemberId = ""; GroupId = $gid }
            }
            foreach ($m in $members) {
                $type = "$(Get-Value $m '@odata.type')" -replace '^#microsoft\.graph\.', ''
                $mu   = if ($userById.ContainsKey("$($m.id)")) { $userById["$($m.id)"] } else { $null }
                [PSCustomObject]@{
                    GroupName      = $gp.Name
                    GrantedAccess  = $access
                    MemberType     = $type
                    MemberName     = $m.displayName
                    MemberUPN      = Get-Value $m "userPrincipalName"
                    MemberUserType = if ($mu) { $mu.userType } else { "" }
                    MemberEnabled  = if ($mu) { $mu.accountEnabled } else { "" }
                    MemberId       = $m.id
                    GroupId        = $gid
                }
            }
        }
    }

    # ==========================================================================
    # 4. USER SUMMARY CSV
    #    The primary identity evidence file: one row per user combining account
    #    state, last sign-in, MFA registration, password age, and admin roles.
    # ==========================================================================
    $rolesByPrincipal = @{}
    foreach ($r in $roleRows) {
        if (-not $rolesByPrincipal.ContainsKey($r.PrincipalId)) { $rolesByPrincipal[$r.PrincipalId] = New-Object System.Collections.ArrayList }
        [void]$rolesByPrincipal[$r.PrincipalId].Add("$($r.Role) ($($r.State))")
    }

    $userRows = Export-Rows "User summary (MFA, sign-in, password age)" "entra-users.csv" {
        foreach ($u in $users) {
            $reg  = if ($regById.ContainsKey($u.id)) { $regById[$u.id] } else { $null }
            $sia  = Get-Value $u "signInActivity"
            $lastInteractive = ConvertTo-UtcDate (Get-Value $sia "lastSignInDateTime")
            $lastNonInter    = ConvertTo-UtcDate (Get-Value $sia "lastNonInteractiveSignInDateTime")
            $lastSuccess     = ConvertTo-UtcDate (Get-Value $sia "lastSuccessfulSignInDateTime")
            # Prefer the last *successful* sign-in; older tenants only expose
            # attempt dates, so fall back to the most recent of those
            $last = $lastSuccess
            if (-not $last) {
                $last = $lastInteractive
                if ($lastNonInter -and (-not $last -or $lastNonInter -gt $last)) { $last = $lastNonInter }
            }
            $created  = ConvertTo-UtcDate $u.createdDateTime
            $pwdSet   = ConvertTo-UtcDate $u.lastPasswordChangeDateTime
            $inactive = "Unknown (sign-in data unavailable)"
            if ($signInAvailable) {
                if ($last) {
                    $inactive = if ((Get-DaysSince $last) -gt $InactiveDays) { "Yes" } else { "No" }
                } elseif ($created -and (Get-DaysSince $created) -gt $InactiveDays) {
                    $inactive = "Yes (never signed in)"
                } else {
                    $inactive = "No (new account, not yet signed in)"
                }
            }
            $mfaRegistered = "Unknown"
            $mfaCapable    = "Unknown"
            if ($mfaRegOk) {
                $mfaRegistered = if ($reg) { [bool]$reg.isMfaRegistered } else { "No data" }
                $mfaCapable    = if ($reg) { [bool]$reg.isMfaCapable }    else { "No data" }
            }
            [PSCustomObject]@{
                UserPrincipalName        = $u.userPrincipalName
                DisplayName              = $u.displayName
                UserType                 = $u.userType
                AccountEnabled           = $u.accountEnabled
                Source                   = if ($u.onPremisesSyncEnabled) { "Synced from AD" } else { "Cloud" }
                CreatedUtc               = Format-Date $created
                LastSignInUtc            = Format-Date $last
                DaysSinceLastSignIn      = Get-DaysSince $last
                Inactive                 = $inactive
                LastInteractiveSignInUtc = Format-Date $lastInteractive
                LastNonInteractiveSignInUtc = Format-Date $lastNonInter
                MfaRegistered            = $mfaRegistered
                MfaCapable               = $mfaCapable
                MethodsRegistered        = if ($reg) { Join-List $reg.methodsRegistered } else { "" }
                DefaultMfaMethod         = if ($reg) { $reg.defaultMfaMethod } else { "" }
                PasswordLastChangedUtc   = Format-Date $pwdSet
                PasswordAgeDays          = Get-DaysSince $pwdSet
                PasswordNeverExpires     = if ("$($u.passwordPolicies)" -match "DisablePasswordExpiration") { "Yes" } else { "No" }
                DirectoryRoles           = if ($rolesByPrincipal.ContainsKey($u.id)) { $rolesByPrincipal[$u.id] -join "; " } else { "" }
                ExternalUserState        = $u.externalUserState
                ObjectId                 = $u.id
            }
        }
    }

    # ==========================================================================
    # 5. AUTHENTICATION AND ACCESS POLICIES
    #    How MFA is enforced (security defaults or Conditional Access), which
    #    methods are allowed, guest/user defaults, and smart lockout.
    # ==========================================================================
    Write-Host ""
    Write-Host "[ Authentication and access policies ]"

    $secDefaults = Export-Data "Security defaults" "entra-security-defaults.json" -Single {
        Invoke-Graph "v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    }
    $caPolicies = Export-Data "Conditional Access policies" "entra-conditional-access-policies.json" {
        Invoke-Graph "v1.0/identity/conditionalAccess/policies"
    }
    $caOk = $LastExportOk
    $namedLocs = Export-Data "Named locations" "entra-named-locations.json" {
        Invoke-Graph "v1.0/identity/conditionalAccess/namedLocations"
    }
    $null = Export-Data "Authentication methods policy" "entra-auth-methods-policy.json" -Single {
        Invoke-Graph "v1.0/policies/authenticationMethodsPolicy"
    }
    $null = Export-Data "Authorization policy (user/guest defaults)" "entra-authorization-policy.json" -Single {
        Invoke-Graph "v1.0/policies/authorizationPolicy"
    }
    $dirSettings = Export-Data "Directory settings (smart lockout)" "entra-directory-settings.json" {
        Invoke-Graph "v1.0/groupSettings"
    }
    $dirSettingsOk = $LastExportOk

    $groupNameById = @{}
    foreach ($g in $groups) { $groupNameById[$g.id] = $g.displayName }
    $locNameById = @{}
    foreach ($l in $namedLocs) { $locNameById[$l.id] = $l.displayName }

    function Resolve-CaList($Values, [hashtable]$Names) {
        $out = foreach ($v in (Get-Items $Values)) {
            if ($Names.ContainsKey("$v")) { $Names["$v"] } else { "$v" }
        }
        return Join-List $out
    }
    $upnById = @{}
    foreach ($u in $users) { $upnById[$u.id] = $u.userPrincipalName }

    $null = Export-Rows "Conditional Access summary" "entra-conditional-access.csv" {
        foreach ($p in $caPolicies) {
            $c = $p.conditions
            $g = $p.grantControls
            $guests = Get-Value $c.users "includeGuestsOrExternalUsers"
            [PSCustomObject]@{
                PolicyName        = $p.displayName
                State             = $p.state
                IncludeUsers      = Resolve-CaList $c.users.includeUsers $upnById
                IncludeGroups     = Resolve-CaList $c.users.includeGroups $groupNameById
                IncludeRoles      = Resolve-CaList $c.users.includeRoles $roleNameById
                IncludeGuests     = if ($guests) { "$($guests.guestOrExternalUserTypes)" } else { "" }
                ExcludeUsers      = Resolve-CaList $c.users.excludeUsers $upnById
                ExcludeGroups     = Resolve-CaList $c.users.excludeGroups $groupNameById
                ExcludeRoles      = Resolve-CaList $c.users.excludeRoles $roleNameById
                IncludeApps       = Resolve-CaList $c.applications.includeApplications $spByAppId
                ExcludeApps       = Resolve-CaList $c.applications.excludeApplications $spByAppId
                UserActions       = Join-List $c.applications.includeUserActions
                ClientAppTypes    = Join-List $c.clientAppTypes
                Platforms         = Join-List $c.platforms.includePlatforms
                IncludeLocations  = Resolve-CaList $c.locations.includeLocations $locNameById
                ExcludeLocations  = Resolve-CaList $c.locations.excludeLocations $locNameById
                SignInRiskLevels  = Join-List $c.signInRiskLevels
                UserRiskLevels    = Join-List $c.userRiskLevels
                GrantOperator     = $g.operator
                GrantControls     = Join-List $g.builtInControls
                AuthStrength      = if ($g.authenticationStrength) { $g.authenticationStrength.displayName } else { "" }
                SignInFrequency   = if ($p.sessionControls.signInFrequency.isEnabled) { "$($p.sessionControls.signInFrequency.value) $($p.sessionControls.signInFrequency.type)" } else { "" }
                PersistentBrowser = if ($p.sessionControls.persistentBrowser.isEnabled) { $p.sessionControls.persistentBrowser.mode } else { "" }
                ModifiedUtc       = Format-Date (ConvertTo-UtcDate $p.modifiedDateTime)
                PolicyId          = $p.id
            }
        }
    }

    # ==========================================================================
    # 6. APPLICATION CREDENTIALS
    #    Client secrets and certificates on app registrations are credentials
    #    for application/system accounts (Req 8.6). Secret values are never
    #    returned by Graph — only names, hints, and validity dates.
    # ==========================================================================
    Write-Host ""
    Write-Host "[ Application credentials ]"

    $apps = Export-Data "App registrations" "entra-app-registrations.json" {
        Invoke-Graph 'v1.0/applications?$select=id,appId,displayName,createdDateTime,signInAudience,passwordCredentials,keyCredentials&$top=999'
    }
    $appsOk = $LastExportOk

    $credRows = Export-Rows "App secrets and certificates" "entra-app-credentials.csv" {
        foreach ($app in $apps) {
            $creds = @()
            foreach ($c in (Get-Items $app.passwordCredentials)) { $creds += [PSCustomObject]@{ Type = "Client secret"; Cred = $c } }
            foreach ($c in (Get-Items $app.keyCredentials))      { $creds += [PSCustomObject]@{ Type = "Certificate";   Cred = $c } }
            foreach ($x in $creds) {
                $start = ConvertTo-UtcDate $x.Cred.startDateTime
                $end   = ConvertTo-UtcDate $x.Cred.endDateTime
                [PSCustomObject]@{
                    Application    = $app.displayName
                    AppId          = $app.appId
                    CredentialType = $x.Type
                    CredentialName = $x.Cred.displayName
                    StartUtc       = Format-Date $start
                    EndUtc         = Format-Date $end
                    Status         = if ($end -and $end -lt $NowUtc) { "Expired" } else { "Active" }
                    LifetimeDays   = if ($start -and $end) { [int][math]::Floor(($end - $start).TotalDays) } else { "" }
                    DaysToExpiry   = if ($end) { [int][math]::Floor(($end - $NowUtc).TotalDays) } else { "" }
                    KeyId          = $x.Cred.keyId
                }
            }
        }
    }

    # ==========================================================================
    # 7. ENTRA ID SCORECARD CHECKS
    # ==========================================================================
    $enabledUsers   = @($users | Where-Object { $_.accountEnabled -eq $true })
    $enabledMembers = @($enabledUsers | Where-Object { $_.userType -eq "Member" })
    $enabledGuests  = @($enabledUsers | Where-Object { $_.userType -eq "Guest" })
    $privRoleRows   = @($roleRows | Where-Object { $_.Privileged -eq "Yes" })

    # --- Licensing (context for everything below)
    if ($skusOk) {
        $lic = if ($hasP2) { "Entra ID P2" } elseif ($hasP1) { "Entra ID P1" } else { "Free (no P1/P2)" }
        Add-Check $CheckScope "Licensing" "Entra ID premium licensing" "INFO" $lic "P1 for Conditional Access and sign-in activity; P2 for PIM" "-" "tenant/entra-licenses.json"
    }

    # --- MFA enforcement for all users
    $enabledCa = @($caPolicies | Where-Object { $_.state -eq "enabled" })
    function Test-CaRequiresMfa($Policy) {
        $g = $Policy.grantControls
        if (-not $g) { return $false }
        $controls = @((Get-Items $g.builtInControls) | Where-Object { $_ })
        $hasMfa   = ($controls -contains "mfa") -or [bool]$g.authenticationStrength
        $count    = $controls.Count + $(if ($g.authenticationStrength) { 1 } else { 0 })
        # With OR, any other control (e.g. compliant device) satisfies the policy
        return ($hasMfa -and ($g.operator -eq "AND" -or $count -eq 1))
    }
    function Test-CaAllUsersAllApps($Policy) {
        return ((Get-Items $Policy.conditions.users.includeUsers) -contains "All") -and
               ((Get-Items $Policy.conditions.applications.includeApplications) -contains "All")
    }
    $mfaPolicies    = @($enabledCa | Where-Object { Test-CaRequiresMfa $_ })
    $mfaAllPolicies = @($mfaPolicies | Where-Object { Test-CaAllUsersAllApps $_ })
    $secDefaultsOn  = ($secDefaults -and $secDefaults.isEnabled -eq $true)

    if ($secDefaultsOn) {
        Add-Check $CheckScope "Authentication" "MFA enforced for all users" "PASS" "Security defaults enabled" "Security defaults or Conditional Access requiring MFA for all users" "8.4.2, 8.4.3" "tenant/entra-security-defaults.json"
    } elseif (-not $caOk) {
        Add-Check $CheckScope "Authentication" "MFA enforced for all users" "UNKNOWN" "Conditional Access not collected" "Security defaults or Conditional Access requiring MFA for all users" "8.4.2, 8.4.3" "tenant/entra-conditional-access.csv"
    } elseif ($mfaAllPolicies.Count -gt 0) {
        $excl = 0
        foreach ($p in $mfaAllPolicies) { $excl += (Get-Items $p.conditions.users.excludeUsers).Count + (Get-Items $p.conditions.users.excludeGroups).Count }
        $status = if ($excl -gt 0) { "REVIEW" } else { "PASS" }
        Add-Check $CheckScope "Authentication" "MFA enforced for all users" $status "$($mfaAllPolicies.Count) CA policy(ies) require MFA for all users / all apps; $excl user/group exclusion(s)" "Security defaults or Conditional Access requiring MFA for all users; exclusions limited to break-glass accounts" "8.4.2, 8.4.3" "tenant/entra-conditional-access.csv"
    } elseif ($mfaPolicies.Count -gt 0) {
        Add-Check $CheckScope "Authentication" "MFA enforced for all users" "REVIEW" "$($mfaPolicies.Count) enabled CA policy(ies) require MFA, none for all users + all apps" "Security defaults or Conditional Access requiring MFA for all users" "8.4.2, 8.4.3" "tenant/entra-conditional-access.csv"
    } else {
        Add-Check $CheckScope "Authentication" "MFA enforced for all users" "FAIL" "Security defaults off; no enabled CA policy requires MFA" "Security defaults or Conditional Access requiring MFA for all users" "8.4.2, 8.4.3" "tenant/entra-conditional-access.csv"
    }

    # --- MFA enforced for administrators
    $adminMfa = @($mfaPolicies | Where-Object {
        ((Get-Items $_.conditions.users.includeUsers) -contains "All") -or
        ((Get-Items $_.conditions.users.includeRoles) -contains $GlobalAdminTemplateId)
    })
    if ($secDefaultsOn) {
        Add-Check $CheckScope "Authentication" "MFA enforced for administrators" "PASS" "Security defaults enabled" "MFA required for all administrative roles" "8.4.1" "tenant/entra-security-defaults.json"
    } elseif (-not $caOk) {
        Add-Check $CheckScope "Authentication" "MFA enforced for administrators" "UNKNOWN" "Conditional Access not collected" "MFA required for all administrative roles" "8.4.1" "tenant/entra-conditional-access.csv"
    } else {
        $status = if ($adminMfa.Count -gt 0) { "PASS" } else { "FAIL" }
        Add-Check $CheckScope "Authentication" "MFA enforced for administrators" $status "$($adminMfa.Count) enabled CA policy(ies) require MFA covering all users or Global Administrator" "MFA required for all administrative roles" "8.4.1" "tenant/entra-conditional-access.csv"
    }

    # --- Legacy authentication (cannot do MFA, so it bypasses it)
    $legacyBlock = @($enabledCa | Where-Object {
        ((Get-Items $_.grantControls.builtInControls) -contains "block") -and
        ((Get-Items $_.conditions.users.includeUsers) -contains "All") -and
        (((Get-Items $_.conditions.clientAppTypes) -contains "exchangeActiveSync") -or ((Get-Items $_.conditions.clientAppTypes) -contains "other"))
    })
    if ($secDefaultsOn) {
        Add-Check $CheckScope "Authentication" "Legacy authentication blocked" "PASS" "Security defaults enabled (blocks legacy auth)" "Legacy authentication protocols blocked for all users" "8.4.2" "tenant/entra-security-defaults.json"
    } elseif (-not $caOk) {
        Add-Check $CheckScope "Authentication" "Legacy authentication blocked" "UNKNOWN" "Conditional Access not collected" "Legacy authentication protocols blocked for all users" "8.4.2" "tenant/entra-conditional-access.csv"
    } else {
        $status = if ($legacyBlock.Count -gt 0) { "PASS" } else { "FAIL" }
        Add-Check $CheckScope "Authentication" "Legacy authentication blocked" $status "$($legacyBlock.Count) enabled CA policy(ies) block legacy clients for all users" "Legacy authentication protocols blocked for all users" "8.4.2" "tenant/entra-conditional-access.csv"
    }

    # --- MFA registration
    if (-not ($usersOk -and $mfaRegOk)) {
        Add-Check $CheckScope "Authentication" "Enabled member users without MFA registered" "UNKNOWN" "MFA registration not collected (needs Entra ID P1/P2 + AuditLog.Read.All)" "0" "8.4.2" "tenant/entra-users.csv"
    } else {
        $noMfa = @($enabledMembers | Where-Object { -not ($regById.ContainsKey($_.id) -and $regById[$_.id].isMfaRegistered) })
        $status = if ($noMfa.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-Check $CheckScope "Authentication" "Enabled member users without MFA registered" $status "$($noMfa.Count) of $($enabledMembers.Count)" "0 (shared, room, and service accounts should be disabled for sign-in)" "8.4.2" "tenant/entra-users.csv"
    }

    # --- Privileged users without MFA registered (direct and via groups)
    if (-not ($roleAssignOk -and $mfaRegOk)) {
        Add-Check $CheckScope "Authentication" "Privileged role holders without MFA registered" "UNKNOWN" "Role assignments or MFA registration not collected" "0" "8.4.1" "tenant/entra-role-assignments.csv"
    } else {
        $privUserIds = @()
        $privUserIds += @($privRoleRows | Where-Object { $_.PrincipalType -eq "User" } | ForEach-Object { $_.PrincipalId })
        $privGroupIds = @($privRoleRows | Where-Object { $_.PrincipalType -eq "Group" } | ForEach-Object { $_.PrincipalId })
        $privUserIds += @($groupMemberRows | Where-Object { $privGroupIds -contains $_.GroupId -and $_.MemberType -eq "user" } | ForEach-Object { $_.MemberId })
        $privUserIds  = @($privUserIds | Select-Object -Unique)
        $privNoMfa    = @($privUserIds | Where-Object { -not ($regById.ContainsKey($_) -and $regById[$_].isMfaRegistered) })
        $names        = @($privNoMfa | ForEach-Object { if ($upnById.ContainsKey($_)) { $upnById[$_] } else { $_ } } | Select-Object -First 10) -join ", "
        $status = if ($privNoMfa.Count -eq 0) { "PASS" } else { "FAIL" }
        $cur    = "$($privNoMfa.Count) of $($privUserIds.Count)"
        if ($names) { $cur += ": $names" }
        Add-Check $CheckScope "Authentication" "Privileged role holders without MFA registered" $status $cur "0" "8.4.1" "tenant/entra-role-assignments.csv"
    }

    # --- Inactive accounts
    if (-not $usersOk) {
        Add-Check $CheckScope "Accounts" "Enabled accounts inactive > $InactiveDays days" "UNKNOWN" "Users not collected" "0" "8.2.6" "tenant/entra-users.csv"
    } elseif (-not $signInAvailable) {
        Add-Check $CheckScope "Accounts" "Enabled accounts inactive > $InactiveDays days" "UNKNOWN" "Sign-in activity unavailable (needs Entra ID P1/P2 + AuditLog.Read.All)" "0" "8.2.6" "tenant/entra-users.csv"
    } else {
        $inactiveRows = @($userRows | Where-Object { $_.AccountEnabled -eq $true -and "$($_.Inactive)" -like "Yes*" })
        $inM = @($inactiveRows | Where-Object { $_.UserType -eq "Member" }).Count
        $inG = @($inactiveRows | Where-Object { $_.UserType -eq "Guest" }).Count
        $status = if ($inactiveRows.Count -eq 0) { "PASS" } else { "FAIL" }
        Add-Check $CheckScope "Accounts" "Enabled accounts inactive > $InactiveDays days" $status "$($inactiveRows.Count) ($inM members, $inG guests)" "0 (disable or remove within $InactiveDays days of inactivity)" "8.2.6" "tenant/entra-users.csv"
    }

    if ($usersOk) {
        Add-Check $CheckScope "Accounts" "Enabled guest (external) accounts" "INFO" "$($enabledGuests.Count)" "Each guest has a documented business need and an owner" "8.2.2, 8.2.4" "tenant/entra-users.csv"
    }

    # --- Global Administrators
    if ($roleAssignOk) {
        $gaRows = @($roleRows | Where-Object { $_.Role -eq "Global Administrator" })
        $gaIds  = @($gaRows | ForEach-Object { $_.PrincipalId } | Select-Object -Unique)
        $gaAct  = @($gaRows | Where-Object { $_.State -eq "Active" } | ForEach-Object { $_.PrincipalId } | Select-Object -Unique).Count
        $status = if ($gaIds.Count -le 4) { "PASS" } else { "REVIEW" }
        Add-Check $CheckScope "Privileged access" "Global Administrator assignments" $status "$($gaIds.Count) principal(s), $gaAct active" "Fewer than 5 (Microsoft guidance); least privilege" "7.2.1, 7.2.2" "tenant/entra-role-assignments.csv"

        $privGuests = @($privRoleRows | Where-Object { $_.PrincipalUserType -eq "Guest" })
        $status = if ($privGuests.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-Check $CheckScope "Privileged access" "Privileged directory roles held by guest accounts" $status "$($privGuests.Count)" "0, or documented business need" "7.2.2" "tenant/entra-role-assignments.csv"
    } else {
        Add-Check $CheckScope "Privileged access" "Global Administrator assignments" "UNKNOWN" "Role assignments not collected" "Fewer than 5 (Microsoft guidance); least privilege" "7.2.1, 7.2.2" "tenant/entra-role-assignments.csv"
    }

    # --- Standing (permanent) privileged access
    if ($roleAssignOk -and $pimActiveOk) {
        $standing = @($privRoleRows | Where-Object { $_.State -eq "Active" -and "$($_.ExpiresUtc)" -like "Never*" })
        $status = if ($standing.Count -le 2) { "PASS" } else { "REVIEW" }
        Add-Check $CheckScope "Privileged access" "Permanent active privileged role assignments" $status "$($standing.Count)" "Only break-glass accounts; other admins eligible through PIM (just-in-time)" "7.2.2, 7.2.5" "tenant/entra-role-assignments.csv"
    } else {
        Add-Check $CheckScope "Privileged access" "Permanent active privileged role assignments" "UNKNOWN" "PIM schedules not collected (needs Entra ID P2)" "Only break-glass accounts; other admins eligible through PIM (just-in-time)" "7.2.2, 7.2.5" "tenant/entra-role-assignments.csv"
    }

    if ($pimPoliciesOk -and $pimRows.Count -gt 0) {
        $gaPolicy = @($pimRows | Where-Object { $_.RoleDefinitionId -eq $GlobalAdminTemplateId }) | Select-Object -First 1
        if ($gaPolicy) {
            $ok = $gaPolicy.ActivationRequiresMfa -or $gaPolicy.ActivationAuthContext
            $status = if ($ok) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Privileged access" "PIM: Global Administrator activation requires MFA" $status "MFA: $($gaPolicy.ActivationRequiresMfa); auth context: $($gaPolicy.ActivationAuthContext); approval: $($gaPolicy.ActivationRequiresApproval)" "MFA (or an authentication context) required on activation" "8.4.1" "tenant/entra-pim-role-settings.csv"
        }
    }

    # --- Smart lockout
    if ($dirSettingsOk) {
        $pwdRule = @($dirSettings | Where-Object { $_.templateId -eq "5cf42378-d67d-4f36-ba46-e8b86229381d" }) | Select-Object -First 1
        $threshold = $null; $duration = $null
        foreach ($v in (Get-Items $pwdRule.values)) {
            if ($v.name -eq "LockoutThreshold")         { $threshold = [int]$v.value }
            if ($v.name -eq "LockoutDurationInSeconds") { $duration  = [int]$v.value }
        }
        if ($null -eq $threshold) {
            Add-Check $CheckScope "Authentication" "Account lockout (smart lockout)" "REVIEW" "Not customised: Entra default is 10 failed attempts, 60 s first lockout (duration increases on repeat)" "Lock after no more than 10 attempts for at least 30 minutes, or until identity is confirmed" "8.3.4" "tenant/entra-directory-settings.json"
        } else {
            $status = if ($threshold -le 10 -and $duration -ge 1800) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Authentication" "Account lockout (smart lockout)" $status "Threshold $threshold attempts, duration $duration s" "Lock after no more than 10 attempts for at least 30 minutes, or until identity is confirmed" "8.3.4" "tenant/entra-directory-settings.json"
        }
    }

    # --- Password policy (fixed by Entra ID for cloud accounts)
    Add-Check $CheckScope "Authentication" "Minimum password length (cloud accounts)" "INFO" "Entra ID enforces a fixed 8-character minimum for cloud accounts; not configurable" "12 characters, or 8 where the system does not support 12. Synced accounts follow on-premises AD policy" "8.3.6" "tenant/entra-domains.json"

    if ($domainsOk) {
        $managed = @($domains | Where-Object { $_.authenticationType -eq "Managed" -and $_.isVerified })
        $expiry  = @($managed | ForEach-Object {
            if ($_.passwordValidityPeriodInDays -ge 2147483647 -or $null -eq $_.passwordValidityPeriodInDays) { "$($_.id): never" } else { "$($_.id): $($_.passwordValidityPeriodInDays) days" }
        })
        $neverUsers = @($enabledUsers | Where-Object { "$($_.passwordPolicies)" -match "DisablePasswordExpiration" }).Count
        $cur = (Join-List $expiry)
        if ($usersOk) { $cur += " | $neverUsers enabled user(s) with password-never-expires flag" }
        Add-Check $CheckScope "Authentication" "Password expiry (managed domains)" "INFO" $cur "90 days if a password is the only factor; not required where MFA is enforced for all access" "8.3.9" "tenant/entra-domains.json"
    }

    # --- Application credentials
    if ($appsOk) {
        $activeSecrets = @($credRows | Where-Object { $_.Status -eq "Active" -and $_.CredentialType -eq "Client secret" })
        $longSecrets   = @($activeSecrets | Where-Object { "$($_.LifetimeDays)" -ne "" -and [int]$_.LifetimeDays -gt 365 })
        $expired       = @($credRows | Where-Object { $_.Status -eq "Expired" })
        $status = if ($longSecrets.Count -eq 0) { "PASS" } else { "REVIEW" }
        Add-Check $CheckScope "Application accounts" "App client secrets valid for more than 1 year" $status "$($longSecrets.Count) of $($activeSecrets.Count) active secrets ($($expired.Count) expired credential(s) not yet removed)" "Secrets rotated per the entity's defined frequency; certificates or managed identities preferred" "8.6.3" "tenant/entra-app-credentials.csv"
    }

    # Hand-off to the Azure phase: principal names for RBAC assignments
    $principalRows = foreach ($id in @($principalById.Keys)) {
        $p = $principalById[$id]
        [PSCustomObject]@{ Id = $id; Type = $p.Type; Name = $p.Name; Upn = $p.Upn; UserType = $p.UserType }
    }
    if ($principalRows) {
        $principalRows | Export-Csv -Path (Join-Path $RunDir "_principals.csv") -NoTypeInformation -Encoding UTF8
    }

    if ($Checks.Count -gt 0) {
        $Checks | Export-Csv -Path (Join-Path $RunDir "pci-checks.csv") -NoTypeInformation -Encoding UTF8
    }

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
    exit 0
}

# ==============================================================================
# PHASE: MAIN — module checks, Azure collection, Entra hand-off, manifest
# ==============================================================================

if (-not $PSCommandPath) {
    Write-Host "  Run this script from its .ps1 file (for example .\azure-csp-export.ps1)."
    exit 1
}
if ($TenantId -eq "YOUR_TENANT_ID" -or @($SubscriptionIds) -contains "YOUR_SUBSCRIPTION_ID") {
    Write-Host "  Update the CONFIG block at the top of the script first:"
    Write-Host "    `$TenantId and `$SubscriptionIds (or set `$SubscriptionIds = @() for all subscriptions)."
    exit 1
}
if (-not $CollectEntra -and -not $CollectAzure) {
    Write-Host "  Both `$CollectEntra and `$CollectAzure are `$false -- nothing to collect."
    exit 1
}

# ---------------------------------------------------------------------------
# Module check — Az.Accounts (Azure Resource Manager) and
# Microsoft.Graph.Authentication (Entra ID). Both are installed as part of the
# full Az and Microsoft.Graph modules, so either form is detected.
# ---------------------------------------------------------------------------
function Confirm-Module([string]$Name, [string]$MinVersion) {
    $found = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if ($found -and $found.Version -ge [version]$MinVersion) { return }

    Write-Host ""
    if ($found) { Write-Host "  $Name $($found.Version) is installed; version $MinVersion or later is required." }
    else        { Write-Host "  PowerShell module $Name is not installed." }
    $answer = Read-Host "  Install $Name from PSGallery now? (yes/no)"
    if ($answer -match "^[Yy]") {
        try {
            Write-Host "  Installing $Name ..."
            Install-Module -Name $Name -MinimumVersion $MinVersion -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host "  $Name installed successfully."
        } catch {
            Write-Host "  Install failed: $_"
            Write-Host "  Install manually: Install-Module -Name $Name -Scope CurrentUser"
            exit 1
        }
    } else {
        Write-Host "  Cannot continue without $Name. Exiting."
        exit 1
    }
}

if ($CollectAzure) { Confirm-Module "Az.Accounts" "2.10.0" }
if ($CollectEntra) { Confirm-Module "Microsoft.Graph.Authentication" "2.0.0" }

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
$Date   = Get-Date -Format "yyyyMMdd_HHmmss"
$RunDir = Join-Path $OutputBase "azure-csp-$Date"
New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
$RunDir    = (Get-Item $RunDir).FullName
$TenantDir = Join-Path $RunDir "tenant"
New-Item -ItemType Directory -Path $TenantDir -Force | Out-Null

Write-Host ""
Write-Host "========================================"
Write-Host "  Azure CSP Controls Export (PCI DSS)"
Write-Host "  Tenant  : $TenantId"
Write-Host "  Output  : $RunDir"
Write-Host "========================================"

# ARM request with retry on throttling (429) and transient server errors.
# Collections are followed through every page and emitted item by item.
function Invoke-Arm([string]$Path, [string]$Method = "GET", [int]$MaxItems = 0) {
    $next    = $Path
    $emitted = 0
    while ($next) {
        $resp = $null
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            $resp = Invoke-AzRestMethod -Path $next -Method $Method -ErrorAction Stop
            if ($resp.StatusCode -ne 429 -and $resp.StatusCode -lt 500) { break }
            Start-Sleep -Seconds (5 * $attempt)
        }
        if ($resp.StatusCode -ge 400) {
            $msg = "HTTP $($resp.StatusCode)"
            try {
                $e = ConvertFrom-JsonSafe $resp.Content
                if ($e.error) { $msg = "$($e.error.code): $($e.error.message)" }
            } catch { }
            throw $msg
        }
        $body = ConvertFrom-JsonSafe $resp.Content
        if (-not (Test-Prop $body "value")) { return $body }
        foreach ($v in (Get-Items $body.value)) {
            $v
            $emitted++
            if ($MaxItems -gt 0 -and $emitted -ge $MaxItems) { return }
        }
        $next = Get-Value $body "nextLink"
        if (-not $next) { $next = Get-Value $body "@odata.nextLink" }
        if ($next) { $next = $next -replace '^https?://[^/]+', '' }
    }
}

# Tries API versions in order; moves on only when the version is rejected
function Invoke-ArmVersions([string]$Path, [string[]]$Versions) {
    $lastError = $null
    foreach ($v in $Versions) {
        try {
            $r = @(Invoke-Arm "$Path`?api-version=$v")
            return $r
        } catch {
            $lastError = $_
            if ("$_" -notmatch "InvalidApiVersion|NoRegisteredProviderFound|InvalidResourceType|not supported") { throw }
        }
    }
    throw $lastError
}

# Diagnostic settings: does any setting send at least one log category to a
# destination? Returns a summary object for the CSV.
function Get-DiagSummary($Settings) {
    $logsOn = $false
    $dest   = @()
    $cats   = @()
    foreach ($s in (Get-Items $Settings)) {
        $p = $s.properties
        foreach ($l in (Get-Items $p.logs)) {
            if ($l.enabled) {
                $logsOn = $true
                $cats += if ($l.categoryGroup) { "group:$($l.categoryGroup)" } else { $l.category }
            }
        }
        if ($p.workspaceId)                 { $dest += "Log Analytics: $(Get-NameFromId $p.workspaceId)" }
        if ($p.storageAccountId)            { $dest += "Storage: $(Get-NameFromId $p.storageAccountId)" }
        if ($p.eventHubAuthorizationRuleId) { $dest += "Event Hub: $(($p.eventHubAuthorizationRuleId -split '/')[8])" }
        if ($p.marketplacePartnerId)        { $dest += "Partner: $(Get-NameFromId $p.marketplacePartnerId)" }
    }
    return [PSCustomObject]@{
        Count        = (Get-Items $Settings).Count
        LogsEnabled  = $logsOn
        Destinations = Join-List ($dest | Select-Object -Unique)
        Categories   = Join-List ($cats | Select-Object -Unique)
    }
}

# Resource types whose diagnostic logs matter for PCI DSS Req 10. Storage
# logs live on the blob service sub-resource. Edit this list to add types.
$DiagResourceTypes = @(
    "microsoft.keyvault/vaults",
    "microsoft.network/networksecuritygroups",
    "microsoft.network/azurefirewalls",
    "microsoft.network/applicationgateways",
    "microsoft.network/frontdoors",
    "microsoft.network/bastionhosts",
    "microsoft.network/virtualnetworkgateways",
    "microsoft.cdn/profiles",
    "microsoft.sql/servers/databases",
    "microsoft.sql/managedinstances",
    "microsoft.dbforpostgresql/flexibleservers",
    "microsoft.dbformysql/flexibleservers",
    "microsoft.documentdb/databaseaccounts",
    "microsoft.cache/redis",
    "microsoft.web/sites",
    "microsoft.containerservice/managedclusters",
    "microsoft.containerregistry/registries",
    "microsoft.apimanagement/service",
    "microsoft.recoveryservices/vaults",
    "microsoft.automation/automationaccounts",
    "microsoft.storage/storageaccounts"
)

# Log tables checked against the 12-month retention requirement (if present)
$KeyLogTables = @(
    "AzureActivity", "SigninLogs", "AADNonInteractiveUserSignInLogs", "AuditLogs",
    "AzureDiagnostics", "SecurityEvent", "Syslog", "Event", "CommonSecurityLog",
    "StorageBlobLogs", "AZFWNetworkRule", "AZFWApplicationRule", "AZKVAuditLogs"
)

$SubResults     = New-Object System.Collections.ArrayList
$azureConnected = $false
$aadDiagOk      = $false

# ==============================================================================
# AZURE RESOURCE MANAGER
# ==============================================================================
if ($CollectAzure) {

    $env:SuppressAzurePowerShellBreakingChangeWarnings = "true"
    Import-Module Az.Accounts -ErrorAction Stop
    # Newer Az.Accounts asks interactively which subscription to use; the
    # script selects subscriptions itself
    try { Update-AzConfig -LoginExperienceV2 Off -Scope Process -ErrorAction Stop | Out-Null } catch { }

    Write-Host ""
    Write-Host "[ Connecting to Azure Resource Manager ]"
    Write-Status "Authenticating"
    try {
        $az = @{ Tenant = $TenantId; ErrorAction = "Stop" }
        if (@($SubscriptionIds).Count -gt 0) { $az.SubscriptionId = @($SubscriptionIds)[0] }
        if ($UseServicePrincipal) {
            $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
            $az.ServicePrincipal = $true
            $az.Credential = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
        }
        Connect-AzAccount @az | Out-Null
        $azCtx = Get-AzContext
        Write-Host " OK"
        Write-Host ("  " + "Signed in as:".PadRight(46) + "   $($azCtx.Account.Id)")
        Write-Log "OK" "Azure sign-in" "$($azCtx.Account.Id)"
        $azureConnected = $true
    } catch {
        $msg = Get-ErrorText $_
        Write-Host " FAILED ($msg)"
        Write-Log "FAILED" "Azure sign-in" $msg
    }
}

if ($azureConnected) {

    # -------------------------------------------------------------------------
    # Tenant-level: Entra ID sign-in and audit log export. Entra ID keeps these
    # logs for 30 days at most; 12-month retention (Req 10.5.1) needs a
    # diagnostic setting sending them to Log Analytics, storage, or a SIEM.
    # -------------------------------------------------------------------------
    $OutDir   = $TenantDir
    $LogScope   = "Tenant"
    Write-Host ""
    Write-Host "[ Entra ID log export ]"
    $aadDiag = Export-Data "Entra ID diagnostic settings" "entra-diagnostic-settings.json" {
        Invoke-Arm "/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01"
    }
    $aadDiagOk = $LastExportOk

    # -------------------------------------------------------------------------
    # Subscriptions in scope
    # -------------------------------------------------------------------------
    Write-Host ""
    Write-Host "[ Subscriptions ]"
    $targets = @()
    Write-Status "Listing subscriptions"
    try {
        $allSubs = @(Invoke-Arm "/subscriptions?api-version=2022-12-01")
        if ($TenantId -match '^[0-9a-fA-F-]{36}$') {
            $allSubs = @($allSubs | Where-Object { -not $_.tenantId -or $_.tenantId -eq $TenantId })
        }
        if (@($SubscriptionIds).Count -gt 0) {
            foreach ($id in $SubscriptionIds) {
                $match = @($allSubs | Where-Object { $_.subscriptionId -eq $id })
                if ($match.Count -eq 0) {
                    Write-Log "FAILED" "Subscription $id" "Not visible to this account"
                    Write-Host ""
                    Write-Host "    WARNING: subscription $id is not visible to this account"
                } else {
                    $targets += $match[0]
                }
            }
        } else {
            $targets = @($allSubs | Where-Object { $_.state -eq "Enabled" })
        }
        Write-Host " OK ($($targets.Count) selected of $($allSubs.Count) visible)"
        Write-Log "OK" "Subscriptions" "$($targets.Count) selected"
    } catch {
        $msg = Get-ErrorText $_
        Write-Host " FAILED ($msg)"
        Write-Log "FAILED" "Subscriptions" $msg
    }

    $assessmentMeta = $null
    $rbacGroups     = New-Object System.Collections.ArrayList

    foreach ($sub in $targets) {
        $sid     = $sub.subscriptionId
        $subName = $sub.displayName
        $subSafe = ($subName -replace '[^\w\-]', '-')
        $OutDir  = Join-Path $RunDir ("sub-" + $subSafe + "-" + $sid.Substring(0, 8))
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
        $LogScope = "Sub: $subName"
        $CheckScope = "Subscription: $subName"
        $rel      = Split-Path $OutDir -Leaf
        $base     = "/subscriptions/$sid"

        Write-Host ""
        Write-Host "========================================"
        Write-Host "  Subscription : $subName"
        Write-Host "  ID           : $sid"
        Write-Host "  Folder       : $rel"
        Write-Host "========================================"

        $null = Export-Data "Subscription details" "subscription.json" -Single { $sub }

        # =====================================================================
        # A. RESOURCE INVENTORY — what exists; establishes scope for the rest
        # =====================================================================
        Write-Host ""
        Write-Host "[ Resource inventory ]"
        $resources = @()
        $resources = Export-Rows "Resources" "resources.csv" {
            foreach ($r in @(Invoke-Arm "$base/resources?api-version=2021-04-01")) {
                [PSCustomObject]@{
                    Name          = $r.name
                    Type          = $r.type
                    ResourceGroup = Get-ResourceGroupFromId $r.id
                    Location      = $r.location
                    Kind          = $r.kind
                    Id            = $r.id
                }
            }
        }

        # =====================================================================
        # B. RBAC — who can do what in the subscription (Req 7.2)
        #    Assignments include those inherited from management groups and
        #    those on resource groups and individual resources. Principal
        #    names are added after the Entra ID phase.
        # =====================================================================
        Write-Host ""
        Write-Host "[ Access control (RBAC) ]"
        $armRoleNames = @{}
        $roleDefsArm = Export-Data "Role definitions (custom only saved)" "rbac-custom-roles.json" {
            $all = @(Invoke-Arm "$base/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01")
            $script:armRoleNames = @{}
            foreach ($d in $all) { $script:armRoleNames[$d.name] = $d.properties.roleName }
            $all | Where-Object { $_.properties.type -eq "CustomRole" }
        }
        $assignments = Export-Data "Role assignments" "rbac-role-assignments.json" {
            Invoke-Arm "$base/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
        }
        $assignmentsOk = $LastExportOk
        $eligible = Export-Data "PIM eligible role assignments" "rbac-pim-eligible.json" {
            Invoke-Arm "$base/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01"
        }

        $wildcardRoles = @($roleDefsArm | Where-Object {
            $acts = @(); foreach ($perm in (Get-Items $_.properties.permissions)) { $acts += Get-Items $perm.actions }
            $acts -contains "*"
        })
        if ($wildcardRoles.Count -gt 0 -or $roleDefsArm.Count -gt 0) {
            $status = if ($wildcardRoles.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Access control" "Custom roles granting all actions (*)" $status "$($wildcardRoles.Count) of $($roleDefsArm.Count) custom roles" "0; custom roles grant only required actions" "7.2.2" "$rel/rbac-custom-roles.json"
        }

        # Groups holding privileged roles are expanded by the Entra phase
        foreach ($a in $assignments) {
            $rn = $armRoleNames[(Get-NameFromId $a.properties.roleDefinitionId)]
            if ($a.properties.principalType -eq "Group" -and $PrivilegedAzureRoles -contains $rn) {
                [void]$rbacGroups.Add([PSCustomObject]@{ GroupId = $a.properties.principalId; Access = "Azure RBAC: $rn on $($a.properties.scope)" })
            }
        }
        foreach ($e in $eligible) {
            $rn = $e.properties.expandedProperties.roleDefinition.displayName
            if ($e.properties.principalType -eq "Group" -and $PrivilegedAzureRoles -contains $rn) {
                [void]$rbacGroups.Add([PSCustomObject]@{ GroupId = $e.properties.principalId; Access = "Azure RBAC: $rn (eligible) on $($e.properties.scope)" })
            }
        }

        # =====================================================================
        # C. LOGGING — activity log, diagnostic settings, Log Analytics
        #    retention, SQL auditing (Req 10.2, 10.3, 10.5)
        # =====================================================================
        Write-Host ""
        Write-Host "[ Logging and monitoring ]"

        $actDiag = Export-Data "Activity log export (diagnostic settings)" "activity-log-diagnostic-settings.json" {
            Invoke-Arm "$base/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview"
        }
        if ($LastExportOk) {
            $cats = @()
            foreach ($d in $actDiag) {
                $p = $d.properties
                if ($p.workspaceId -or $p.storageAccountId -or $p.eventHubAuthorizationRuleId -or $p.marketplacePartnerId) {
                    foreach ($l in (Get-Items $p.logs)) {
                        if ($l.enabled) { $cats += if ($l.categoryGroup) { $l.categoryGroup } else { $l.category } }
                    }
                }
            }
            $hasAdmin = ($cats -contains "Administrative") -or ($cats -contains "allLogs")
            $hasSec   = ($cats -contains "Security") -or ($cats -contains "allLogs")
            $status = if ($hasAdmin -and $hasSec) { "PASS" } else { "FAIL" }
            $cur    = if ($actDiag.Count -eq 0) { "No diagnostic setting (activity log kept 90 days only)" } else { "Categories exported: " + (Join-List ($cats | Select-Object -Unique)) }
            Add-Check $CheckScope "Logging" "Activity log exported for retention" $status $cur "Administrative and Security categories sent to Log Analytics, storage, or SIEM" "10.2.1, 10.5.1" "$rel/activity-log-diagnostic-settings.json"
        } else {
            Add-Check $CheckScope "Logging" "Activity log exported for retention" "UNKNOWN" "Not collected" "Administrative and Security categories sent to Log Analytics, storage, or SIEM" "10.2.1, 10.5.1" "$rel/activity-log-diagnostic-settings.json"
        }

        $workspaces = Export-Data "Log Analytics workspaces" "log-analytics-workspaces.json" {
            Invoke-Arm "$base/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01"
        }
        $tableRows = Export-Rows "Log Analytics table retention" "log-analytics-table-retention.csv" {
            foreach ($ws in $workspaces) {
                try {
                    $tables = @(Invoke-Arm "$($ws.id)/tables?api-version=2022-10-01")
                } catch {
                    [PSCustomObject]@{ Workspace = $ws.name; Table = "ERROR"; Plan = ""; InteractiveRetentionDays = ""; TotalRetentionDays = ""; KeySecurityTable = ""; Note = (Get-ErrorText $_) }
                    continue
                }
                foreach ($t in $tables) {
                    [PSCustomObject]@{
                        Workspace                = $ws.name
                        Table                    = $t.name
                        Plan                     = $t.properties.plan
                        InteractiveRetentionDays = $t.properties.retentionInDays
                        TotalRetentionDays       = $t.properties.totalRetentionInDays
                        KeySecurityTable         = if ($KeyLogTables -contains $t.name) { "Yes" } else { "No" }
                        Note                     = ""
                    }
                }
            }
        }
        foreach ($ws in $workspaces) {
            $wsRet  = $ws.properties.retentionInDays
            $keyT   = @($tableRows | Where-Object { $_.Workspace -eq $ws.name -and $_.KeySecurityTable -eq "Yes" })
            if ($keyT.Count -gt 0) {
                $short = @($keyT | Where-Object { [int]$_.InteractiveRetentionDays -lt 90 -or [int]$_.TotalRetentionDays -lt 365 })
                $status = if ($short.Count -eq 0) { "PASS" } else { "FAIL" }
                $cur    = "Workspace default $wsRet days; $($short.Count) of $($keyT.Count) security tables below 90 days interactive / 365 days total"
                if ($short.Count -gt 0) { $cur += ": " + (($short | ForEach-Object { "$($_.Table) ($($_.InteractiveRetentionDays)/$($_.TotalRetentionDays))" }) -join ", ") }
            } else {
                $status = if ($wsRet -ge 365) { "PASS" } elseif ($wsRet -ge 90) { "REVIEW" } else { "FAIL" }
                $cur    = "Workspace default retention $wsRet days (table retention not available)"
            }
            Add-Check $CheckScope "Logging" "Log retention: workspace $($ws.name)" $status $cur "At least 12 months retained, 3 months immediately available" "10.5.1" "$rel/log-analytics-table-retention.csv"
        }

        $diagTargets = @($resources | Where-Object { $DiagResourceTypes -contains "$($_.Type)".ToLower() })
        $diagRows = Export-Rows "Resource diagnostic settings ($($diagTargets.Count) resources)" "resource-diagnostic-settings.csv" {
            foreach ($r in $diagTargets) {
                $target = $r.Id
                if ("$($r.Type)".ToLower() -eq "microsoft.storage/storageaccounts") { $target = "$($r.Id)/blobServices/default" }
                $summary = $null
                $note    = ""
                try {
                    $summary = Get-DiagSummary @(Invoke-Arm "$target/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview")
                } catch {
                    $note = Get-ErrorText $_
                }
                [PSCustomObject]@{
                    ResourceType       = $r.Type
                    ResourceName       = $r.Name
                    ResourceGroup      = $r.ResourceGroup
                    DiagnosticSettings = if ($summary) { $summary.Count } else { "" }
                    LogsEnabled        = if ($summary) { $summary.LogsEnabled } else { "Unknown" }
                    Destinations       = if ($summary) { $summary.Destinations } else { "" }
                    LogCategories      = if ($summary) { $summary.Categories } else { "" }
                    Note               = $note
                    ResourceId         = $r.Id
                }
            }
        }
        if ($diagTargets.Count -gt 0) {
            $noLogs = @($diagRows | Where-Object { $_.LogsEnabled -eq $false })
            $status = if ($noLogs.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Logging" "Security-relevant resources without diagnostic logs" $status "$($noLogs.Count) of $($diagRows.Count)" "All in-scope resources send logs to a central destination" "10.2.1, 10.3.3" "$rel/resource-diagnostic-settings.csv"
        }

        $sqlServers = @($resources | Where-Object { "$($_.Type)".ToLower() -eq "microsoft.sql/servers" })
        if ($sqlServers.Count -gt 0) {
            $sqlRows = Export-Rows "SQL server auditing" "sql-server-auditing.csv" {
                foreach ($srv in $sqlServers) {
                    try {
                        $a = Invoke-Arm "$($srv.Id)/auditingSettings/default?api-version=2021-11-01"
                        [PSCustomObject]@{
                            Server              = $srv.Name
                            ResourceGroup       = $srv.ResourceGroup
                            AuditingState       = $a.properties.state
                            ToLogAnalytics      = $a.properties.isAzureMonitorTargetEnabled
                            StorageEndpoint     = $a.properties.storageEndpoint
                            RetentionDays       = $a.properties.retentionDays
                            AuditActionsAndGroups = Join-List $a.properties.auditActionsAndGroups
                            Note                = ""
                        }
                    } catch {
                        [PSCustomObject]@{ Server = $srv.Name; ResourceGroup = $srv.ResourceGroup; AuditingState = "Unknown"; ToLogAnalytics = ""; StorageEndpoint = ""; RetentionDays = ""; AuditActionsAndGroups = ""; Note = (Get-ErrorText $_) }
                    }
                }
            }
            $off = @($sqlRows | Where-Object { $_.AuditingState -ne "Enabled" })
            $status = if ($off.Count -eq 0) { "PASS" } else { "FAIL" }
            Add-Check $CheckScope "Logging" "SQL servers with auditing disabled" $status "$($off.Count) of $($sqlRows.Count)" "0; server-level auditing enabled on every SQL server" "10.2.1, 10.2.2" "$rel/sql-server-auditing.csv"
        }

        # =====================================================================
        # D. STORAGE — anonymous access, network exposure, encryption in
        #    transit, and blob protection (soft delete, versioning, immutability)
        # =====================================================================
        Write-Host ""
        Write-Host "[ Storage accounts ]"
        $storage = Export-Data "Storage accounts" "storage-accounts.json" {
            Invoke-Arm "$base/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
        }
        $storageOk = $LastExportOk

        $blobSvc = @{}
        $saRows = Export-Rows "Storage account settings" "storage-accounts.csv" {
            foreach ($sa in $storage) {
                $p  = $sa.properties
                $bs = $null
                if ($sa.kind -ne "FileStorage") {
                    try { $bs = Invoke-Arm "$($sa.id)/blobServices/default?api-version=2023-01-01" } catch { }
                }
                $blobSvc[$sa.id] = $bs
                [PSCustomObject]@{
                    Name                  = $sa.name
                    ResourceGroup         = Get-ResourceGroupFromId $sa.id
                    Location              = $sa.location
                    Kind                  = $sa.kind
                    AllowBlobPublicAccess = if ($null -eq $p.allowBlobPublicAccess) { "Not set (allowed)" } else { $p.allowBlobPublicAccess }
                    PublicNetworkAccess   = if ($p.publicNetworkAccess) { $p.publicNetworkAccess } else { "Not set (enabled)" }
                    NetworkDefaultAction  = $p.networkAcls.defaultAction
                    PrivateEndpoints      = (Get-Items $p.privateEndpointConnections).Count
                    HttpsOnly             = $p.supportsHttpsTrafficOnly
                    MinimumTlsVersion     = if ($p.minimumTlsVersion) { $p.minimumTlsVersion } else { "Not set (TLS1_0)" }
                    AllowSharedKeyAccess  = if ($null -eq $p.allowSharedKeyAccess) { "Not set (allowed)" } else { $p.allowSharedKeyAccess }
                    EncryptionKeySource   = $p.encryption.keySource
                    InfrastructureEncryption = [bool]$p.encryption.requireInfrastructureEncryption
                    Key1CreatedUtc        = Format-Date (ConvertTo-UtcDate $p.keyCreationTime.key1)
                    Key2CreatedUtc        = Format-Date (ConvertTo-UtcDate $p.keyCreationTime.key2)
                    KeyExpirationDays     = $p.keyPolicy.keyExpirationPeriodInDays
                    BlobSoftDelete        = if ($bs) { [bool]$bs.properties.deleteRetentionPolicy.enabled } else { "" }
                    BlobSoftDeleteDays    = if ($bs) { $bs.properties.deleteRetentionPolicy.days } else { "" }
                    BlobVersioning        = if ($bs) { [bool]$bs.properties.isVersioningEnabled } else { "" }
                    Id                    = $sa.id
                }
            }
        }

        $containerRows = Export-Rows "Blob containers (public access, immutability)" "storage-containers.csv" {
            foreach ($sa in $storage) {
                if ($sa.kind -eq "FileStorage") { continue }
                $accountAllows = ($sa.properties.allowBlobPublicAccess -ne $false)
                try {
                    $containers = @(Invoke-Arm "$($sa.id)/blobServices/default/containers?api-version=2023-01-01")
                } catch {
                    [PSCustomObject]@{ StorageAccount = $sa.name; Container = "ERROR"; PublicAccess = ""; EffectivelyPublic = ""; ImmutableStorageWithVersioning = ""; HasImmutabilityPolicy = ""; HasLegalHold = ""; LastModifiedUtc = ""; Note = (Get-ErrorText $_) }
                    continue
                }
                foreach ($c in $containers) {
                    $pa = $c.properties.publicAccess
                    [PSCustomObject]@{
                        StorageAccount        = $sa.name
                        Container             = $c.name
                        PublicAccess          = if ($pa) { $pa } else { "None" }
                        # Container-level public access only takes effect if the account allows it
                        EffectivelyPublic     = ($accountAllows -and $pa -and $pa -ne "None")
                        ImmutableStorageWithVersioning = [bool]$c.properties.immutableStorageWithVersioning.enabled
                        HasImmutabilityPolicy = [bool]$c.properties.hasImmutabilityPolicy
                        HasLegalHold          = [bool]$c.properties.hasLegalHold
                        LastModifiedUtc       = Format-Date (ConvertTo-UtcDate $c.properties.lastModifiedTime)
                        Note                  = ""
                    }
                }
            }
        }

        if ($storageOk -and $storage.Count -gt 0) {
            $pubContainers = @($containerRows | Where-Object { $_.EffectivelyPublic -eq $true })
            $status = if ($pubContainers.Count -eq 0) { "PASS" } else { "FAIL" }
            $cur = "$($pubContainers.Count)"
            if ($pubContainers.Count -gt 0) { $cur += ": " + (($pubContainers | Select-Object -First 10 | ForEach-Object { "$($_.StorageAccount)/$($_.Container)" }) -join ", ") }
            Add-Check $CheckScope "Storage" "Blob containers readable anonymously" $status $cur "0" "1.4.4, 7.2.1" "$rel/storage-containers.csv"

            $anonAllowed = @($saRows | Where-Object { $_.AllowBlobPublicAccess -ne $false })
            $status = if ($anonAllowed.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Storage" "Storage accounts permitting anonymous blob access" $status "$($anonAllowed.Count) of $($saRows.Count)" "0 (allowBlobPublicAccess = false)" "1.4.4, 7.2.1" "$rel/storage-accounts.csv"

            $weakTransit = @($saRows | Where-Object { $_.HttpsOnly -ne $true -or @("TLS1_2", "TLS1_3") -notcontains $_.MinimumTlsVersion })
            $status = if ($weakTransit.Count -eq 0) { "PASS" } else { "FAIL" }
            Add-Check $CheckScope "Storage" "Storage accounts allowing HTTP or TLS below 1.2" $status "$($weakTransit.Count) of $($saRows.Count)" "0 (HTTPS only, minimum TLS 1.2)" "4.2.1, 2.2.7" "$rel/storage-accounts.csv"

            $openNet = @($saRows | Where-Object { $_.PublicNetworkAccess -ne "Disabled" -and $_.NetworkDefaultAction -eq "Allow" })
            $status = if ($openNet.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Storage" "Storage accounts reachable from all networks" $status "$($openNet.Count) of $($saRows.Count)" "Public network access disabled or firewall default action Deny for accounts holding in-scope data" "1.3.1, 1.4.1" "$rel/storage-accounts.csv"
        }

        # =====================================================================
        # E. KEY VAULT — protection of cryptographic keys and secrets (Req 3.6)
        # =====================================================================
        Write-Host ""
        Write-Host "[ Key Vault ]"
        $vaults = Export-Data "Key vaults" "key-vaults.json" {
            Invoke-Arm "$base/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        }
        $vaultsOk = $LastExportOk
        $kvRows = Export-Rows "Key vault settings" "key-vaults.csv" {
            foreach ($v in $vaults) {
                $p = $v.properties
                [PSCustomObject]@{
                    Name                 = $v.name
                    ResourceGroup        = Get-ResourceGroupFromId $v.id
                    Location             = $v.location
                    Sku                  = $p.sku.name
                    SoftDelete           = if ($null -eq $p.enableSoftDelete) { "Not set (enabled)" } else { $p.enableSoftDelete }
                    SoftDeleteDays       = $p.softDeleteRetentionInDays
                    PurgeProtection      = [bool]$p.enablePurgeProtection
                    RbacAuthorization    = [bool]$p.enableRbacAuthorization
                    AccessPolicies       = (Get-Items $p.accessPolicies).Count
                    PublicNetworkAccess  = if ($p.publicNetworkAccess) { $p.publicNetworkAccess } else { "Not set (enabled)" }
                    NetworkDefaultAction = if ($p.networkAcls) { $p.networkAcls.defaultAction } else { "Not set (Allow)" }
                    PrivateEndpoints     = (Get-Items $p.privateEndpointConnections).Count
                    Id                   = $v.id
                }
            }
        }
        if ($vaultsOk -and $kvRows.Count -gt 0) {
            $noPurge = @($kvRows | Where-Object { $_.PurgeProtection -ne $true })
            $status = if ($noPurge.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Key management" "Key vaults without purge protection" $status "$($noPurge.Count) of $($kvRows.Count)" "0 for vaults holding keys that protect account data" "3.6.1, 3.7.3" "$rel/key-vaults.csv"

            $openKv = @($kvRows | Where-Object { $_.PublicNetworkAccess -ne "Disabled" -and $_.NetworkDefaultAction -ne "Deny" })
            $status = if ($openKv.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Key management" "Key vaults reachable from all networks" $status "$($openKv.Count) of $($kvRows.Count)" "Public network access disabled or firewall default action Deny" "1.3.1, 3.6.1" "$rel/key-vaults.csv"
        }

        # =====================================================================
        # F. MICROSOFT DEFENDER FOR CLOUD
        #    Plans (threat protection, anti-malware, FIM for servers), security
        #    contacts, secure score, recommendations, and the PCI DSS
        #    regulatory compliance dashboard.
        # =====================================================================
        Write-Host ""
        Write-Host "[ Microsoft Defender for Cloud ]"

        $pricings = Export-Data "Defender plans" "defender-plans.json" {
            Invoke-ArmVersions "$base/providers/Microsoft.Security/pricings" @("2024-01-01", "2023-01-01", "2018-06-01")
        }
        $pricingsOk = $LastExportOk
        $null = Export-Rows "Defender plans summary" "defender-plans.csv" {
            foreach ($p in $pricings) {
                [PSCustomObject]@{
                    Plan           = $p.name
                    Tier           = $p.properties.pricingTier
                    SubPlan        = $p.properties.subPlan
                    EnabledSinceUtc = Format-Date (ConvertTo-UtcDate $p.properties.enablementTime)
                    Deprecated     = [bool]$p.properties.deprecated
                }
            }
        }
        if ($pricingsOk) {
            $servers = @($pricings | Where-Object { $_.name -eq "VirtualMachines" }) | Select-Object -First 1
            $tier    = if ($servers) { "$($servers.properties.pricingTier) $($servers.properties.subPlan)".Trim() } else { "Not listed" }
            $status  = if ($servers -and $servers.properties.pricingTier -eq "Standard") { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Threat protection" "Defender for Servers plan" $status $tier "Standard (Plan 2 adds file integrity monitoring), or equivalent anti-malware and FIM deployed on every VM" "5.2.1, 5.3.1, 11.5.2" "$rel/defender-plans.csv"

            $free = @($pricings | Where-Object { $_.properties.pricingTier -eq "Free" -and -not $_.properties.deprecated } | ForEach-Object { $_.name })
            Add-Check $CheckScope "Threat protection" "Defender plans on the Free tier" "INFO" $(if ($free.Count) { $free -join ", " } else { "None" }) "Plans enabled for every resource type that hosts in-scope workloads" "5.2.1, 10.7.1, 11.5.1" "$rel/defender-plans.csv"
        }

        $contacts = Export-Data "Security contacts" "defender-security-contacts.json" {
            Invoke-ArmVersions "$base/providers/Microsoft.Security/securityContacts" @("2023-12-01-preview", "2020-01-01-preview", "2017-08-01-preview")
        }
        if ($LastExportOk) {
            $emails = @($contacts | ForEach-Object { if ($_.properties.emails) { $_.properties.emails } elseif ($_.properties.email) { $_.properties.email } } | Where-Object { $_ })
            $status = if ($emails.Count -gt 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Incident response" "Defender security alert contact" $status $(if ($emails.Count) { $emails -join "; " } else { "No contact email configured" }) "Alerts routed to the incident response team" "12.10.1, 10.7.1" "$rel/defender-security-contacts.json"
        }

        $null = Export-Data "Secure score" "defender-secure-score.json" {
            Invoke-Arm "$base/providers/Microsoft.Security/secureScores?api-version=2020-01-01"
        }

        if ($null -eq $assessmentMeta) {
            try {
                $assessmentMeta = @{}
                foreach ($m in @(Invoke-Arm "/providers/Microsoft.Security/assessmentMetadata?api-version=2021-06-01")) {
                    $assessmentMeta[$m.name] = $m.properties
                }
            } catch {
                Write-Log "INFO" "Assessment metadata" ("Severity unavailable: " + (Get-ErrorText $_))
            }
        }
        $unhealthy = Export-Data "Recommendations (unhealthy only)" "defender-recommendations.json" {
            Invoke-Arm "$base/providers/Microsoft.Security/assessments?api-version=2021-06-01" |
                Where-Object { $_.properties.status.code -eq "Unhealthy" }
        }
        $unhealthyOk = $LastExportOk
        $recRows = Export-Rows "Recommendations summary" "defender-recommendations.csv" {
            foreach ($a in $unhealthy) {
                $meta  = if ($assessmentMeta -and $assessmentMeta.ContainsKey($a.name)) { $assessmentMeta[$a.name] } else { $null }
                $resId = Get-Value $a.properties.resourceDetails "Id"
                if (-not $resId) { $resId = Get-Value $a.properties.resourceDetails "ResourceId" }
                [PSCustomObject]@{
                    Recommendation = $a.properties.displayName
                    Severity       = if ($meta) { $meta.severity } else { "" }
                    Status         = $a.properties.status.code
                    Cause          = $a.properties.status.cause
                    ResourceName   = Get-NameFromId $resId
                    ResourceGroup  = Get-ResourceGroupFromId $resId
                    ResourceId     = $resId
                }
            }
        }
        if ($unhealthyOk) {
            $high   = @($recRows | Where-Object { $_.Severity -eq "High" })
            $status = if ($high.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Configuration" "Unhealthy Defender recommendations (High severity)" $status "$($high.Count) High of $($recRows.Count) unhealthy" "High-severity findings remediated or risk-ranked" "2.2.1, 6.3.1" "$rel/defender-recommendations.csv"
        }

        $standards = Export-Data "Regulatory compliance standards" "defender-regulatory-standards.json" {
            Invoke-Arm "$base/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview"
        }
        $pciStandards = @($standards | Where-Object { $_.name -match "PCI" })
        $pciControls  = New-Object System.Collections.ArrayList
        if ($pciStandards.Count -gt 0) {
            $ctlRows = Export-Rows "PCI DSS controls (Defender)" "defender-pci-controls.csv" {
                foreach ($std in $pciStandards) {
                    $stdPath = "$base/providers/Microsoft.Security/regulatoryComplianceStandards/" + [uri]::EscapeDataString($std.name)
                    foreach ($ctl in @(Invoke-Arm "$stdPath/regulatoryComplianceControls?api-version=2019-01-01-preview")) {
                        [void]$pciControls.Add([PSCustomObject]@{ Std = $std.name; StdPath = $stdPath; Ctl = $ctl })
                        [PSCustomObject]@{
                            Standard           = $std.name
                            Control            = $ctl.name
                            Description        = $ctl.properties.description
                            State              = $ctl.properties.state
                            PassedAssessments  = $ctl.properties.passedAssessments
                            FailedAssessments  = $ctl.properties.failedAssessments
                            SkippedAssessments = $ctl.properties.skippedAssessments
                        }
                    }
                }
            }
            $null = Export-Rows "PCI DSS failed control assessments" "defender-pci-failed-assessments.csv" {
                foreach ($pc in $pciControls) {
                    if ($pc.Ctl.properties.state -ne "Failed") { continue }
                    $path = "$($pc.StdPath)/regulatoryComplianceControls/" + [uri]::EscapeDataString($pc.Ctl.name) + "/regulatoryComplianceAssessments?api-version=2019-01-01-preview"
                    foreach ($as in @(Invoke-Arm $path)) {
                        if ($as.properties.state -ne "Failed") { continue }
                        [PSCustomObject]@{
                            Standard        = $pc.Std
                            Control         = $pc.Ctl.name
                            Assessment      = $as.properties.description
                            State           = $as.properties.state
                            FailedResources = $as.properties.failedResources
                            PassedResources = $as.properties.passedResources
                            DetailsLink     = $as.properties.assessmentDetailsLink
                        }
                    }
                }
            }
            $stdSummary = ($pciStandards | ForEach-Object { "$($_.name): $($_.properties.state) ($($_.properties.passedControls) passed / $($_.properties.failedControls) failed controls)" }) -join "; "
            Add-Check $CheckScope "Compliance tracking" "PCI DSS standard in Defender regulatory compliance" "INFO" $stdSummary "Optional; automated control results support (do not replace) assessor testing" "12.4.1" "$rel/defender-pci-controls.csv"
        } else {
            Write-Host "  No PCI DSS standard assigned in Defender regulatory compliance"
            Write-Log "INFO" "PCI DSS standard" "Not assigned in Defender regulatory compliance"
            Add-Check $CheckScope "Compliance tracking" "PCI DSS standard in Defender regulatory compliance" "INFO" "Not assigned" "Optional; automated control results support (do not replace) assessor testing" "12.4.1" "$rel/defender-regulatory-standards.json"
        }

        # =====================================================================
        # G. AZURE POLICY — assignments and current non-compliance
        # =====================================================================
        Write-Host ""
        Write-Host "[ Azure Policy ]"
        $polAssign = Export-Data "Policy assignments" "policy-assignments.json" {
            Invoke-Arm "$base/providers/Microsoft.Authorization/policyAssignments?api-version=2022-06-01"
        }
        $polName = @{}
        foreach ($pa in $polAssign) { $polName["$($pa.id)".ToLower()] = if ($pa.properties.displayName) { $pa.properties.displayName } else { $pa.name } }

        $polSummary = Export-Data "Compliance summary" "policy-compliance-summary.json" {
            Invoke-Arm "$base/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01" "POST"
        }
        $polSummaryOk = $LastExportOk
        $null = Export-Rows "Compliance by assignment" "policy-compliance-summary.csv" {
            foreach ($sum in $polSummary) {
                foreach ($pa in (Get-Items $sum.policyAssignments)) {
                    [PSCustomObject]@{
                        Assignment            = $polName["$($pa.policyAssignmentId)".ToLower()]
                        NonCompliantResources = $pa.results.nonCompliantResources
                        NonCompliantPolicies  = $pa.results.nonCompliantPolicies
                        AssignmentId          = $pa.policyAssignmentId
                    }
                }
            }
        }
        $ncLimit = 20000
        $ncRows = Export-Rows "Non-compliant resources (max $ncLimit)" "policy-noncompliant-resources.csv" {
            $path = "$base/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01&`$top=1000&`$filter=" +
                    [uri]::EscapeDataString("complianceState eq 'NonCompliant'")
            foreach ($st in @(Invoke-Arm $path "POST" $ncLimit)) {
                [PSCustomObject]@{
                    Assignment          = $polName["$($st.policyAssignmentId)".ToLower()]
                    PolicyDefinition    = $st.policyDefinitionName
                    PolicyReferenceId   = $st.policyDefinitionReferenceId
                    ResourceType        = $st.resourceType
                    ResourceGroup       = $st.resourceGroup
                    ResourceName        = Get-NameFromId $st.resourceId
                    ComplianceState     = $st.complianceState
                    EvaluatedUtc        = Format-Date (ConvertTo-UtcDate $st.timestamp)
                    ResourceId          = $st.resourceId
                }
            }
        }
        if ($polSummaryOk) {
            $ncRes = 0
            foreach ($sum in $polSummary) { $ncRes = $sum.results.nonCompliantResources }
            $pciAssigned = @($polAssign | Where-Object { "$($_.properties.displayName)" -match "PCI" }).Count
            Add-Check $CheckScope "Compliance tracking" "Azure Policy non-compliant resources" "INFO" "$ncRes non-compliant resource(s); $pciAssigned PCI DSS initiative assignment(s)" "Non-compliance reviewed and remediated or accepted" "2.2.1, 12.4.1" "$rel/policy-compliance-summary.csv"
        }

        [void]$SubResults.Add([PSCustomObject]@{
            Name          = $subName
            Id            = $sid
            Dir           = $OutDir
            Rel           = $rel
            Assignments   = $assignments
            AssignmentsOk = $assignmentsOk
            Eligible      = $eligible
            RoleNames     = $armRoleNames
        })
    }

    if ($rbacGroups.Count -gt 0) {
        $rbacGroups | Export-Csv -Path (Join-Path $RunDir "_rbac-groups.csv") -NoTypeInformation -Encoding UTF8
    }
}

# ==============================================================================
# ENTRA ID — collected in a separate PowerShell process (see .NOTES)
# ==============================================================================
if ($CollectEntra) {
    if ($PSVersionTable.PSEdition -eq "Core") {
        $psExe = Join-Path $PSHOME "pwsh"
        if ($IsWindows) { $psExe += ".exe" }
    } else {
        $psExe = Join-Path $PSHOME "powershell.exe"
    }
    & $psExe -NoProfile -File $PSCommandPath -Phase Entra -RunDir $RunDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "  WARNING: Entra ID collection did not complete (exit code $LASTEXITCODE)."
        Write-Host "  See collection-log.txt in the output folder."
    }
}

# ==============================================================================
# RBAC SUMMARY — needs principal names from the Entra ID phase
# ==============================================================================
$principals = @{}
$principalFile = Join-Path $RunDir "_principals.csv"
$haveLookup = Test-Path $principalFile
if ($haveLookup) {
    foreach ($p in (Import-Csv $principalFile)) { $principals[$p.Id] = $p }
}

if ($azureConnected) {
    $OutDir   = $TenantDir
    $LogScope   = "Tenant"
    if ($aadDiagOk) {
        $sentCats = @()
        foreach ($d in $aadDiag) {
            $p = $d.properties
            if ($p.workspaceId -or $p.storageAccountId -or $p.eventHubAuthorizationRuleId -or $p.marketplacePartnerId) {
                foreach ($l in (Get-Items $p.logs)) { if ($l.enabled) { $sentCats += $l.category } }
            }
        }
        $ok = ($sentCats -contains "SignInLogs") -and ($sentCats -contains "AuditLogs")
        $status = if ($ok) { "PASS" } else { "FAIL" }
        $cur    = if ($aadDiag.Count -eq 0) { "No diagnostic setting (Entra ID keeps sign-in and audit logs 30 days at most)" } else { "Categories exported: " + (Join-List ($sentCats | Select-Object -Unique)) }
        Add-Check "Tenant" "Logging" "Entra ID sign-in and audit logs exported" $status $cur "SignInLogs and AuditLogs sent to Log Analytics, storage, or SIEM" "10.2.1, 10.5.1" "tenant/entra-diagnostic-settings.json"
    } else {
        Add-Check "Tenant" "Logging" "Entra ID sign-in and audit logs exported" "UNKNOWN" "Not collected (needs Security Reader or Global Reader directory role)" "SignInLogs and AuditLogs sent to Log Analytics, storage, or SIEM" "10.2.1, 10.5.1" "tenant/entra-diagnostic-settings.json"
    }
}

foreach ($sr in $SubResults) {
    $OutDir   = $sr.Dir
    $LogScope = "Sub: $($sr.Name)"
    $CheckScope = "Subscription: $($sr.Name)"

    Write-Host ""
    Write-Host "[ RBAC summary: $($sr.Name) ]"
    $rbacRows = Export-Rows "Role assignments (active + eligible)" "rbac-role-assignments.csv" {
        foreach ($a in $sr.Assignments) {
            $p  = $a.properties
            $rn = $sr.RoleNames[(Get-NameFromId $p.roleDefinitionId)]
            $pr = if ($principals.ContainsKey("$($p.principalId)")) { $principals["$($p.principalId)"] } else { $null }
            [PSCustomObject]@{
                Role              = $rn
                Privileged        = if ($PrivilegedAzureRoles -contains $rn) { "Yes" } else { "No" }
                State             = "Active"
                ScopeLevel        = Get-ScopeLevel $p.scope
                Scope             = $p.scope
                PrincipalType     = $p.principalType
                PrincipalName     = if ($pr) { $pr.Name } elseif ($haveLookup) { "(not found in directory - deleted?)" } else { "(Entra ID not collected)" }
                PrincipalUPN      = if ($pr) { $pr.Upn } else { "" }
                PrincipalUserType = if ($pr) { $pr.UserType } else { "" }
                EndUtc            = ""
                Condition         = $p.condition
                CreatedUtc        = Format-Date (ConvertTo-UtcDate $p.createdOn)
                PrincipalId       = $p.principalId
            }
        }
        foreach ($e in $sr.Eligible) {
            $p  = $e.properties
            $x  = $p.expandedProperties
            $rn = if ($x.roleDefinition.displayName) { $x.roleDefinition.displayName } else { $sr.RoleNames[(Get-NameFromId $p.roleDefinitionId)] }
            $pr = if ($principals.ContainsKey("$($p.principalId)")) { $principals["$($p.principalId)"] } else { $null }
            [PSCustomObject]@{
                Role              = $rn
                Privileged        = if ($PrivilegedAzureRoles -contains $rn) { "Yes" } else { "No" }
                State             = "Eligible"
                ScopeLevel        = Get-ScopeLevel $p.scope
                Scope             = $p.scope
                PrincipalType     = $p.principalType
                PrincipalName     = if ($pr) { $pr.Name } else { $x.principal.displayName }
                PrincipalUPN      = if ($pr) { $pr.Upn } else { $x.principal.email }
                PrincipalUserType = if ($pr) { $pr.UserType } else { "" }
                EndUtc            = if ($p.endDateTime) { Format-Date (ConvertTo-UtcDate $p.endDateTime) } else { "Never (permanent)" }
                Condition         = $p.condition
                CreatedUtc        = Format-Date (ConvertTo-UtcDate $p.createdOn)
                PrincipalId       = $p.principalId
            }
        }
    }

    if ($sr.AssignmentsOk) {
        $subLevel = @("Root", "Management group", "Subscription")
        $owners   = @($rbacRows | Where-Object { $_.Role -eq "Owner" -and $_.State -eq "Active" -and $subLevel -contains $_.ScopeLevel })
        $ownerIds = @($owners | ForEach-Object { $_.PrincipalId } | Select-Object -Unique)
        $names    = @($owners | ForEach-Object { if ($_.PrincipalUPN) { $_.PrincipalUPN } else { $_.PrincipalName } } | Select-Object -Unique -First 10) -join ", "
        $status   = if ($ownerIds.Count -le 3) { "PASS" } else { "REVIEW" }
        Add-Check $CheckScope "Access control" "Owners at subscription scope or above" $status "$($ownerIds.Count): $names" "No more than 3 (Microsoft guidance); least privilege" "7.2.1, 7.2.2" "$($sr.Rel)/rbac-role-assignments.csv"

        if ($haveLookup) {
            $privGuests = @($rbacRows | Where-Object { $_.Privileged -eq "Yes" -and $_.PrincipalUserType -eq "Guest" })
            $status = if ($privGuests.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Access control" "Privileged Azure roles held by guest accounts" $status "$($privGuests.Count)" "0, or documented business need" "7.2.2" "$($sr.Rel)/rbac-role-assignments.csv"

            $orphans = @($rbacRows | Where-Object { $_.State -eq "Active" -and "$($_.PrincipalName)" -like "(not found*" })
            $status = if ($orphans.Count -eq 0) { "PASS" } else { "REVIEW" }
            Add-Check $CheckScope "Access control" "Role assignments to deleted principals" $status "$($orphans.Count)" "0; remove assignments for identities that no longer exist" "7.2.4, 8.2.6" "$($sr.Rel)/rbac-role-assignments.csv"
        }
    } else {
        Add-Check $CheckScope "Access control" "Owners at subscription scope or above" "UNKNOWN" "Role assignments not collected" "No more than 3 (Microsoft guidance); least privilege" "7.2.1, 7.2.2" "$($sr.Rel)/rbac-role-assignments.csv"
    }
}

# Hand-off files are working data, not evidence
Remove-Item (Join-Path $RunDir "_principals.csv")  -ErrorAction SilentlyContinue
Remove-Item (Join-Path $RunDir "_rbac-groups.csv") -ErrorAction SilentlyContinue

# ==============================================================================
# SCORECARD — Entra ID rows were written by the Entra phase; append the rest
# ==============================================================================
$checksPath = Join-Path $RunDir "pci-checks.csv"
$ordered = @($Checks | Where-Object { $_.Scope -eq "Tenant" })
foreach ($sr in $SubResults) { $ordered += @($Checks | Where-Object { $_.Scope -eq "Subscription: $($sr.Name)" }) }
if ($ordered.Count -gt 0) {
    $ordered | Export-Csv -Path $checksPath -NoTypeInformation -Encoding UTF8 -Append
}

# ==============================================================================
# MANIFEST + SHA-256 INTEGRITY HASHES
# Every exported file (in every subfolder) is hashed with SHA-256 and recorded
# in MANIFEST.txt for chain-of-custody, plus checksums.sha256 for independent
# verification. Paths use forward slashes so sha256sum -c works unchanged.
# ==============================================================================
Write-Host ""
Write-Host -NoNewline "  Hashing evidence (SHA-256) + manifest...".PadRight(52)

$manifestPath = Join-Path $RunDir "MANIFEST.txt"
$checksumPath = Join-Path $RunDir "checksums.sha256"
$files        = Get-ChildItem $RunDir -File -Recurse |
                    Where-Object { $_.FullName -ne $manifestPath -and $_.FullName -ne $checksumPath } |
                    Sort-Object FullName

$hashes = foreach ($f in $files) {
    $h   = Get-FileHash -Path $f.FullName -Algorithm SHA256
    $rp  = $f.FullName.Substring($RunDir.Length).TrimStart('\', '/') -replace '\\', '/'
    [PSCustomObject]@{ Name = $rp; SizeKB = [math]::Round($f.Length / 1KB, 1); SHA256 = $h.Hash }
}

# One "<hash> *<file>" line per file — the format understood by sha256sum -c
$hashes | ForEach-Object { "{0} *{1}" -f $_.SHA256, $_.Name } |
    Out-File -FilePath $checksumPath -Encoding ASCII

$subList = if ($SubResults.Count -gt 0) { ($SubResults | ForEach-Object { "$($_.Name) ($($_.Id))" }) } else { @("(none)") }
$manifestLines = @(
    "Azure CSP Controls Export Manifest (PCI DSS)"
    "============================================"
    "Tenant ID      : $TenantId"
    "Subscriptions  : $($subList[0])"
)
foreach ($extra in @($subList | Select-Object -Skip 1)) { $manifestLines += "                 $extra" }
$manifestLines += @(
    "Exported       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Hashed (UTC)   : $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC"
    "Host           : $([Environment]::MachineName)"
    "User           : $([Environment]::UserName)"
    "Auth mode      : $(if ($UseServicePrincipal) { "Service principal $ClientId" } else { 'Interactive sign-in' })"
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

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$allChecks = @()
if (Test-Path $checksPath) { $allChecks = @(Import-Csv $checksPath) }
$failed    = @(Get-Content (Join-Path $RunDir "collection-log.txt") -ErrorAction SilentlyContinue | Where-Object { $_ -match '\sFAILED\s' })

Write-Host "========================================"
Write-Host "  Export complete."
Write-Host "  Files saved to: $RunDir"
Write-Host ""
Write-Host ("  Scorecard: {0} PASS, {1} FAIL, {2} REVIEW, {3} INFO, {4} UNKNOWN" -f `
    @($allChecks | Where-Object { $_.Status -eq "PASS" }).Count,
    @($allChecks | Where-Object { $_.Status -eq "FAIL" }).Count,
    @($allChecks | Where-Object { $_.Status -eq "REVIEW" }).Count,
    @($allChecks | Where-Object { $_.Status -eq "INFO" }).Count,
    @($allChecks | Where-Object { $_.Status -eq "UNKNOWN" }).Count)
foreach ($c in @($allChecks | Where-Object { $_.Status -eq "FAIL" })) {
    Write-Host "    FAIL  [$($c.Scope)] $($c.Check)"
}
if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "  $($failed.Count) item(s) could not be collected -- see collection-log.txt"
}
Write-Host ""
Write-Host "  MANIFEST.txt records a SHA-256 hash of every file."
Write-Host "  checksums.sha256 can be verified with: sha256sum -c checksums.sha256"
Write-Host ""
Write-Host "  For assessor review:"
Write-Host "  - pci-checks.csv                     -- scorecard; read this first"
Write-Host "  - tenant/entra-users.csv             -- MFA, last sign-in, password age per user"
Write-Host "  - tenant/entra-role-assignments.csv  -- directory admins (active + PIM eligible)"
Write-Host "  - tenant/entra-conditional-access.csv -- how MFA is enforced"
Write-Host "  - sub-*/rbac-role-assignments.csv    -- who can change each subscription"
Write-Host "  - sub-*/defender-pci-controls.csv    -- Defender PCI DSS control results"
Write-Host "  - collection-log.txt                 -- every item collected or failed"
Write-Host "========================================"
