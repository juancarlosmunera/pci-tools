<#
.SYNOPSIS
    Export Azure network security configuration for PCI DSS assessment.

.DESCRIPTION
    Connects to Azure using the Az PowerShell module and exports:
      - Network Security Group rules (inbound and outbound, sorted by priority,
        with source, destination, protocol, port, and allow/deny action)
      - NSG-to-subnet and NSG-to-NIC associations (embedded in NSG export)
      - Virtual Network topology and subnet definitions
      - Application Security Groups
      - Azure Firewall instances, policies, and rule collection groups (if deployed)

    All output is saved to a timestamped folder as JSON files readable in
    VS Code or Notepad++ on Windows. No changes are made to Azure.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.NOTES
    Requires Az.Network and Az.Accounts PowerShell modules.
    The script will offer to install these automatically if not found.
    See azure-network-export_powershell_readme.txt for full setup instructions.
#>

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================
$TenantId       = "YOUR_TENANT_ID"          # Azure AD Tenant ID (GUID)
$SubscriptionId = "YOUR_SUBSCRIPTION_ID"    # Azure Subscription ID (GUID)

# Service Principal credentials — for non-interactive / scripted use.
# Leave both as "" to use interactive browser login instead.
$ClientId       = ""                         # App Registration Application (client) ID
$ClientSecret   = ""                         # App Registration client secret

$OutputBase     = "C:\azure-export"
# ==============================================================================

# ---------------------------------------------------------------------------
# Az module check — supports modular (Az.Network) and monolithic (Az)
# ---------------------------------------------------------------------------
$azFlavor = $null

if     (Get-Module -ListAvailable -Name "Az.Network")  { $azFlavor = "modular" }
elseif (Get-Module -ListAvailable -Name "Az")           { $azFlavor = "monolithic" }

if (-not $azFlavor) {
    Write-Host ""
    Write-Host "  Az PowerShell module is not installed."
    Write-Host "  Required: Az.Accounts and Az.Network"
    Write-Host ""
    $answer = Read-Host "  Install from PSGallery now? (yes/no)"
    if ($answer -match "^[Yy]") {
        try {
            Write-Host "  Installing Az.Accounts ..."
            Install-Module -Name Az.Accounts -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "  Installing Az.Network ..."
            Install-Module -Name Az.Network  -Scope CurrentUser -Force -ErrorAction Stop
            Write-Host "  Modules installed successfully."
            $azFlavor = "modular"
        } catch {
            Write-Error "  Install failed: $_"
            Write-Host "  Install manually: Install-Module -Name Az.Network -Scope CurrentUser"
            exit 1
        }
    } else {
        Write-Host "  Cannot continue without the Az module. Exiting."
        exit 1
    }
}

switch ($azFlavor) {
    "modular" {
        Import-Module Az.Accounts -ErrorAction Stop
        Import-Module Az.Network  -ErrorAction Stop
    }
    "monolithic" {
        Import-Module Az -ErrorAction Stop
    }
}

# ---------------------------------------------------------------------------
# Connect to Azure
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[ Connecting to Azure ]"
Write-Host -NoNewline ("  " + "Authenticating...".PadRight(40) + "...")

try {
    if ($ClientId -and $ClientSecret) {
        # Service Principal login — non-interactive
        $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $spCred       = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
        Connect-AzAccount -ServicePrincipal -Credential $spCred `
            -Tenant $TenantId -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    } else {
        # Interactive login — opens browser (PS 7) or device code prompt (PS 5.1)
        Connect-AzAccount -Tenant $TenantId -SubscriptionId $SubscriptionId `
            -ErrorAction Stop | Out-Null
    }
    Write-Host " OK"
} catch {
    Write-Host " FAILED ($_)"
    exit 1
}

# Set subscription context and retrieve display info
Write-Host -NoNewline ("  " + "Setting subscription context...".PadRight(40) + "...")
try {
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    $context     = Get-AzContext
    $SubName     = $context.Subscription.Name
    $SubId       = $context.Subscription.Id
    $TenantName  = $context.Tenant.Id
    Write-Host " OK"
    Write-Host ("  " + "Subscription:".PadRight(40) + "  $SubName")
    Write-Host ("  " + "Subscription ID:".PadRight(40) + "  $SubId")
} catch {
    Write-Host " FAILED ($_)"
    exit 1
}

# ---------------------------------------------------------------------------
# Setup — export directory named after the subscription
# ---------------------------------------------------------------------------
$Date      = Get-Date -Format "yyyyMMdd_HHmmss"
$SubSafe   = $SubName -replace '[^\w\-]', '-'
$ExportDir = Join-Path $OutputBase "azure-$SubSafe-$Date"

New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null

Write-Host ""
Write-Host "========================================"
Write-Host "  Azure Network Security Export"
Write-Host "  Subscription : $SubName"
Write-Host "  Output       : $ExportDir"
Write-Host "========================================"

# ---------------------------------------------------------------------------
# Helper: run a scriptblock, serialize result to JSON, save to file
# ---------------------------------------------------------------------------
function Export-AzureResource {
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
# 1. VIRTUAL NETWORK INFRASTRUCTURE
#    VNets (with embedded subnets and peerings), route tables, and gateways.
#    Establishes the network topology for the PCI assessor.
# ==============================================================================
Write-Host ""
Write-Host "[ Virtual network infrastructure ]"

Export-AzureResource "Virtual networks (VNets)" "vnets.json" {
    # Returns VNets with subnets, peerings, and NSG/RouteTable associations embedded
    Get-AzVirtualNetwork
}

Export-AzureResource "Route tables" "route-tables.json" {
    Get-AzRouteTable
}

Export-AzureResource "Virtual network gateways" "vnet-gateways.json" {
    Get-AzVirtualNetworkGateway -ResourceGroupName (Get-AzResourceGroup | Select-Object -ExpandProperty ResourceGroupName) `
        -ErrorAction SilentlyContinue
}

Export-AzureResource "VPN / ExpressRoute connections" "vnet-connections.json" {
    Get-AzVirtualNetworkGatewayConnection -ResourceGroupName (Get-AzResourceGroup | Select-Object -ExpandProperty ResourceGroupName) `
        -ErrorAction SilentlyContinue
}

# ==============================================================================
# 2. NETWORK ACCESS CONTROLS
#    NSGs are the primary per-subnet and per-NIC traffic control in Azure.
#    Rules are sorted by direction then priority so the assessor sees them
#    in the exact order Azure evaluates them (lowest priority number wins).
# ==============================================================================
Write-Host ""
Write-Host "[ Network access controls ]"

Export-AzureResource "Network Security Groups (NSGs)" "network-security-groups.json" {
    $nsgs = Get-AzNetworkSecurityGroup
    foreach ($nsg in $nsgs) {
        # Sort custom rules by direction (Inbound first) then priority
        $nsg.SecurityRules = @(
            $nsg.SecurityRules | Sort-Object Direction, Priority
        )
        # Sort default rules the same way (these are Azure's built-in rules)
        $nsg.DefaultSecurityRules = @(
            $nsg.DefaultSecurityRules | Sort-Object Direction, Priority
        )
    }
    $nsgs
}

# ==============================================================================
# 3. APPLICATION SECURITY GROUPS
#    ASGs are logical groupings of VMs used as source/destination in NSG rules.
#    Exporting them lets the assessor resolve what each ASG reference covers.
# ==============================================================================
Write-Host ""
Write-Host "[ Application Security Groups ]"

Export-AzureResource "Application Security Groups (ASGs)" "application-security-groups.json" {
    Get-AzApplicationSecurityGroup
}

# ==============================================================================
# 4. AZURE FIREWALL (if deployed)
#    Exports firewall instances, all linked policies, and each policy's full
#    rule collection groups (application, network, and DNAT rules).
#    Handles both Classic rule mode and Firewall Policy mode.
#    Skipped gracefully if not deployed.
# ==============================================================================
Write-Host ""
Write-Host "[ Azure Firewall ]"

$firewallList = @()
try {
    $firewallList = @(Get-AzFirewall -ErrorAction Stop)
} catch {
    Write-Host ("  " + "Firewall check...".PadRight(40) + "... FAILED ($_)")
}

if ($firewallList.Count -eq 0) {
    Write-Host "  No Azure Firewall instances found in this subscription"
    # Write a marker file so the assessor knows this was checked
    @{ checked = $true; found = $false; subscription = $SubName } |
        ConvertTo-Json | Out-File -FilePath (Join-Path $ExportDir "azfw-not-deployed.json") -Encoding UTF8
} else {
    Write-Host "  $($firewallList.Count) firewall instance(s) found"

    # Firewall instances — includes Classic rules inline (ApplicationRuleCollections,
    # NetworkRuleCollections, NatRuleCollections) when not using Firewall Policy
    Export-AzureResource "Firewall instances" "azfw-firewalls.json" {
        $firewallList
    }

    # Firewall Policies — newer deployment model with rule collection groups
    Export-AzureResource "Firewall policies" "azfw-policies.json" {
        Get-AzFirewallPolicy
    }

    # Rule Collection Groups — the actual rules inside each policy.
    # Iterates every policy and collects all rule collection groups with their
    # application, network, and DNAT rule content.
    Export-AzureResource "Policy rule collection groups" "azfw-rule-collections.json" {
        $allGroups  = @()
        $allPolicies = @(Get-AzFirewallPolicy)
        foreach ($policy in $allPolicies) {
            $rg = $policy.ResourceGroupName
            if (-not $rg) {
                # Parse resource group from the policy resource ID
                $rg = ($policy.Id -split '/')[4]
            }
            $groups = @(Get-AzFirewallPolicyRuleCollectionGroup `
                -FirewallPolicyName $policy.Name `
                -ResourceGroupName  $rg `
                -ErrorAction SilentlyContinue)
            foreach ($group in $groups) {
                # Tag each group with its parent policy name for easy cross-reference
                $group | Add-Member -NotePropertyName "ParentPolicyName" `
                                    -NotePropertyValue $policy.Name -Force
            }
            $allGroups += $groups
        }
        $allGroups
    }
}

# ==============================================================================
# 5. MANIFEST
# ==============================================================================
Write-Host ""

$manifestPath = Join-Path $ExportDir "MANIFEST.txt"
$files        = Get-ChildItem $ExportDir |
                    Where-Object { $_.Name -ne "MANIFEST.txt" } |
                    Sort-Object Name

$manifestLines = @(
    "Azure Network Security Export Manifest"
    "Subscription : $SubName"
    "Sub ID       : $SubId"
    "Tenant ID    : $TenantName"
    "Exported     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "Host         : $env:COMPUTERNAME"
    "User         : $env:USERNAME"
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
Write-Host "  - Open .json files in VS Code or Notepad++"
Write-Host "    (VS Code: Ctrl+Shift+P > Format Document for JSON pretty-print)"
Write-Host "  - network-security-groups.json -- NSG rules sorted by priority"
Write-Host "    Look at SecurityRules (custom) and DefaultSecurityRules (built-in)"
Write-Host "    NSG-to-subnet and NSG-to-NIC associations are in Subnets / NetworkInterfaces"
Write-Host "  - vnets.json -- VNet/subnet topology with NSG + route table associations"
Write-Host "  - azfw-*.json -- Azure Firewall rules (if deployed)"
Write-Host "========================================"
