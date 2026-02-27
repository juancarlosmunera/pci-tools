================================================================================
  azure-network-export.ps1  —  README
  Azure Network Security Configuration Export (PowerShell)
  Audience: Azure Administrator / Sysadmin
================================================================================

PURPOSE
-------
This script connects to Azure using the Az PowerShell module and exports
network security configuration for review by a PCI DSS assessor. It is
read-only and makes no changes to your Azure environment.

What is exported:

  Network Security Groups     All NSG rules (custom and Azure default rules),
  (NSGs)                      inbound and outbound, sorted in the order Azure
                              evaluates them (lowest priority number first).
                              Each rule includes: priority, direction, action
                              (Allow/Deny), protocol, source address prefix,
                              destination address prefix, source port range,
                              and destination port range.

  NSG Associations            Each NSG export includes the list of subnets and
                              network interfaces the NSG is attached to —
                              embedded in the same NSG JSON entry.

  Virtual Network topology    VNet definitions (address space, subnets, subnet
                              CIDR blocks, subnet NSG and route table links),
                              VNet peerings, and route tables with routes.

  Application Security        ASG definitions — logical VM groupings used as
  Groups (ASGs)               source or destination in NSG rules. Export allows
                              the assessor to resolve what each ASG reference
                              covers.

  Azure Firewall              Firewall instances (Classic rules inline),
  (if deployed)               Firewall Policies, and all Policy Rule Collection
                              Groups (application rules, network rules, DNAT
                              rules) with full rule content.


REQUIREMENTS
------------
  - Windows PowerShell 5.1 (built into Windows 10/11 and Server 2016+)
    OR PowerShell 7+ (recommended)

  - Az PowerShell module — the script will offer to install automatically
    if not found. Modules installed:
      Az.Accounts     (authentication and subscription context)
      Az.Network      (NSGs, VNets, ASGs, Azure Firewall, route tables)

  - Azure credentials with read-only access. See "RBAC PERMISSIONS REQUIRED".

  - Network access to Azure (internet or ExpressRoute to Azure endpoints).


BEFORE YOU RUN — EDIT THESE SETTINGS IN THE SCRIPT
---------------------------------------------------
Open azure-network-export.ps1 in Notepad or VS Code and update the following
lines near the top of the file:

    $TenantId       = "YOUR_TENANT_ID"          <-- Your Azure AD Tenant ID
    $SubscriptionId = "YOUR_SUBSCRIPTION_ID"    <-- The subscription to export

    $ClientId       = ""                         <-- App Registration client ID
    $ClientSecret   = ""                         <-- App Registration secret
                                                     Leave both as "" for
                                                     interactive browser login

    $OutputBase     = "C:\azure-export"          <-- Output folder (auto-created)

FINDING YOUR TENANT ID AND SUBSCRIPTION ID:
  Azure Portal > Azure Active Directory > Overview
    Tenant ID is shown on this page as "Tenant ID"

  Azure Portal > Subscriptions
    Click your subscription — Subscription ID is shown on the Overview page

  From PowerShell (if already logged in):
    Get-AzContext | Select-Object -ExpandProperty Subscription


TWO WAYS TO AUTHENTICATE
------------------------
The script supports two authentication modes. Choose based on your setup:

  OPTION A — Interactive login (simpler, recommended for one-time use):
    Leave $ClientId and $ClientSecret as "".
    When you run the script, a browser window opens for you to sign in
    with your Azure AD credentials (same as logging into the Azure Portal).
    On Windows PowerShell 5.1 without a browser, a device code is shown
    instead — copy it to https://microsoft.com/devicelogin.

  OPTION B — Service Principal (for automated / non-interactive use):
    Create an App Registration, generate a secret, and paste the values
    into $ClientId and $ClientSecret in the script.
    See "CREATING A SERVICE PRINCIPAL" below.


RBAC PERMISSIONS REQUIRED
--------------------------
The account or service principal needs read-only access to network resources.
Attach either of these at the Subscription scope:

  Built-in roles (easiest):
    "Reader"                   Read all resources in the subscription
    OR
    "Network Contributor"      Read/write network — use Reader instead as
                               it is strictly read-only

  Minimum required actions (custom role if you need least privilege):
    Microsoft.Network/virtualNetworks/read
    Microsoft.Network/virtualNetworks/subnets/read
    Microsoft.Network/networkSecurityGroups/read
    Microsoft.Network/networkSecurityGroups/securityRules/read
    Microsoft.Network/applicationSecurityGroups/read
    Microsoft.Network/routeTables/read
    Microsoft.Network/routeTables/routes/read
    Microsoft.Network/azureFirewalls/read
    Microsoft.Network/firewallPolicies/read
    Microsoft.Network/firewallPolicies/ruleCollectionGroups/read
    Microsoft.Network/virtualNetworkGateways/read
    Microsoft.Network/connections/read

  Assign in Azure Portal:
    Subscriptions > your subscription > Access Control (IAM) >
    Add role assignment > Reader > select the user or service principal


CREATING A SERVICE PRINCIPAL (OPTIONAL)
-----------------------------------------
Only needed for Option B (non-interactive login).

  Step 1 — Create an App Registration:
    Azure Portal > Azure Active Directory > App registrations > New registration
    Name: pci-readonly-export (or any descriptive name)
    Supported account types: Accounts in this organizational directory only
    Click Register

  Step 2 — Create a client secret:
    In the App Registration > Certificates & secrets > New client secret
    Description: pci-assessment
    Expires: set appropriate expiry (delete after assessment is done)
    Click Add — copy the VALUE immediately (shown only once)

  Step 3 — Note the IDs:
    From the App Registration overview page:
      Application (client) ID → paste into $ClientId
      Directory (tenant) ID  → paste into $TenantId
    The client secret value  → paste into $ClientSecret

  Step 4 — Assign Reader role:
    Subscriptions > your subscription > Access Control (IAM) >
    Add role assignment > Reader >
    Search for the App Registration name > Assign

  Step 5 — Clean up after the assessment:
    Azure AD > App registrations > pci-readonly-export >
    Certificates & secrets > delete the client secret
    (or delete the entire App Registration)


RUNNING THE SCRIPT
------------------
  1. Open PowerShell (search "PowerShell" in the Start menu)

  2. If execution policy blocks scripts:
       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  3. Navigate to the script folder:
       cd "C:\path\to\script"

  4. Run:
       .\azure-network-export.ps1

  5. If Az modules are not installed, the script prompts:
       "Install from PSGallery now? (yes/no)"
     Type "yes" — requires internet access, takes 1-3 minutes, one-time only.

  6. If using interactive login (Option A), a browser window opens. Sign in
     with your Azure credentials and close the browser when prompted.

  7. A successful run looks like:

       [ Connecting to Azure ]
         Authenticating...                          OK
         Setting subscription context...            OK
         Subscription:                              Contoso Production

       ========================================
         Azure Network Security Export
         Subscription : Contoso-Production
         Output       : C:\azure-export\azure-Contoso-Production-20260225_143012
       ========================================

       [ Virtual network infrastructure ]
         Virtual networks (VNets)                   OK (4 items, 38.2 KB)
         Route tables                               OK (6 items, 14.7 KB)
         Virtual network gateways                   OK (1 items, 8.4 KB)
         VPN / ExpressRoute connections             OK (2 items, 12.1 KB)

       [ Network access controls ]
         Network Security Groups (NSGs)             OK (18 items, 124.6 KB)

       [ Application Security Groups ]
         Application Security Groups (ASGs)         OK (7 items, 9.3 KB)

       [ Azure Firewall ]
         1 firewall instance(s) found
         Firewall instances                         OK (1 items, 45.2 KB)
         Firewall policies                          OK (2 items, 18.7 KB)
         Policy rule collection groups              OK (6 items, 32.4 KB)


OUTPUT FILES EXPLAINED
----------------------
All files saved in a folder named: azure-<SUBSCRIPTION-NAME>-<DATE>_<TIME>
Example: C:\azure-export\azure-Contoso-Production-20260225_143012

File                              What it contains
------------------------------    -------------------------------------------------------
network-security-groups.json      All NSGs in the subscription.

                                  Each NSG entry includes:
                                  - Name, ResourceGroupName, Location, Id

                                  - SecurityRules (custom rules you created):
                                    Priority, Direction (Inbound/Outbound),
                                    Access (Allow/Deny), Protocol (TCP/UDP/ICMP/*/Ah/Esp),
                                    SourcePortRange, DestinationPortRange,
                                    SourceAddressPrefix, DestinationAddressPrefix,
                                    SourceApplicationSecurityGroups (ASG references),
                                    DestinationApplicationSecurityGroups (ASG references)
                                    Rules sorted by Direction then Priority.

                                  - DefaultSecurityRules (Azure's built-in rules):
                                    Same structure. These show what Azure allows/denies
                                    by default (e.g., AllowAzureLoadBalancerInBound,
                                    DenyAllInBound). Also sorted by Direction/Priority.

                                  - Subnets: list of subnet IDs this NSG is attached to
                                  - NetworkInterfaces: list of NIC IDs this NSG is on

                                  This single file covers NSG rules AND associations.

vnets.json                        All Virtual Networks with embedded subnets.

                                  Each VNet entry includes:
                                  - AddressSpace.AddressPrefixes: VNet CIDR block(s)
                                  - Subnets: list of all subnets with:
                                    - AddressPrefix: subnet CIDR
                                    - NetworkSecurityGroup.Id: NSG attached to subnet
                                    - RouteTable.Id: route table attached to subnet
                                    - ServiceEndpoints, PrivateEndpointNetworkPolicies
                                  - VirtualNetworkPeerings: cross-VNet connections

route-tables.json                 All route tables with their routes.
                                  Each route: AddressPrefix (destination CIDR),
                                  NextHopType (VirtualAppliance, Internet, VnetLocal, etc.),
                                  NextHopIpAddress (for virtual appliance routes).

application-security-groups.json  All ASGs: Id, Name, Location, ResourceGroupName.
                                  ASGs are referenced by name in NSG rules. Use this
                                  file to resolve what VMs belong to each ASG group.

vnet-gateways.json                VPN and ExpressRoute gateways: type, SKU, subnet,
                                  and public IP. Shows how on-premises connectivity
                                  enters the VNet.

vnet-connections.json             VPN / ExpressRoute connection objects: connection
                                  type, shared key presence, IKE protocol version.

azfw-firewalls.json               Azure Firewall instances with:
(if deployed)                     - IP configurations (subnet, public IP)
                                  - SKU (Standard or Premium)
                                  - FirewallPolicy reference (if using Policy mode)
                                  - Classic rule collections inline (if using Classic
                                    rules mode): ApplicationRuleCollections,
                                    NetworkRuleCollections, NatRuleCollections

azfw-policies.json                Firewall Policy objects: ThreatIntelMode, Sku/tier,
(if deployed)                     and references to rule collection groups.

azfw-rule-collections.json        Full rule content for all policy rule collection groups.
(if deployed)                     Each group entry includes:
                                  - ParentPolicyName (added by script for cross-reference)
                                  - Priority
                                  - RuleCollections (collections within the group):
                                    - Name, Priority, Action (Allow/Deny/DNAT)
                                    - Rules list with full source, destination,
                                      protocols, ports, and action per rule
                                      (ApplicationRule, NetworkRule, or NatRule)

azfw-not-deployed.json            Written when no Azure Firewall is found. Confirms
                                  the check was run — documented absence for PCI evidence.

MANIFEST.txt                      Subscription name, subscription ID, tenant ID,
                                  export timestamp, machine, user, and file list with
                                  sizes. For chain-of-custody records.


HOW TO REVIEW THE FILES ON WINDOWS
-----------------------------------
  VS Code (recommended):
    - Download: code.visualstudio.com
    - File > Open Folder > select the export folder
    - Click any .json file — press Shift+Alt+F to format/pretty-print
    - Ctrl+F: search within a file
    - Ctrl+Shift+F: search across all files in the folder

  Useful search terms for NSG security review:
    "*"                     Wildcard — any source/destination or any protocol
    "0.0.0.0/0"             Broad IPv4 source/destination (review carefully)
    "Internet"              Azure's tag for all internet addresses
    "Allow"                 All Allow rules (filter by direction manually)
    "Deny"                  All explicit Deny rules
    "Direction"             Find all rule direction fields

  Useful search terms for VNet topology review:
    "AddressPrefix"         Subnet CIDR blocks
    "NetworkSecurityGroup"  Which NSG is attached to each subnet
    "RouteTable"            Which route table is attached to each subnet
    "VirtualNetworkPeerings" Cross-VNet peering connections

  Useful search terms for Azure Firewall review:
    "Action"                Allow/Deny/DNAT decisions in rules
    "RuleCollections"       Rule collections inside each group
    "DestinationPorts"      Port targets in network and DNAT rules
    "TargetFqdns"           Domain targets in application rules

  Notepad++ (lightweight alternative):
    - Download: notepad-plus-plus.org
    - Language > JSON for syntax coloring


TROUBLESHOOTING
---------------
  "cannot be loaded because running scripts is disabled on this system"
      Run first (current session only):
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  "Authenticating... FAILED" with "AADSTS50034: user account does not exist"
      - The Tenant ID is incorrect
      - Find correct Tenant ID: Azure Portal > Azure Active Directory > Overview

  "Authenticating... FAILED" with "AADSTS7000215: Invalid client secret"
      - The client secret is wrong or expired (Service Principal auth)
      - Regenerate in: Azure AD > App registrations > your app >
        Certificates & secrets > New client secret

  "Setting subscription context... FAILED" / "Subscription not found"
      - The Subscription ID is incorrect or the account lacks access
      - Confirm with: Get-AzSubscription (run after Connect-AzAccount)

  "Network Security Groups... FAILED" with "AuthorizationFailed"
      - The account lacks the required RBAC permissions
      - Assign the "Reader" role at the Subscription scope (see above)

  Virtual network gateways or connections show 0 items
      - No VPN/ExpressRoute gateway exists in this subscription — this is normal
        for cloud-only environments. Not an error.

  Azure Firewall shows "No Azure Firewall instances found"
      - Azure Firewall is not deployed in this subscription — expected for
        environments using only NSGs. Documented in azfw-not-deployed.json.

  JSON files are very large (100+ MB)
      - Large subscriptions with many NSGs can produce large JSON files
      - Use VS Code with the "Large File Support" extension
      - Or filter by resource group: add -ResourceGroupName to the cmdlets
        in the script if you only need a specific environment's data

  "Policy rule collection groups... FAILED"
      - The service principal may lack permission to read rule collection groups
      - Add: Microsoft.Network/firewallPolicies/ruleCollectionGroups/read
        to the custom RBAC role, or use the built-in Reader role

  Sign-in browser window does not open (PowerShell 5.1)
      - PowerShell 5.1 uses device code authentication instead of a browser
      - Watch the console for: "To sign in, use a web browser to open the
        page https://microsoft.com/devicelogin and enter the code XXXXXXXX"
      - Open that URL in any browser and enter the code


SECURITY NOTES
--------------
  - Client secrets are stored in plain text in this script. Restrict file
    access using NTFS permissions — right-click > Properties > Security,
    remove all access except your own account.

  - Use a dedicated App Registration or guest account created for this
    assessment. Assign only the minimum RBAC permissions (Reader role).

  - Set an expiry on the client secret that matches the assessment duration.

  - After the assessment:
    - Delete or deactivate the client secret in the App Registration
    - Remove the RBAC assignment from the subscription
    - Delete the App Registration if it was created solely for this purpose
    - Delete or securely archive the export folder — it documents your entire
      network security posture including firewall rules and subnet topology

================================================================================
