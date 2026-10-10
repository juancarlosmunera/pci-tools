================================================================================
  azure-csp-export.ps1  —  README
  Azure Cloud Service Provider Controls Export (PowerShell)
  Audience: Azure / Entra ID Administrator / Sysadmin
  PCI DSS 4.0.1 — Identity, Access, and Logging Controls
================================================================================

PURPOSE
-------
This script reads identity, access, and logging settings from Microsoft Entra
ID (formerly Azure AD) and your Azure subscriptions and saves them as evidence
for a PCI DSS review. It is read-only and makes no changes to Entra ID or Azure.

What is exported and why it matters for PCI DSS:

  PCI checks scorecard      All: pci-checks.csv summarises every check below as
  (CSV)                     current value vs. expected value, with the PCI DSS
                            requirement and the evidence file to look at.
                            Read this first.

  Entra ID user summary     Req 8.2.6, 8.3, 8.4: THE MOST IMPORTANT IDENTITY
  (CSV)                     FILE. One row per user: enabled/disabled, member or
                            guest, last successful sign-in, days inactive,
                            MFA registered (yes/no) and which methods, password
                            age, password-never-expires flag, and any directory
                            admin roles held.

  Directory role            Req 7.2: Every Entra ID admin role assignment —
  assignments               active and PIM-eligible — with expiry date, plus
                            the members of any group that holds an admin role.

  PIM role settings         Req 8.4.1: For each role, whether activation
                            requires MFA, justification, and approval, and the
                            maximum activation time.

  Conditional Access        Req 8.4.2, 8.4.3: How MFA is actually enforced —
  and security defaults     who is included and excluded, which apps, and
                            whether legacy authentication is blocked.

  Smart lockout, domain     Req 8.3.4, 8.3.6, 8.3.9: Account lockout threshold
  password expiry           and duration, password expiry per domain.

  App registration          Req 8.6: Client secrets and certificates on
  credentials               application accounts, with start/end dates and
                            lifetime. Secret values are never exported.

  Entra ID log export       Req 10.2, 10.5.1: Whether sign-in and audit logs
                            are sent somewhere that keeps them for 12 months
                            (Entra ID itself keeps them 30 days at most).

  Azure RBAC                Req 7.2: Every role assignment in each subscription
                            — inherited from management groups, at subscription
                            level, on resource groups, and on single resources —
                            active and PIM-eligible, with principal names.
                            Members of groups holding Owner, Contributor, or
                            User Access Administrator are listed too.

  Activity log and          Req 10.2, 10.3: Whether the subscription activity
  diagnostic settings       log and the logs of security-relevant resources
                            (Key Vault, NSGs, Azure Firewall, SQL, storage,
                            App Service, AKS, and more) go to a central store.

  Log Analytics retention   Req 10.5.1: Interactive and total (archive)
                            retention for every table in every workspace.

  SQL server auditing       Req 10.2: Auditing state and destination per server.

  Storage accounts          Req 1.4, 4.2.1, 7.2: Anonymous blob access, public
  and blob containers       network access, HTTPS-only and minimum TLS, shared
                            key access, soft delete, versioning, and which
                            containers are readable by anyone on the internet.

  Key Vault                 Req 3.6, 3.7: Soft delete, purge protection,
                            RBAC vs. access policies, network exposure.

  Microsoft Defender for    Req 5, 10.7, 11.5, 12.10: Which Defender plans are
  Cloud                     on, security alert contacts, secure score, unhealthy
                            recommendations, and — if the PCI DSS standard is
                            assigned — per-control PCI DSS results.

  Azure Policy              Req 2.2, 12.4: Policy assignments and every
                            currently non-compliant resource.


IMPORTANT — TWO SCRIPTS FOR AZURE
---------------------------------
This script (azure-csp-export.ps1) covers identity, access, and logging controls.

A separate script (azure-network-export.ps1) covers network security controls:
  NSGs, VNets, route tables, VPN/ExpressRoute gateways, Azure Firewall.

Run BOTH scripts to provide complete PCI DSS network and CSP evidence.


HOW THE SCRIPT WORKS
--------------------
The script talks to two Microsoft services:

  Azure Resource Manager    Subscriptions: RBAC, logging, storage, Key Vault,
                            Defender for Cloud, Azure Policy, plus the Entra ID
                            log export setting. Uses the Az.Accounts module.

  Microsoft Graph           Entra ID: users, MFA, roles, PIM, Conditional
                            Access, applications. Uses the
                            Microsoft.Graph.Authentication module.

The Entra ID part runs in a second PowerShell process, in the same window,
that the script starts by itself. This keeps the two modules apart — on Windows PowerShell 5.1
they can conflict if loaded into the same session. You do not need to do
anything; just be aware that with interactive sign-in you will be asked to
sign in TWICE (once for Azure, once for Microsoft Graph).

One run covers the whole tenant plus every subscription you list.


REQUIREMENTS
------------
  - Windows PowerShell 5.1 OR PowerShell 7+ (recommended)

  - PowerShell modules — offered for auto-install if not found:
      Az.Accounts                       (2.10.0 or later)
      Microsoft.Graph.Authentication    (2.0.0 or later)
    Both are already present if you have the full "Az" or "Microsoft.Graph"
    modules installed.

  - An account or service principal with read-only access. See
    "PERMISSIONS REQUIRED".

  - Internet access to management.azure.com, graph.microsoft.com, and
    login.microsoftonline.com.


BEFORE YOU RUN — EDIT THESE SETTINGS IN THE SCRIPT
---------------------------------------------------
Open azure-csp-export.ps1 in Notepad or VS Code and update:

    $TenantId        = "YOUR_TENANT_ID"            <-- Entra ID Tenant ID (GUID)

    $SubscriptionIds = @("YOUR_SUBSCRIPTION_ID")   <-- One or more subscriptions
                                                       Several:
                                                       @("id-1", "id-2", "id-3")
                                                       Every subscription the
                                                       account can see: @()

    $ClientId        = ""                           <-- App Registration client ID
    $ClientSecret    = ""                           <-- App Registration secret
                                                        Leave both as "" for
                                                        interactive sign-in

    $OutputBase      = "C:\azure-export"            <-- Output folder (auto-created)

Optional settings:

    $CollectEntra    = $true      Set to $false to skip Entra ID (Azure only)
    $CollectAzure    = $true      Set to $false to skip subscriptions (Entra only)
    $InactiveDays    = 90         Inactive-account threshold (PCI DSS 8.2.6)

WHICH SUBSCRIPTIONS TO LIST:
  Every subscription that holds in-scope resources — the cardholder data
  environment (CDE) and anything connected to it or able to affect its
  security (hub networks, shared logging, identity, management). If unsure,
  use @() to export all of them; the assessor can narrow scope afterwards.

FINDING YOUR TENANT ID AND SUBSCRIPTION IDs:
  Azure Portal > Microsoft Entra ID > Overview      "Tenant ID"
  Azure Portal > Subscriptions                      "Subscription ID" column


LICENSING NOTE — WHAT ENTRA ID P1 / P2 CHANGES
----------------------------------------------
Some Entra ID data only exists if the tenant has premium licensing:

  Needs Entra ID P1 (or P2):
    - Last sign-in dates (used for the inactive-account check, Req 8.2.6)
    - MFA registration report (used for the MFA checks, Req 8.4)
    - Conditional Access policies

  Needs Entra ID P2:
    - Privileged Identity Management (PIM): eligible assignments, assignment
      expiry, and activation settings

Without the licence, the script still runs. Each item that cannot be read is
marked FAILED on screen and in collection-log.txt, and the matching scorecard
check shows UNKNOWN with the reason — never a false PASS. The user list is
still exported, without sign-in dates.


PERMISSIONS REQUIRED
--------------------
Three kinds of read-only access are needed. All three apply whether you sign in
interactively or use a service principal.

  1. Azure RBAC — on each subscription (or on a management group above them):
       "Reader"                    Reads everything the script needs, including
                                   Defender for Cloud and Azure Policy results.

  2. Entra ID directory role — on the tenant:
       "Global Reader"             Reads all Entra ID settings, including
                                   Conditional Access, PIM, and the Entra ID
                                   log export setting. Read-only.

  3. Microsoft Graph permissions — all read-only:
       Directory.Read.All                    users, groups, roles, apps, domains
       AuditLog.Read.All                     last sign-in, MFA registration report
       Policy.Read.All                       Conditional Access, security defaults,
                                             authentication methods
       RoleManagement.Read.Directory         directory role assignments and PIM
       RoleManagementPolicy.Read.Directory   PIM activation settings
       UserAuthenticationMethod.Read.All     MFA registration report

     Interactive sign-in: these are requested automatically. The first time,
     an administrator (Global Administrator or Privileged Role Administrator)
     must approve them — the sign-in page shows a consent prompt. Tick
     "Consent on behalf of your organization" so other users are not asked.

     Service principal: add them as APPLICATION permissions on the App
     Registration and grant admin consent (see below).

  Assign in the Azure Portal:
    RBAC:            Subscriptions > your subscription > Access control (IAM) >
                     Add role assignment > Reader > select the user or app
    Directory role:  Microsoft Entra ID > Roles and administrators >
                     Global Reader > Add assignments > select the user or app


CREATING A SERVICE PRINCIPAL (OPTIONAL)
---------------------------------------
Only needed for non-interactive use. Requires a Global Administrator or
Privileged Role Administrator to grant consent in Step 4.

  Step 1 — Create an App Registration:
    Microsoft Entra ID > App registrations > New registration
    Name: pci-readonly-export (or any descriptive name)
    Supported account types: Accounts in this organizational directory only
    Click Register

  Step 2 — Create a client secret:
    In the App Registration > Certificates & secrets > New client secret
    Description: pci-assessment
    Expires: set to the length of the assessment
    Click Add — copy the VALUE immediately (shown only once)

  Step 3 — Add Microsoft Graph permissions:
    In the App Registration > API permissions > Add a permission >
    Microsoft Graph > Application permissions > tick each of:
      Directory.Read.All
      AuditLog.Read.All
      Policy.Read.All
      RoleManagement.Read.Directory
      RoleManagementPolicy.Read.Directory
      UserAuthenticationMethod.Read.All
    Click Add permissions

  Step 4 — Grant admin consent:
    Still on API permissions > "Grant admin consent for <your tenant>" > Yes
    Every permission should now show a green tick under Status.

  Step 5 — Assign roles:
    Reader on each subscription (see PERMISSIONS REQUIRED)
    Global Reader directory role (search for the app name when assigning)

  Step 6 — Copy the IDs into the script:
    From the App Registration overview page:
      Application (client) ID → $ClientId
      Directory (tenant) ID   → $TenantId
    The client secret value   → $ClientSecret

  Step 7 — Clean up after the assessment:
    Delete the client secret (or the whole App Registration), and remove the
    Reader and Global Reader assignments.


RUNNING THE SCRIPT
------------------
  1. Open PowerShell

  2. If needed (common on corporate machines):
       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  3. Navigate to the script folder:
       cd "C:\path\to\script"

  4. Run:
       .\azure-csp-export.ps1

     Run it from the .ps1 file as shown. Pasting the script into a console
     does not work, because the script needs to start a copy of itself.

  5. If modules are not installed, answer "yes" at the prompt.
     This requires internet access and takes 1-3 minutes (one-time).

  6. Interactive sign-in: sign in when the browser opens for Azure, and again
     when it opens for Microsoft Graph.

  7. A successful run looks like (shortened):

       ========================================
         Azure CSP Controls Export (PCI DSS)
         Tenant  : 72f988bf-0000-0000-0000-2d7cd011db47
         Output  : C:\azure-export\azure-csp-20260225_143012
       ========================================

       [ Connecting to Azure Resource Manager ]
         Authenticating                                ... OK
         Signed in as:                                    admin@contoso.com

       [ Entra ID log export ]
         Entra ID diagnostic settings                  ... OK (1 items, 0.4 KB)

       [ Subscriptions ]
         Listing subscriptions                         ... OK (2 selected of 5 visible)

       ========================================
         Subscription : Contoso-Production
         ID           : 1111aaaa-2222-bbbb-3333-cccc4444dddd
         Folder       : sub-Contoso-Production-1111aaaa
       ========================================
       [ Resource inventory ]
         Resources                                     ... OK (412 rows)
       [ Access control (RBAC) ]
         Role assignments                              ... OK (87 items, 31.2 KB)
       [ Logging and monitoring ]
         Activity log export (diagnostic settings)     ... OK (1 items, 0.9 KB)
         Resource diagnostic settings (64 resources)   ... OK (64 rows)
       [ Storage accounts ]
         Blob containers (public access, immutability) ... OK (38 rows)
       [ Microsoft Defender for Cloud ]
         PCI DSS controls (Defender)                   ... OK (264 rows)
       ...

       [ Connecting to Microsoft Graph (Entra ID) ]
         Authenticating                                ... OK
       [ Users, groups, and MFA registration ]
         Users (with sign-in activity)                 ... OK (1243 items, 1650.2 KB)
         MFA registration details                      ... OK (1243 items, 512.7 KB)
       [ Directory roles and PIM ]
         Role assignments (active + eligible)          ... OK (31 rows)
       ...

         Hashing evidence (SHA-256) + manifest...           OK (73 files)
       ========================================
         Export complete.
         Scorecard: 18 PASS, 4 FAIL, 21 REVIEW, 9 INFO, 0 UNKNOWN
           FAIL  [Tenant] Enabled accounts inactive > 90 days
           FAIL  [Subscription: Contoso-Production] SQL servers with auditing disabled
           ...

  Run time depends on tenant and subscription size: a few minutes for most
  environments. Diagnostic settings and blob containers are read one resource
  at a time, so subscriptions with hundreds of resources take longer.


OUTPUT FILES EXPLAINED
----------------------
All files are saved in: azure-csp-<DATE>_<TIME>
Example: C:\azure-export\azure-csp-20260225_143012

  azure-csp-20260225_143012\
    pci-checks.csv              Scorecard — read first
    collection-log.txt          Every item collected, or why it failed
    MANIFEST.txt                Chain-of-custody record with SHA-256 hashes
    checksums.sha256            Hashes for bulk verification
    tenant\                     Entra ID (one per tenant)
    sub-<NAME>-<ID>\            One folder per subscription

SCORECARD
---------
pci-checks.csv                    One row per check. Columns:
                                    Scope        Tenant, or Subscription: <name>
                                    Area         e.g. Authentication, Logging
                                    Check        What was tested
                                    Status       PASS / FAIL / REVIEW / INFO / UNKNOWN
                                    Current      What the script found
                                    Expected     What PCI DSS (or Microsoft
                                                 guidance, where stated) expects
                                    PciDss       Requirement number(s)
                                    EvidenceFile The file that backs the result

                                  Status meanings:
                                    PASS     Meets the expected value
                                    FAIL     Does not meet it — likely finding
                                    REVIEW   Needs assessor judgement (e.g. an
                                             exclusion that may be a break-glass
                                             account, or a resource that may be
                                             out of scope)
                                    INFO     Context; no pass/fail
                                    UNKNOWN  Data could not be collected — see
                                             collection-log.txt for the reason

                                  The scorecard points at evidence; it does not
                                  replace the assessor's testing.

collection-log.txt                One line per item: time, OK / FAILED / INFO,
                                  scope, file name, and detail. Any FAILED line
                                  means that evidence file contains a
                                  "collected": false marker instead of data.

TENANT FOLDER (tenant\)
-----------------------
entra-users.csv                   THE MOST IMPORTANT IDENTITY FILE. Open in Excel.
                                  One row per user. Key columns:
                                    AccountEnabled       True / False
                                    UserType             Member / Guest
                                    LastSignInUtc        Last successful sign-in
                                    DaysSinceLastSignIn
                                    Inactive             Yes / No against the
                                                         $InactiveDays threshold
                                                         (default 90)
                                    MfaRegistered        True / False
                                    MethodsRegistered    e.g. microsoftAuthenticator;
                                                         fido2
                                    PasswordAgeDays
                                    PasswordNeverExpires Yes / No
                                    DirectoryRoles       Admin roles held directly
                                  Filter AccountEnabled = True and Inactive = Yes*
                                  for Req 8.2.6. Filter MfaRegistered = False for
                                  users who cannot complete MFA.

entra-role-assignments.csv        Every directory role assignment:
                                    Role, Privileged (Yes for admin roles)
                                    State        Active / Eligible (PIM)
                                    AssignedVia  Direct / PIM activation /
                                                 PIM eligibility
                                    ExpiresUtc   Date, or "Never (permanent)"
                                    PrincipalType, PrincipalName, PrincipalUPN,
                                    PrincipalUserType (Member / Guest)
                                  A principal of "(not found ...)" is a deleted
                                  account that still holds a role.

entra-privileged-group-members.csv
                                  Members (including nested) of every group that
                                  holds an Entra ID admin role or a privileged
                                  Azure RBAC role. GrantedAccess shows why the
                                  group is listed. Without this file, people who
                                  are admins through a group would be invisible.

entra-pim-role-settings.csv       Per role: ActivationRequiresMfa,
(Entra ID P2)                     ActivationRequiresApproval,
                                  ActivationRequiresJustification,
                                  MaxActivationDuration (e.g. PT8H = 8 hours),
                                  PermanentEligibleAllowed, PermanentActiveAllowed.

entra-conditional-access.csv      One row per Conditional Access policy with
                                  names (not IDs) for users, groups, roles,
                                  apps, and locations. Key columns:
                                    State            enabled /
                                                     enabledForReportingButNotEnforced
                                                     (report-only — NOT enforced) /
                                                     disabled
                                    IncludeUsers     "All" = everyone
                                    ExcludeUsers / ExcludeGroups — review each
                                    GrantControls    mfa / block / compliantDevice
                                    GrantOperator    OR means any one control is
                                                     enough — MFA is then not
                                                     strictly required
                                    ClientAppTypes   exchangeActiveSync / other =
                                                     legacy authentication

entra-app-credentials.csv         One row per client secret or certificate:
                                  Application, CredentialType, StartUtc, EndUtc,
                                  Status (Active / Expired), LifetimeDays,
                                  DaysToExpiry. Secret values are never exported.

entra-diagnostic-settings.json    Where Entra ID sign-in and audit logs are sent.
                                  Look for SignInLogs and AuditLogs with
                                  "enabled": true and a destination
                                  (workspaceId / storageAccountId / eventHub).

entra-security-defaults.json      isEnabled true/false
entra-conditional-access-policies.json   Full Conditional Access definitions
entra-named-locations.json        Trusted IP ranges and countries used in CA
entra-auth-methods-policy.json    Allowed MFA methods (Authenticator, FIDO2,
                                  SMS, voice, etc.) and who may use them
entra-authorization-policy.json   Guest invitation and user default settings
entra-directory-settings.json     Smart lockout values, if customised. Empty =
                                  Microsoft defaults (10 attempts, 60 seconds)
entra-domains.json                Federated vs. managed domains and password
                                  expiry (2147483647 = never expires)
entra-licenses.json               Licences, to confirm P1/P2
entra-users.json, entra-groups.json, entra-service-principals.json,
entra-role-definitions.json, entra-role-assignments.json,
entra-pim-*.json, entra-mfa-registration.json, entra-app-registrations.json,
entra-organization.json           Raw data behind the CSV files

SUBSCRIPTION FOLDERS (sub-<NAME>-<ID>\)
---------------------------------------
rbac-role-assignments.csv         Every RBAC assignment affecting the subscription:
                                    Role, Privileged (Owner / Contributor /
                                    User Access Administrator / RBAC Administrator)
                                    State        Active / Eligible (PIM)
                                    ScopeLevel   Management group / Subscription /
                                                 Resource group / Resource
                                    PrincipalName, PrincipalUPN, PrincipalUserType
                                  "(not found in directory - deleted?)" = an
                                  assignment left behind for a deleted identity.

rbac-custom-roles.json            Custom roles with their allowed actions. An
                                  action of "*" means everything.

activity-log-diagnostic-settings.json
                                  Where the subscription activity log is sent.
                                  Empty = kept 90 days only, in Azure.

resource-diagnostic-settings.csv  Each security-relevant resource: LogsEnabled
                                  (True / False / Unknown), Destinations,
                                  LogCategories. Covers Key Vault, NSGs, Azure
                                  Firewall, Application Gateway, Front Door,
                                  Bastion, VPN gateways, SQL databases and
                                  managed instances, PostgreSQL, MySQL, Cosmos DB,
                                  Redis, App Service, AKS, Container Registry,
                                  API Management, Recovery Services, Automation,
                                  and storage (blob logs).

log-analytics-table-retention.csv One row per table per workspace:
                                    InteractiveRetentionDays  immediately queryable
                                    TotalRetentionDays        including archive
                                    KeySecurityTable          Yes for sign-in,
                                                              audit, activity,
                                                              firewall, and OS
                                                              security tables
                                  Req 10.5.1: 12 months total, 3 months
                                  immediately available.

sql-server-auditing.csv           Per SQL server: AuditingState, ToLogAnalytics,
(if SQL servers exist)            StorageEndpoint, RetentionDays.

storage-accounts.csv              Per storage account:
                                    AllowBlobPublicAccess  should be False
                                    PublicNetworkAccess / NetworkDefaultAction
                                    HttpsOnly              should be True
                                    MinimumTlsVersion      should be TLS1_2
                                    AllowSharedKeyAccess
                                    BlobSoftDelete, BlobVersioning
                                    Key1CreatedUtc / Key2CreatedUtc (key age)

storage-containers.csv            Per blob container: PublicAccess (None / Blob /
                                  Container) and EffectivelyPublic — True only if
                                  the storage account also allows anonymous access.
                                  Also shows immutability (WORM) for log archives.

key-vaults.csv                    Per vault: SoftDelete, PurgeProtection,
                                  RbacAuthorization, PublicNetworkAccess,
                                  NetworkDefaultAction, PrivateEndpoints.

defender-plans.csv                Defender plan per resource type: Tier
                                  (Free / Standard) and SubPlan (P1 / P2).
                                  "VirtualMachines" = Defender for Servers.

defender-recommendations.csv      Every unhealthy recommendation with Severity
                                  and the affected resource.

defender-pci-controls.csv         Only if the PCI DSS standard is assigned in
                                  Defender for Cloud > Regulatory compliance.
                                  One row per PCI DSS control: State (Passed /
                                  Failed / Skipped) and assessment counts.
defender-pci-failed-assessments.csv
                                  The failing checks behind each failed control,
                                  with a link to the details in the portal.

defender-security-contacts.json   Who receives Defender security alerts.
defender-secure-score.json        Current and maximum secure score.

policy-compliance-summary.csv     Non-compliant resource count per policy
                                  assignment.
policy-noncompliant-resources.csv Every non-compliant resource (up to 20,000).

resources.csv                     Inventory of every resource in the subscription
                                  — useful for confirming scope.

subscription.json, rbac-*.json, storage-accounts.json, key-vaults.json,
log-analytics-workspaces.json, policy-*.json, defender-*.json
                                  Raw data behind the CSV files.


VERIFYING EVIDENCE INTEGRITY
----------------------------
The assessor (or anyone) can confirm the files have not been altered since
collection using the hashes in the MANIFEST or checksums.sha256. Paths in
both files are relative to the export folder (e.g. tenant/entra-users.csv).

  Verify a single file's hash matches the MANIFEST:
    Windows   : certutil -hashfile tenant\entra-users.csv SHA256
    PowerShell: Get-FileHash tenant\entra-users.csv -Algorithm SHA256

  Verify all files at once against checksums.sha256:
    Linux/macOS : sha256sum -c checksums.sha256
    (run from inside the export folder)

If any hash does not match, the file was modified after collection — do not
rely on it; re-run the export.


HOW TO REVIEW THE FILES ON WINDOWS
----------------------------------
  CSV files — Excel:
    - Double-click to open, or Data > From Text/CSV > select file > Load
    - Data > Filter to add filter arrows to each column
    - pci-checks.csv: filter Status = FAIL, then REVIEW
    - entra-users.csv: filter AccountEnabled = TRUE, then Inactive or
      MfaRegistered

  JSON files — VS Code:
    - File > Open Folder > select the export folder
    - Click any .json file, press Shift+Alt+F to format/indent
    - Ctrl+Shift+F to search across all files
    - Search "collected": false to find anything that was not collected


TROUBLESHOOTING
---------------
  "Run this script from its .ps1 file"
      The script was pasted into a console. Save it as a .ps1 file and run it
      as .\azure-csp-export.ps1.

  "cannot be loaded because running scripts is disabled on this system"
      Run first (current session only):
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  "Authenticating... FAILED" with "AADSTS7000215: Invalid client secret"
      The client secret is wrong or expired. Create a new one in
      App registrations > your app > Certificates & secrets.

  "Authenticating... FAILED" with "AADSTS50034" or "AADSTS90002"
      The Tenant ID is wrong. Check Microsoft Entra ID > Overview.

  Graph sign-in shows "Need admin approval"
      The Microsoft Graph permissions have not been consented. Ask a Global
      Administrator to sign in once and approve on behalf of the organisation,
      or use a service principal with admin consent granted.

  "WARNING: subscription <id> is not visible to this account"
      The ID is wrong, or the account lacks Reader on that subscription.

  Many Entra items FAILED with "Authorization_RequestDenied"
      Interactive: the user does not hold Global Reader.
      Service principal: a Graph application permission is missing or admin
      consent was not granted (API permissions page — look for green ticks).

  "Users (with sign-in activity)" OK but "sign-in activity unavailable"
      The tenant has no Entra ID P1/P2 licence, or AuditLog.Read.All is
      missing. Users are exported without sign-in dates; the inactive-account
      check shows UNKNOWN. Evidence for Req 8.2.6 must come from elsewhere.

  "PIM ..." FAILED with "AadPremiumLicenseRequired" or similar
      The tenant has no Entra ID P2 licence, so PIM is not in use. Active role
      assignments are still exported.

  "Entra ID diagnostic settings... FAILED" with "AuthorizationFailed"
      The account needs the Global Reader (or Security Reader) directory role.

  "Regulatory compliance standards" OK but "No PCI DSS standard assigned"
      Normal if PCI DSS has not been added in Defender for Cloud >
      Regulatory compliance > Manage compliance policies. Not an error.

  "Entra ID collection did not complete"
      Read collection-log.txt for the reason. The Azure subscription evidence
      is still complete; RBAC principal names show "(Entra ID not collected)".

  Run is slow on large subscriptions
      Diagnostic settings and blob containers are read one resource at a time.
      Hundreds of resources can take 10+ minutes. This is expected.


SECURITY NOTES
--------------
  - Client secrets are stored in plain text in this script. Restrict file
    access using NTFS permissions — right-click > Properties > Security,
    remove all access except your own account.

  - Use a dedicated account or App Registration created for this assessment,
    with only Reader, Global Reader, and the read-only Graph permissions
    listed above. Set the client secret to expire when the assessment ends.

  - After the assessment:
    - Delete the client secret or the App Registration
    - Remove the Reader and Global Reader assignments
    - Delete or securely archive the export folder — it contains your full
      user list, admin assignments, MFA status, and security posture

================================================================================
