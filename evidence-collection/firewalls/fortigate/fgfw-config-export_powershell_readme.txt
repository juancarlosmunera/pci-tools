================================================================================
  fgfw-config-export.ps1  —  README
  FortiGate Firewall Configuration Export (PowerShell)
  Audience: Firewall Administrator / Sysadmin
================================================================================

PURPOSE
-------
This script connects to a FortiGate firewall using its REST API and exports
the firewall configuration for review by a PCI DSS assessor. It is read-only
and makes no changes to the firewall.

Two types of output are produced:

  1. full-config.txt     — The complete running configuration (all sections).
                           Equivalent to "show full-configuration" on the CLI.
                           Open in VS Code or Notepad++ and use Ctrl+F to
                           search by section (e.g. "config firewall policy").

  2. Individual .json    — One structured JSON file per table: firewall rules,
     files                 interfaces, address objects, service objects, routes,
                           admin accounts, logging, and more. These are easier
                           to navigate than the flat config file and can be
                           opened in VS Code, Notepad++, or a browser.

A MANIFEST.txt is also created listing all files, sizes, and who ran the export.


REQUIREMENTS
------------
  - Windows PowerShell 5.1 (built into Windows 10/11 and Server 2016+)
    OR PowerShell 7+ (recommended — faster, better error output)

  - Network access to the firewall's management interface (port 443)
  - A FortiGate REST API token with read access (see "GENERATING AN API TOKEN")
  - The output folder will be created automatically — no need to pre-create it

  No additional modules or installs are required.


BEFORE YOU RUN — EDIT THESE 4 SETTINGS IN THE SCRIPT
-----------------------------------------------------
Open fgfw-config-export.ps1 in Notepad or VS Code and update the following
lines near the top of the file:

    $FortiGateIP = "10.0.1.1"             <-- Firewall management IP or hostname
    $ApiToken    = "YOUR_API_TOKEN"        <-- Paste your API token here
    $Vdom        = "root"                  <-- VDOM name (leave as "root" for
                                               standalone / non-VDOM FortiGates)
    $OutputBase  = "C:\fortigate-export"   <-- Folder where output will be saved
                                               (created automatically if missing)


WHAT IS A VDOM?
---------------
VDOMs (Virtual Domains) allow one FortiGate to act as multiple virtual
firewalls. If your organization does not use VDOMs, leave $Vdom = "root".

If VDOMs are enabled and your firewall policies live in a specific VDOM
(not root), change this to that VDOM's name. If you're unsure, check:
  System > VDOM in the FortiGate web UI
  OR run: get system vdom  (in the CLI)


GENERATING AN API TOKEN
-----------------------
You need a REST API token tied to an administrator account. The account needs
at minimum read-only access. Steps:

  Step 1 — Create a REST API Admin (web UI):
    1. Log in to the FortiGate web UI
    2. Go to System > Administrators
    3. Click "Create New" > "REST API Admin"
    4. Enter a username (e.g., pci-readonly)
    5. Set "Administrator Profile" to "super_admin_readonly" or a custom
       read-only profile
    6. Leave "PKI Group" blank unless your org requires it
    7. Set "Trusted Hosts" to the IP of the machine that will run this script
       (best practice — restricts who can use the token)
    8. Click OK — FortiGate will display the API token ONCE. Copy it now.
       It will not be shown again.

  Note: API token generation via CLI is not covered here; the web UI method
  above is the most straightforward.

  Treat the API token like a password. Do not share it or store it in email.


RUNNING THE SCRIPT
------------------
  1. Open PowerShell (search "PowerShell" in the Start menu — do NOT use
     PowerShell ISE for running scripts)

  2. If you see a script execution policy error (common on locked-down machines),
     run this first in the same window:
       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  3. Navigate to the folder containing the script:
       cd "C:\path\to\script"

  4. Run it:
       .\fgfw-config-export.ps1

  5. Watch the output. Each line shows OK or FAILED with details. A typical
     successful run looks like:

       ========================================
         FortiGate Configuration Export
         Target : 10.0.1.1
         VDOM   : root
         Output : C:\fortigate-export\fg-10.0.1.1-20260225_143012
       ========================================

       [ Full running config ]
         full config backup...              OK (14823 lines)

       [ Structured JSON exports ]
         Firewall policies (rulebase)...    OK (48.3 KB)
         Firewall policies (IPv6)...        OK (1.2 KB)
         Interfaces...                      OK (22.7 KB)
         Static routes...                   OK (5.4 KB)
         ...


OUTPUT FILES EXPLAINED
----------------------
All files are saved in a folder named:
  fg-<FIREWALL-IP>-<DATE>_<TIME>
  Example: C:\fortigate-export\fg-10.0.1.1-20260225_143012

File                          What it contains
---------------------------   -------------------------------------------------------
full-config.txt               Complete running config (all VDOMs and global settings).
                              Start here for a comprehensive review. Search with Ctrl+F
                              using section headers like "config firewall policy".

firewall-policies.json        IPv4 firewall rules (the rulebase). Each entry is one
                              rule with source, destination, service, action, etc.

firewall-policies-ipv6.json   Same as above for IPv6 rules.

interfaces.json               All interfaces: physical, VLAN, loopback, zones, IPs,
                              allowed management access (ping, HTTPS, SSH, etc.)

routes-static.json            Static routing table.
routes-bgp.json               BGP routing configuration (if used).
routes-ospf.json              OSPF routing configuration (if used).

address-objects.json          Host and subnet objects (IP addresses, FQDNs, ranges).
address-groups.json           Address groups (collections of address objects).

service-objects.json          Custom service definitions (protocol + port mappings).
service-groups.json           Service groups (collections of service objects).

admin-accounts.json           Administrator accounts, access profiles, trusted hosts,
                              and 2FA settings. Important for PCI access control review.

logging-syslog.json           Syslog server settings: IP, port, facility, severity.
ntp.json                      NTP server settings and sync status.

MANIFEST.txt                  List of all files with sizes, export timestamp, username,
                              and hostname. Useful for chain-of-custody documentation.


HOW TO REVIEW THE FILES ON WINDOWS
-----------------------------------
Recommended tools (free):

  VS Code (best overall):
    - Download: code.visualstudio.com
    - Open the export folder: File > Open Folder
    - For JSON files: right-click in the editor > Format Document (or Shift+Alt+F)
      This indents and structures the JSON for easy reading
    - Use Ctrl+F for search within a file
    - Use Ctrl+Shift+F to search across all files in the folder

  Notepad++ (lightweight alternative):
    - Download: notepad-plus-plus.org
    - Plugins > Plugin Admin > install "JSON Viewer" for JSON pretty-printing
    - Supports large files better than regular Notepad

  Browser (quick JSON view, no install needed):
    - Drag any .json file into a Chrome or Edge browser tab
    - The browser renders it as a collapsible tree — easy to navigate

  Regular Notepad:
    - Works for the .txt file but will struggle with large JSON on older Windows


TROUBLESHOOTING
---------------
  "cannot be loaded because running scripts is disabled on this system"
      Run this first (current session only, does not change system settings):
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  FAILED (HTTP 401) or FAILED (HTTP 403)
      - The API token is invalid, expired, or the account lacks permissions
      - Regenerate the token in System > Administrators > your API admin
      - Confirm the admin profile has read access to firewall policies

  FAILED (HTTP 404)
      - The API endpoint path is not valid for your FortiOS version
      - This script targets FortiOS v6.4 and later; older versions may
        not support all CMDB endpoints
      - The JSON export for that section will be missing — the full-config.txt
        will still contain the data

  FAILED — output is not a valid FortiGate config
      - The firewall returned an error page instead of the config
      - Common causes: wrong IP, API access not enabled on the management
        interface, or the token is invalid
      - Check: System > Feature Visibility > REST API access is enabled
      - Check: System > Administrators > your API admin > Trusted Hosts
        must include the IP of the machine you're running this from

  "Unable to connect to the remote server" or connection timeout
      - Confirm the firewall IP is correct and reachable:
          Test-NetConnection -ComputerName 10.0.1.1 -Port 443
      - Confirm HTTPS management access is enabled on the interface you're
        connecting to (System > Network > Interfaces > edit interface >
        Administrative Access > HTTPS must be checked)

  Some JSON files are empty or very small (e.g., 0-50 bytes)
      - This is normal for features not in use (e.g., BGP returns minimal
        data if BGP is not configured)
      - Open the file — if it contains {"status":"ok","results":[]} that
        means the table is simply empty, which is a valid finding

  Output folder not created / permission denied
      - Run PowerShell as your normal user account (not necessarily as Admin)
      - If $OutputBase is on a network drive, make sure you're connected to it
        and have write permission


SECURITY NOTES
--------------
  - The API token is stored in plain text in the script file. Restrict access
    to the script using NTFS permissions so only the running account can read it.
  - Set "Trusted Hosts" on the API admin account in FortiGate to limit which
    IPs can use the token.
  - Run the script from a managed workstation, not a shared machine.
  - After the PCI assessment, securely delete or archive the export folder —
    it contains your complete firewall configuration including admin accounts.
  - Consider disabling or deleting the API admin account in FortiGate once the
    assessment is complete.

================================================================================
