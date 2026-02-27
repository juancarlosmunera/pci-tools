================================================================================
  cisco-config-export.ps1  —  README
  Cisco Firewall / Router / Switch Configuration Export (PowerShell)
  Audience: Firewall Administrator / Sysadmin
================================================================================

PURPOSE
-------
This script connects to a Cisco device via SSH and exports the running
configuration along with key show command outputs for review by a PCI DSS
assessor. It is read-only and makes no changes to the device.

Supported device types:
  - Cisco ASA (firewall)
  - Cisco IOS (routers and switches)
  - Cisco IOS-XE (routers and switches)

All output is saved to a timestamped folder as plain text files. Files open
directly in VS Code or Notepad++ on Windows with no special tools required.


REQUIREMENTS
------------
  - Windows PowerShell 5.1 (built into Windows 10/11 and Server 2016+)
    OR PowerShell 7+ (recommended)

  - Posh-SSH PowerShell module (the script will offer to install this for you
    automatically — see "RUNNING THE SCRIPT" below)

  - SSH access to the Cisco device from this Windows machine (port 22)
    SSH must be enabled on the device — see "ENABLING SSH ON THE DEVICE" below

  - A username and password for the device with at least read access
  - The enable password (if your device requires it for privileged commands)

  No REST API or web access is required. The script connects over SSH only.


BEFORE YOU RUN — EDIT THESE 6 SETTINGS IN THE SCRIPT
-----------------------------------------------------
Open cisco-config-export.ps1 in Notepad or VS Code and update the following
lines near the top of the file:

    $DeviceIP       = "10.0.1.3"           <-- IP address or hostname of the device
    $Username       = "admin"              <-- SSH login username
    $Password       = "YOUR_PASSWORD"      <-- SSH login password
    $EnablePassword = "YOUR_ENABLE_PASSWORD" <-- Enable password (see note below)
    $DeviceType     = "ios"               <-- Device type: ios | iosxe | asa
    $OutputBase     = "C:\cisco-export"    <-- Folder where output will be saved
                                               (created automatically if missing)

ENABLE PASSWORD NOTE:
  Most Cisco devices require you to type "enable" after logging in to reach
  privileged mode (where show commands work). The enable password is separate
  from your login password. If your account logs in directly to privileged mode
  (privilege level 15) or if enable is not configured, leave $EnablePassword
  as an empty string: $EnablePassword = ""


WHAT IS MY DEVICE TYPE?
------------------------
  ios     — Cisco routers and switches running IOS (e.g., 2900, 3900, 3560,
             3850 series). The prompt looks like:  Router>  or  Switch>
             After enable:                         Router#  or  Switch#

  iosxe   — Cisco routers and switches running IOS-XE (e.g., ASR 1000,
             ISR 4000, Catalyst 9000 series). Looks identical to IOS at
             the prompt. Check with: show version | include IOS XE

  asa     — Cisco ASA firewall (5505, 5506, 5508, 5510, 5515, 5525, etc.)
             The prompt looks like:  ciscoasa>
             After enable:           ciscoasa#


ENABLING SSH ON THE DEVICE
---------------------------
SSH must be enabled before running this script. To check and enable SSH:

  For IOS / IOS-XE:
    Check if SSH is running:
      show ip ssh

    Minimal configuration to enable SSH (requires crypto key):
      conf t
        ip domain-name yourdomain.com
        crypto key generate rsa modulus 2048
        ip ssh version 2
        line vty 0 4
          transport input ssh
          login local
        end

  For ASA:
    Check if SSH is running:
      show ssh

    Minimal configuration to enable SSH:
      conf t
        domain-name yourdomain.com
        crypto key generate rsa modulus 2048
        ssh <your-workstation-IP> <subnet-mask> management
        ssh version 2
        aaa authentication ssh console LOCAL
        end


RUNNING THE SCRIPT
------------------
  1. Open PowerShell (search "PowerShell" in the Start menu)

  2. If execution policy blocks the script, run this first (current session only):
       Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  3. Navigate to the folder containing the script:
       cd "C:\path\to\script"

  4. Run it:
       .\cisco-config-export.ps1

  5. If Posh-SSH is not installed, the script will ask you:
       "Install Posh-SSH now from PSGallery? (yes/no)"
     Type "yes" and press Enter. This requires internet access and may take
     30-60 seconds. It only needs to be done once.

  6. Watch the output. A successful run looks like:

       ========================================
         Cisco Configuration Export
         Target      : 10.0.1.3
         Device type : ios
         Output      : C:\cisco-export\cisco-10.0.1.3-20260225_143012
       ========================================

       [ Connecting ]
         SSH session...                           OK
         Enable mode...                           OK
         Disable pagination...                    OK

       [ Running configuration ]
         Device version and model...              OK (3.1 KB)
         Full running configuration...            OK (48.3 KB)
         Currently logged-in users...             OK (0.5 KB)

       [ Network security ]
         IP access control lists (ACLs)...        OK (12.7 KB)
         IP routing table...                      OK (5.4 KB)
         Interfaces (full detail)...              OK (22.1 KB)
         ...

       ========================================
         Export complete.
         Files saved to: C:\cisco-export\cisco-10.0.1.3-20260225_143012
       ========================================


OUTPUT FILES EXPLAINED
----------------------
All files are saved in a folder named:
  cisco-<DEVICE-IP>-<DATE>_<TIME>
  Example: C:\cisco-export\cisco-10.0.1.3-20260225_143012

File                          What it contains
---------------------------   -------------------------------------------------------
running-config.txt            Full running configuration — the primary evidence file.
                              Contains all device settings: interfaces, ACLs, routing,
                              AAA, logging, NTP, management access, etc.
                              Use Ctrl+F in VS Code to search by section keyword.

version-info.txt              Device model, serial number, IOS/ASA version, uptime,
                              license information. Useful for identifying the exact
                              device and verifying patch level.

access-lists.txt              All ACL rules with hit counts (IOS: "show ip access-lists",
                              ASA: "show access-list"). Critical for PCI firewall
                              rule review. Shows actual permit/deny entries.

routes.txt                    Routing table showing how traffic is forwarded.
                              Helps confirm network segmentation and traffic paths.

interfaces.txt                All interfaces with IP addresses, status, speed, duplex,
                              and input/output error counters.

interfaces-brief.txt          [IOS/IOS-XE only] One-line summary per interface:
(IOS/IOS-XE)                  IP address, status (up/down), and protocol state.

interfaces-nameif.txt         [ASA only] Interface names, security levels, and IP
(ASA)                         addresses. Security levels are key for ASA traffic flow.

address-objects.txt           [ASA only] Network and service objects used in ACLs.
(ASA)

object-groups.txt             [ASA only] Object groups (collections of objects) used
(ASA)                         in ACL rules. Needed to understand what each ACL entry
                              actually permits or denies.

nat-rules.txt                 [ASA only] NAT rules with source, destination, and
(ASA)                         translated addresses. Relevant for understanding traffic
                              flow between security zones.

vlans.txt                     [IOS/IOS-XE only] VLAN database. Important for switches
(IOS/IOS-XE)                  to understand network segmentation.

spanning-tree.txt             [IOS/IOS-XE only] Spanning tree state and port roles.
(IOS/IOS-XE)

logging-config.txt            Syslog configuration: logging level, destination server
                              IP and port. Required for PCI logging controls review.

ntp.txt / ntp-status.txt /    NTP server configuration and sync status. Required for
ntp-associations.txt          PCI time synchronization controls review.

logged-in-users.txt           Users currently logged in to the device via console,
                              telnet, or SSH. Contextual info for the assessor.

MANIFEST.txt                  List of all files with sizes, export timestamp, the
                              machine and user account that ran the script. Useful
                              for chain-of-custody documentation.


HOW TO REVIEW THE FILES ON WINDOWS
-----------------------------------
Recommended tools (all free):

  VS Code (recommended):
    - Download: code.visualstudio.com
    - Open the export folder: File > Open Folder
    - Use Ctrl+F to search within a file
    - Use Ctrl+Shift+F to search across all files at once
    - Use the outline/minimap on the right side to navigate large configs

  Notepad++ (lightweight alternative):
    - Download: notepad-plus-plus.org
    - Handles very large files well
    - Use Find in Files (Ctrl+Shift+F) to search across the export folder

  For the running-config.txt, useful search terms by section:
    "ip access-list"        — named ACLs
    "access-list"           — numbered ACLs (older style)
    "interface"             — interface sections
    "ip route"              — static routes
    "logging"               — log settings
    "ntp server"            — NTP configuration
    "username"              — local user accounts
    "aaa"                   — authentication/authorization settings
    "crypto"                — SSH, VPN, and encryption settings
    "line vty"              — remote access (SSH/Telnet) settings


TROUBLESHOOTING
---------------
  "cannot be loaded because running scripts is disabled on this system"
      Run this first (current session only, no permanent system change):
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

  "Posh-SSH module is not installed" / install fails
      - Confirm internet access from this machine
      - Run PowerShell as your user account (not necessarily as admin)
      - Manual install: Open PowerShell and run:
          Install-Module -Name Posh-SSH -Scope CurrentUser -Force
      - If PSGallery is blocked, ask your IT team to install it, or download
        from: https://github.com/darkoperator/Posh-SSH

  "SSH session... FAILED"
      - Confirm the device IP is reachable:
          Test-NetConnection -ComputerName 10.0.1.3 -Port 22
      - Confirm SSH is enabled on the device (see "ENABLING SSH ON THE DEVICE")
      - Confirm the username and password are correct
      - Confirm your workstation IP is in the device's SSH allowed-hosts list
        (ASA: "ssh <IP> <mask> management",  IOS: "access-class" on vty lines)

  "Enable mode... FAILED (enable password rejected)"
      - The enable password in $EnablePassword is incorrect
      - Try logging in to the device manually (PuTTY) and testing the enable
        password interactively before running the script
      - If no enable password is set on the device, leave $EnablePassword = ""

  "Enable mode... FAILED (already privileged)" — this is NOT an error
      If you see "OK (already privileged)" it means your SSH account has
      privilege level 15 configured and enable is not needed. This is fine.

  Commands return very small files (under 1 KB) or appear empty
      - Some commands return minimal output when not configured
        (e.g., "show vlan" on a router, "show ntp associations" if NTP is off)
        Open the file and check — empty output for unused features is valid.
      - If show running-config is unexpectedly small, the enable mode may have
        failed silently. Verify by running the script with PuTTY side-by-side.

  Commands time out on large devices
      - The default timeout is 60 seconds per command (120s for running-config)
      - On very large configs (thousands of lines), increase the timeout by
        editing the Invoke-ShowCommand calls at the bottom of the script:
          Invoke-ShowCommand "show running-config" "running-config.txt" "..." 180

  Host key warning / "key not found in known hosts"
      - The script uses -AcceptKey which automatically accepts and stores the
        device's SSH host key. This is the equivalent of typing "yes" when
        prompted by PuTTY on first connection.
      - This is expected behavior for network devices that use self-signed keys.


SECURITY NOTES
--------------
  - Passwords are stored in plain text in this script. Restrict file access
    using NTFS permissions so only the running account can read it.
    (Right-click > Properties > Security — remove all access except your account)

  - Run the script from a managed workstation, not a shared or public machine.

  - The SSH credentials used should be a dedicated read-only account created
    for this assessment, not a shared admin account.

  - After the assessment is complete:
    - Delete or securely archive the export folder — it contains the full
      device configuration
    - Disable or remove the assessment account from the device if one was
      created specifically for this purpose
    - Delete the script file or remove the passwords from it

================================================================================
