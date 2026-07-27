================================================================================
  windows-os-export.ps1  —  README
  Windows Operating System Configuration Export (PowerShell)
  Audience: Windows Administrator / Sysadmin
  PCI DSS 4.0.1 — System Hardening, Access Control, and Logging Controls
================================================================================

PURPOSE
-------
This script collects Windows host configuration evidence for PCI DSS system
hardening, access control, and logging control reviews. It is read-only and
makes NO changes to any system.

It can run two ways:
  - LOCAL   — collect from the machine the script is run on.
  - REMOTE  — collect from a list of hostnames (one per line in a text file)
              over PowerShell Remoting (WinRM), from a single admin workstation.
              You do not have to log on to each server.

Each target gets its own timestamped evidence folder inside one run folder.
Every output file is hashed with SHA-256, and each host folder has its own
MANIFEST recording the collection date/time, the account used on the target,
the workstation that retrieved and hashed the bundle, and every file's hash —
so the assessor can verify the evidence has not been altered since collection.

What is collected and why it matters for PCI DSS:

  System information        Context: OS edition, build/patch baseline, domain
                            membership, and uptime for the host described by
                            this evidence set.

  Local user accounts       Req 8.2, 8.3: Every local account with enabled
                            status, whether a password is required, password
                            last-set date, expiry, and last logon. Used to find
                            shared, stale, non-expiring, or passwordless accounts.

  Local groups + members    Req 7.2: Group membership, especially Administrators,
                            Remote Desktop Users, and Backup Operators — the core
                            of a least-privilege review.

  Password / lockout policy Req 8.3.4, 8.3.6, 8.3.9, 8.3.4: Minimum length,
                            complexity, history, maximum age, lockout threshold,
                            and lockout duration (net accounts + secedit).

  Security policy (secedit) Req 7.2, 8.3: Authoritative local security policy —
                            password policy, lockout policy, and user rights
                            assignments (who can log on, back up files, etc.).

  Audit policy (auditpol)   Req 10.2, 10.3: Which security events are logged —
                            logon, account management, privilege use, policy
                            change, object access.

  Event log configuration   Req 10.5: Max size and retention per event log —
                            confirms audit trails are retained and protected.

  Windows Firewall          Req 1.2, 1.3, 1.4: Firewall enabled per profile,
                            default inbound/outbound actions, and every rule.

  Installed software        Req 6.3.3, 2.2: Application inventory (from registry
                            uninstall keys) to review for unnecessary or
                            unsupported software.

  Installed hotfixes        Req 6.3.3: Applied OS patches with install dates —
                            confirms the host is current on security updates.

  Windows Update config     Req 6.3.3: How the host receives patches (automatic
                            update setting, WSUS server if used).

  Services                  Req 2.2.4, 2.2.5: Running/configured services with
                            start mode and run-as account — only necessary
                            services should be enabled.

  Scheduled tasks / startup Req 2.2.4: Scheduled tasks and startup items — review
                            for persistence and unnecessary automation.

  Hardening registry keys   Req 2.2: Current vs. recommended values for key CIS
                            hardening settings (SMBv1, RDP/NLA, UAC, LSA/NTLM,
                            autorun, inactivity lock).

  Defender / AV status      Req 5: Anti-malware deployed, active, and current
                            (real-time protection on, signature age).

  BitLocker status          Req 3: Disk encryption status per volume.

  Network exposure          Req 1.2, 2.2.4: Listening ports (attack surface),
                            active connections, and SMB shares (data exposure).

  Time synchronization      Req 10.6: Clock sync to a trusted time source so
                            audit timestamps are accurate and correlated.

  Group Policy result       For domain-joined hosts: effective policy after
                            domain GPOs apply (domain policy overrides local).

  MANIFEST + checksums      Chain-of-custody record with SHA-256 hash of every
                            file, plus a checksums.sha256 file for independent
                            verification.


REQUIREMENTS
------------
  On the COLLECTOR machine (where you run the script):
  - Windows PowerShell 5.1 OR PowerShell 7+ (either works).
  - NO external modules required. Every tool used is built into Windows
    (Get-LocalUser, Get-NetFirewall*, secedit, auditpol, netsh, Get-HotFix,
    Get-FileHash, w32tm, gpresult).

  For LOCAL collection:
  - Run in an ELEVATED (Administrator) PowerShell session. Without elevation,
    the following are skipped or incomplete and the script will warn you:
        - Security policy export (secedit)
        - Audit policy (auditpol)
        - Some firewall and registry detail
        - Group Policy result for computer settings

  For REMOTE collection (list of hosts):
  - PowerShell Remoting (WinRM) must be enabled on each TARGET. On a target:
        Enable-PSRemoting -Force
    (In a domain this is commonly enabled by GPO already.)
  - The collector must be able to reach the targets on TCP 5985 (HTTP) or
    5986 (HTTPS) — the WinRM ports.
  - You need credentials with LOCAL ADMINISTRATOR rights on each target. The
    remote session runs elevated automatically, so secedit/auditpol/gpresult
    all succeed. (There is no elevation prompt on the remote side.)
  - Targets not in the same domain (or by IP) may need the collector's
    TrustedHosts list updated, e.g.:
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "10.0.5.10,10.0.5.11"


BEFORE YOU RUN — EDIT THESE SETTINGS IN THE SCRIPT
---------------------------------------------------
Open windows-os-export.ps1 in Notepad or VS Code and update:

    $HostListFile = ""                     <-- path to a .txt file of hostnames,
                                               one per line. Leave "" for local only.
    $Hosts        = @()                    <-- OR list hosts inline, e.g.
                                               @("web01","web02","10.0.5.10")
                                               (used only if $HostListFile is "")
    $OutputBase   = "C:\windows-os-export" <-- where the run folder is created
    $UseCurrentCredential = $true          <-- $true = use your current account;
                                               $false = prompt once for credentials
                                               to use against all remote hosts

If both $HostListFile and $Hosts are empty, the script collects from the LOCAL
machine only.

HOST LIST FILE FORMAT
  One hostname or IP per line. Blank lines and lines starting with '#' are
  ignored. Example (hosts.txt):

      # Cardholder data environment — Windows servers
      WIN-SQL01
      WIN-APP01
      WIN-APP02
      10.0.5.20


RUNNING THE SCRIPT
------------------
  LOCAL collection:
    1. Right-click PowerShell and choose "Run as administrator".
    2. If script execution is blocked (common on hardened machines):
         Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    3. cd "C:\path\to\script"
    4. Leave $HostListFile / $Hosts empty, then run:
         .\windows-os-export.ps1

  REMOTE collection (many hosts):
    1. Create your host list file, e.g. C:\pci\hosts.txt
    2. Set $HostListFile = "C:\pci\hosts.txt" in the script.
    3. If not using your current account, set $UseCurrentCredential = $false.
    4. Open PowerShell (does NOT need to be elevated for remote-only runs) and:
         .\windows-os-export.ps1
    5. If prompted, enter credentials with admin rights on the targets.

  A successful multi-host run looks like:

       ========================================
         Windows OS Configuration Export (PCI DSS)
         Collector : ADMIN-WS01 (CORP\assessor)
         Targets   : 3  [WIN-SQL01, WIN-APP01, WIN-APP02]
         Output    : C:\windows-os-export\windows-os-run-20260726_143012
       ========================================

       ----------------------------------------
         Target: WIN-SQL01  (remote)
       ----------------------------------------
         Opening remoting session...              OK
           [ System information ]
             Host and OS details...                       OK (1 items, 0.9 KB)
           [ Local accounts and groups ]
             Local user accounts...                       OK (6 items, 2.1 KB)
             ... (all sections) ...
         Retrieving evidence (copy from host)...   OK
         Hashing evidence (SHA-256) + manifest...  OK (26 files)

       ----------------------------------------
         Target: WIN-APP01  (remote)
       ----------------------------------------
         ...

       ========================================
         Export complete.
         Hosts collected: 3 / 3
         Run folder     : C:\windows-os-export\windows-os-run-20260726_143012
       ========================================


RUN FOLDER LAYOUT
-----------------
  windows-os-run-<DATE>\
    RUN-SUMMARY.txt                         per-host status (OK/FAILED, file count)
    windows-os-WIN-SQL01-<DATE>\            one folder per target
        MANIFEST.txt                        chain-of-custody + SHA-256 hashes
        checksums.sha256                    verifiable hash list
        system-info.json, local-users.csv, ... (all evidence files below)
    windows-os-WIN-APP01-<DATE>\
        ...


OUTPUT FILES EXPLAINED
----------------------
All files saved in: windows-os-<HOSTNAME>-<DATE>_<TIME>
Example: C:\windows-os-export\windows-os-WIN-SQL01-20260726_143012

File                           What it contains and how to use it
---------------------------    -------------------------------------------------------
system-info.json               OS edition, build, domain membership, uptime, and who
                               collected the evidence and when.

local-users.csv                One row per local account. Key columns:
                                 Enabled            Is the account active?
                                 PasswordRequired   FALSE is a finding
                                 PasswordLastSet    Age of the current password
                                 PasswordExpires    Non-expiring passwords are a finding
                                 LastLogon          Identify stale/unused accounts
                               Open in Excel and filter Enabled = TRUE, then review
                               PasswordRequired = FALSE and blank PasswordExpires.

local-groups.json              Every local group with its members. Focus on
                               "Administrators" — the member list must match the
                               documented list of privileged users (Req 7.2).

password-lockout-policy.txt    Output of 'net accounts' (local and domain). Shows
                               minimum password length, maximum age, history, and
                               lockout threshold/duration/window.

security-policy.inf            Full local security policy from secedit. Sections:
                                 [System Access]    password + lockout + account rules
                                 [Privilege Rights] user rights assignments
                                 [Event Audit]      legacy audit categories
                               Requires the script to have run elevated.

audit-policy.txt / .csv        Advanced audit policy per subcategory (auditpol). Verify
                               Logon/Logoff, Account Management, Privilege Use, Policy
                               Change, and Object Access are set to Success and/or
                               Failure per Req 10.2. Requires elevation.

event-log-config.csv           Max size and overwrite policy per event log — confirms
                               logs are large enough and retained (Req 10.5).

firewall-profiles.json         Per-profile (Domain/Private/Public): Enabled (must be
                               True), DefaultInboundAction (should be Block), and log
                               settings. The primary firewall evidence file.

firewall-rules.csv             Every firewall rule: DisplayName, Direction, Action,
                               Enabled, Profile. Filter/sort in Excel.

firewall-rules-detailed.txt    Full rule detail including local/remote ports,
                               addresses, and programs (netsh verbose output).

firewall-config.txt            netsh summary of all three firewall profiles.

installed-software.csv         Installed applications with version and publisher.
                               Review for unsupported or unnecessary software (Req 6.3,
                               2.2). Sort by Publisher or DisplayName.

installed-hotfixes.csv         Applied OS patches with install date. Sort by
                               InstalledOn descending to confirm recent patching.

windows-update-config.json     Automatic update / WSUS configuration.

services.csv                   All services with State, StartMode, and StartName
                               (run-as account). Look for services running as
                               LocalSystem from non-standard paths, or unexpected
                               auto-start services (Req 2.2.4/2.2.5).

scheduled-tasks.csv            Scheduled tasks with run-as user and run level.

startup-programs.csv           Programs that launch at logon/boot.

hardening-registry.json        THE HARDENING SCORECARD. Each row lists the setting,
                               CurrentValue, Recommended value, and PCIReference.
                               Compare CurrentValue against Recommended:
                                 SMB1 = 0 or absent          (SMBv1 disabled)
                                 UserAuthentication = 1       (RDP NLA required)
                                 EnableLUA = 1                (UAC on)
                                 LmCompatibilityLevel = 5     (NTLMv2 only)
                                 NoLMHash = 1                 (no LM hash stored)
                                 RunAsPPL = 1                 (LSASS protected)
                               Any deviation is a hardening finding (Req 2.2).

defender-status.json           Microsoft Defender: AntivirusEnabled,
                               RealTimeProtectionEnabled, and signature age. Confirms
                               anti-malware is active and current (Req 5).

antivirus-products.json        Registered AV products (client OS only — absent on
                               Windows Server, where defender-status.json applies).

bitlocker-status.csv           Encryption status per volume (Req 3).

listening-ports.csv            Listening TCP ports with the owning process — the
                               host's network attack surface (Req 1.2, 2.2.4).

netstat.txt                    Full netstat -ano output (connections + PIDs).

smb-shares.csv                 SMB shares and their paths — review for unnecessary
                               data exposure.

time-sync.txt                  w32tm status, configuration, and peers — confirms the
                               clock syncs to a trusted source (Req 10.6).

gpresult.html                  Resultant Set of Policy for domain-joined hosts — the
                               effective policy after domain GPOs apply. Open in a
                               browser. Domain policy overrides local settings, so this
                               is the authoritative source on domain members.

checksums.sha256               SHA-256 hash of every evidence file, in the standard
                               "<hash> *<filename>" format.

MANIFEST.txt                   Chain-of-custody record: host, collection date/time
                               (local and UTC), collecting user, elevation status, and
                               the SHA-256 hash of every file.


VERIFYING EVIDENCE INTEGRITY
----------------------------
The assessor (or anyone) can confirm the files have not been altered since
collection using the hashes in the MANIFEST or checksums.sha256:

  Verify a single file's hash matches the MANIFEST:
    Windows : certutil -hashfile local-users.csv SHA256
    PowerShell: Get-FileHash local-users.csv -Algorithm SHA256

  Verify all files at once against checksums.sha256:
    Linux/macOS : sha256sum -c checksums.sha256
    (run from inside the export folder)

If any hash does not match, the file was modified after collection — do not
rely on it; re-collect from the source system.


HOW TO REVIEW THE FILES ON WINDOWS
-----------------------------------
  CSV files — open in Excel:
    - Data > From Text/CSV > select file > Load, then add filters.
    - local-users.csv: filter Enabled = TRUE, review PasswordRequired/expiry.
    - services.csv: sort by StartName to group by run-as account.

  JSON files — VS Code:
    - File > Open Folder > select the export folder.
    - Open any .json, press Shift+Alt+F to format.
    - hardening-registry.json: scan CurrentValue vs Recommended.

  gpresult.html — open in any web browser.

  .inf / .txt files — VS Code or Notepad++.


TROUBLESHOOTING
---------------
  Remote: "Opening remoting session... FAILED" / WinRM cannot complete
      PowerShell Remoting is not enabled or not reachable on the target. On the
      target run: Enable-PSRemoting -Force. Confirm TCP 5985/5986 is open. Test
      from the collector: Test-WSMan -ComputerName <host>.

  Remote: "Access is denied"
      The credentials lack local administrator rights on the target, or set
      $UseCurrentCredential = $false and supply an admin account.

  Remote: connecting by IP or to a non-domain host fails with a trust error
      Add the target to the collector's TrustedHosts list:
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<host-or-ip>"
      (append with -Concatenate; reset to "" after the assessment).

  "WARNING: Local collection requested but this session is not elevated"
      Only affects LOCAL collection. Close PowerShell and re-launch with "Run
      as administrator". Remote targets are unaffected (they run elevated).

  "Security policy (secedit export)... SKIPPED (not elevated)"
      Re-run elevated. The security-policy.inf file is the authoritative
      password/lockout/user-rights evidence and requires administrator rights.

  "Local user accounts... OK (0 items)" or fallback used
      The LocalAccounts module was unavailable; the script fell back to WMI,
      which omits PasswordLastSet/LastLogon. This is normal on some older or
      minimal installs — the account list is still complete.

  "Effective policy report (gpresult)... SKIPPED"
      Normal on standalone (non-domain) hosts — there is no domain policy to
      report. On domain members, ensure the script ran elevated.

  "Registered AV products (SecurityCenter2)... OK" with a Note
      SecurityCenter2 does not exist on Windows Server. Use defender-status.json
      (or your third-party AV console) for server anti-malware evidence.

  Firewall rules export is large
      Hosts with many rules produce a large firewall-rules-detailed.txt. This is
      expected — it contains full port/address/program detail per rule.


SECURITY NOTES
--------------
  - This export contains a full picture of each host's accounts, privileged
    group membership, services, installed software, and hardening posture.
    Treat the run folder as sensitive.

  - Apply NTFS permissions to restrict the run folder to your account.

  - For remote collection, evidence is written to a temporary folder on each
    target, copied back over the encrypted WinRM channel, and then deleted from
    the target. Nothing is left behind on the servers.

  - Do not hard-code credentials in the script. Use $UseCurrentCredential, or
    let the script prompt with Get-Credential (kept in memory only).

  - If you edited TrustedHosts to reach non-domain targets, reset it after the
    assessment:  Set-Item WSMan:\localhost\Client\TrustedHosts -Value ""

  - After the assessment: delete or securely archive the run folder. Its
    integrity hashes are in each MANIFEST, so archive them together.

================================================================================
