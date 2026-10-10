================================================================================
  macos-os-export.sh  —  README
  macOS Configuration Export (Bash)
  Audience: Mac Administrator / Sysadmin
  PCI DSS 4.0.1 — System Hardening, Access Control, and Logging Controls
================================================================================

PURPOSE
-------
This script collects macOS configuration evidence for PCI DSS system hardening,
access control, and logging control reviews. It is read-only and makes NO
changes to any system.

It can run two ways:
  - LOCAL   — collect from the Mac the script is run on.
  - REMOTE  — collect from a list of hostnames (one per line in a text file)
              over SSH, from a single admin Mac. You do not have to log in to
              each machine.

Each target gets its own timestamped evidence folder inside one run folder.
Every output file is hashed with SHA-256, and each host folder has its own
MANIFEST recording the collection date/time, the account used on the target,
whether it ran as root, the workstation that retrieved and hashed the bundle,
and every file's hash — so the assessor can verify the evidence has not been
altered since collection.

Written for the bash 3.2 and BSD userland that ship with macOS. Nothing needs
to be installed on either the collector or the targets.

What is collected and why it matters for PCI DSS:

  System information        Context: macOS version and build, hardware model,
                            serial number, and uptime for the host described by
                            this evidence set.

  Local user accounts       Req 8.2, 8.3: Every account from Directory Services
                            with UID, admin rights, hidden status, password last
                            set date, failed login count, secure token status,
                            and last login. Used to find shared, stale, or
                            over-privileged accounts.

  Groups and membership     Req 7.2: Every group with its members and nested
                            groups. The admin group is the core of a
                            least-privilege review on macOS.

  Privileged accounts       Req 7.2: admin and wheel members, UID 0 accounts,
                            whether the root account is enabled, the
                            com.apple.access_ssh group, FileVault-enabled users,
                            and secure token holders.

  sudo configuration        Req 7.2: /etc/sudoers and /etc/sudoers.d with every
                            NOPASSWD entry called out, plus Touch ID for sudo.

  Password policy           Req 8.3.4, 8.3.6, 8.3.7, 8.3.9: Global and per-user
                            account policies from pwpolicy, and any password
                            policy delivered by configuration profile.

  Screen lock               Req 8.2.8: Screen saver idle time, whether a password
                            is required on wake, and the delay before it is
                            demanded. Also automatic login, which is a finding
                            whenever it is set.

  FileVault                 Req 3.5.1: Whole-disk encryption status, which users
                            can unlock the volume, whether an institutional
                            recovery key exists, and per-volume APFS state.

  Application Firewall      Req 1.2, 1.4: Global state, block-all mode, stealth
                            mode, logging, and the per-application exception
                            list. The pf packet filter is captured too.

  Platform security         Req 2.2.6, 5.2, 11.5: System Integrity Protection,
                            Gatekeeper assessment state, XProtect and MRT
                            versions, secure boot policy, third-party kernel
                            extensions, and system extensions.

  Configuration profiles    Req 2.2: Installed configuration profiles and MDM
                            enrolment state. Where a profile enforces a control,
                            the profile is the authoritative evidence — it
                            overrides local preferences.

  Installed software        Req 6.3.3, 2.2: Applications with version and code
                            signing state, package receipts, install history,
                            and Homebrew packages if present.

  Patch status              Req 6.3.3: Available updates from Apple, the
                            automatic update settings, the update schedule, and
                            the last successful check.

  launchd services          Req 2.2.4, 2.2.5: Every loaded job plus the contents
                            of the LaunchDaemons and LaunchAgents directories,
                            with Apple and third-party items distinguished.

  Sharing services          Req 2.2.4: Remote Login, Remote Apple Events, Screen
                            Sharing, File Sharing, per-user login items, and
                            disabled launchd jobs.

  Network exposure          Req 1.2, 2.2.4: Listening TCP/UDP ports with owning
                            process, interfaces, routes, DNS, proxies, and
                            established connections.

  SSH server configuration  Req 2.2.7, 8.2.2: Effective sshd configuration, the
                            config files, whether SSH access is restricted to a
                            group, and authorized_keys per account.

  Unified logging           Req 10.2: Logging mode, log store size,
                            newsyslog rotation, legacy ASL configuration, and
                            any log-shipping agent installed.

  OpenBSM audit             Req 10.2: audit_control flags and retention,
                            per-user audit flags, auditd state, and the audit
                            trail files.

  Login history             Req 10.2.1: Current sessions, recent logins, failed
                            authentication attempts, and sudo usage from the
                            unified log.

  Anti-malware              Req 5.2, 5.3.2: Built-in protections (Gatekeeper,
                            SIP, XProtect version) and detection of common
                            third-party endpoint agents.

  File integrity            Req 11.5: Dedicated FIM tooling if present, plus SIP
                            and authenticated-root as the platform's own
                            integrity controls.

  Filesystems               Req 3.5, 7.2: Mounts, disk usage, SUID/SGID
                            binaries, world-writable directories, and the
                            permissions on key files and home directories.

  Time synchronization      Req 10.6: Whether network time is on, which server
                            is configured, and the time zone.

  Login banners             Req 2.2.4: The login window message, motd, SSH
                            banner, and any PolicyBanner.

  MANIFEST + checksums      Chain-of-custody record with SHA-256 hash of every
                            file, plus a checksums.sha256 file for independent
                            verification.


REQUIREMENTS
------------
  On the COLLECTOR machine (where you run the script):
  - macOS with its stock bash 3.2, or any Linux with bash — both work.
  - ssh, for remote collection only.
  - NO external packages. shasum is used for hashing on macOS; sha256sum is
    used automatically where it exists instead.

  On each TARGET:
  - macOS. Everything the script calls is optional — if a tool is absent on a
    given macOS version, the corresponding file records that rather than failing.

  PRIVILEGES — this matters for evidence completeness:
  - Run as root, or with an account that has PASSWORDLESS sudo (the script uses
    "sudo -n" and never prompts).
  - Without root, the script still runs and clearly labels what it could not
    read, but the following are incomplete:
        - systemsetup values (Remote Login, network time) — all show
          "(requires root)"
        - FileVault user list and institutional recovery key
        - Application Firewall detail and pf rules
        - OpenBSM audit configuration
        - Effective SSH configuration (sshd -T)
        - Configuration profiles and MDM enrolment
        - Failed authentication and sudo events from the unified log
  - The script warns on stderr at the start of each host when it is running
    unprivileged, so an incomplete collection is never silent.

  For REMOTE collection:
  - Remote Login must be enabled on each target:
      System Settings > General > Sharing > Remote Login
  - Key-based authentication is strongly recommended — with password
    authentication you are prompted once per host.
  - Because the SSH session has no TTY, sudo CANNOT prompt for a password. For
    remote collection as a non-root user, the account must have NOPASSWD sudo,
    otherwise privileged evidence is skipped.


BEFORE YOU RUN — EDIT THESE SETTINGS IN THE SCRIPT
---------------------------------------------------
Open macos-os-export.sh in any text editor and update:

    HOST_LIST_FILE=""                   <-- path to a .txt file of hostnames,
                                            one per line. Leave "" for local only.
    HOSTS=()                            <-- OR list hosts inline, e.g.
                                            HOSTS=("mac01" "mac02" "10.0.5.10")
                                            (used only if HOST_LIST_FILE is "")
    OUTPUT_BASE="$HOME/macos-os-export" <-- where the run folder is created
    SSH_USER=""                         <-- blank uses your current username
    SSH_PORT="22"
    SSH_KEY=""                          <-- e.g. "$HOME/.ssh/id_ed25519"
    SSH_EXTRA_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
    USE_SUDO="auto"                     <-- "auto" uses root, else passwordless
                                            sudo. "no" collects unprivileged only.
    CHECK_FOR_UPDATES="yes"             <-- "softwareupdate --list" contacts
                                            Apple and can take 30-60s per host.
                                            Set to "no" to skip it.

If both HOST_LIST_FILE and HOSTS are empty, the script collects from the LOCAL
machine only.

HOST LIST FILE FORMAT
  One hostname or IP per line. Blank lines and anything after '#' are ignored.
  Example (macs.txt):

      # Cardholder data environment — Macs
      finance-mbp-01.corp.local
      finance-mbp-02.corp.local
      10.0.5.31


RUNNING THE SCRIPT
------------------
  LOCAL collection:
    1. chmod +x macos-os-export.sh
    2. Leave HOST_LIST_FILE / HOSTS empty.
    3. Run as root for a complete export:
         sudo ./macos-os-export.sh
       (Running without sudo works but produces an incomplete export — see
       PRIVILEGES above.)

  REMOTE collection (many Macs):
    1. Create your host list file, e.g. ~/pci/macs.txt
    2. Set HOST_LIST_FILE="/Users/you/pci/macs.txt" in the script.
    3. Set SSH_USER / SSH_KEY if needed. Confirm the account is root or has
       NOPASSWD sudo on the targets.
    4. Run WITHOUT sudo on the collector — the privileges that matter are the
       ones on the targets:
         ./macos-os-export.sh

  How remote collection works:
    The script streams a copy of itself to the target over the SSH connection,
    runs it there in collection mode, and receives the finished evidence folder
    back as a tar stream. The temporary copy and the staging directory are
    always removed from the target. Nothing is left behind, and no files are
    written to the target outside /tmp.

  A successful run looks like:

       ========================================
         macOS Configuration Export (PCI DSS)
         Collector : admin-mac (assessor)
         Targets   : 2  [finance-mbp-01 finance-mbp-02]
         Output    : /Users/you/macos-os-export/macos-os-run-20260727_143012
       ========================================

       ----------------------------------------
         Target: finance-mbp-01  (remote over SSH)
       ----------------------------------------
         Collecting over SSH...
           [ System information ]
             macOS version, hardware, and uptime...         OK (0.7 KB)
           [ Accounts and groups ]
             Local user accounts...                         OK (1.0 KB)
             ... (all sections) ...
         Retrieving evidence (tar stream)...            OK
         Hashing evidence (SHA-256) + manifest...       OK (30 files)

       ========================================
         Export complete.
         Hosts collected: 2 / 2
       ========================================


RUN FOLDER LAYOUT
-----------------
  macos-os-run-<DATE>/
    RUN-SUMMARY.txt                        per-host status (OK/FAILED, file count)
    macos-os-finance-mbp-01-<DATE>/        one folder per target
        MANIFEST.txt                       chain-of-custody + SHA-256 hashes
        checksums.sha256                   verifiable hash list
        hardening-checks.csv, local-users.csv, ... (all evidence files below)
    macos-os-finance-mbp-02-<DATE>/
        ...


OUTPUT FILES EXPLAINED
----------------------
All files saved in: macos-os-<HOSTNAME>-<DATE>_<TIME>

File                            What it contains and how to use it
----------------------------    ------------------------------------------------------
hardening-checks.csv            THE HARDENING SCORECARD — read this first. One row per
                                setting with Source, CurrentValue, Recommended, and
                                PCIReference. Any row where CurrentValue does not meet
                                Recommended is a candidate finding under Req 2.2.
                                Covers FileVault, SIP, Gatekeeper, XProtect, the
                                Application Firewall, sharing services, screen lock,
                                guest access, password policy, software update settings,
                                OpenBSM audit, time sync, SSH, and MDM enrolment.

                                Read the Source column. "sshd -T (effective)" is the
                                configuration actually in force including compiled-in
                                defaults; "sshd_config (declared only)" means sshd -T
                                could not run, so options left at their default read
                                "(not set)" rather than their real value. Values that
                                could not be read say "(no access - re-run as root)" or
                                "(requires root)" — never read those as "not configured".

local-users.csv                 One row per account. Key columns:
                                  IsAdmin           Membership of the admin group
                                  IsHidden          Accounts hidden from the login window
                                  PasswordLastSet   Age of the current password
                                  FailedLoginCount  Non-zero may indicate attacks
                                  SecureToken       Needed to unlock FileVault
                                  LastLogin         Identify stale/unused accounts
                                Open in a spreadsheet and filter IsAdmin = yes.

local-groups.csv                Every group with its members and nested groups. Focus on
                                admin, wheel, and com.apple.access_ssh (Req 7.2).

privileged-accounts.txt         admin/wheel membership, UID 0 accounts, whether root is
                                enabled, the SSH access group, FileVault-enabled users,
                                and secure token holders — the least-privilege summary.

sudoers-config.txt              /etc/sudoers and /etc/sudoers.d with comments stripped,
                                every NOPASSWD entry called out, and Touch ID for sudo.

password-policy.txt             Global and per-user pwpolicy account policies, and any
                                password policy delivered by configuration profile.

screen-lock-and-loginwindow.txt Screen saver idle time, password-on-wake settings, guest
                                account state, and automatic login. NOTE: screen saver
                                settings are PER-USER; the file reports the console
                                user's values and says so. On a multi-user Mac, confirm
                                the control is enforced by profile for all users.

filevault-and-volumes.txt       FileVault status, enabled users, institutional recovery
                                key, and per-volume APFS encryption state (Req 3.5.1).

platform-security.txt           SIP, Gatekeeper, secure boot, XProtect/MRT versions,
                                third-party kernel extensions, and system extensions.

configuration-profiles.txt      Installed profiles and MDM enrolment. Settings delivered
                                by profile OVERRIDE local preferences, so where a profile
                                enforces a control this file is the authoritative evidence.

firewall-rules.txt              Application Firewall global state, block-all, stealth
                                mode, logging, per-app exceptions, and pf (Req 1.2, 1.4).

listening-ports.csv             Listening TCP/UDP ports with address, port, process, PID,
                                and user (Req 1.2, 2.2.4). The process columns are only
                                fully populated when the collection ran as root.

network-config.txt              Interfaces, routes, network service order, DNS, proxies,
                                hardware ports, and established connections.

ssh-server-config.txt           Remote Login state, effective sshd configuration, the
                                config files, whether SSH is restricted to a group, and
                                authorized_keys per account (Req 8.2.2).

launchd-services.csv            Every loaded launchd job plus the LaunchDaemons and
                                LaunchAgents directory contents, with Apple and
                                third-party items distinguished (Req 2.2.4).

sharing-and-login-items.txt     Remote Login, Remote Apple Events, Screen Sharing, File
                                Sharing, disabled jobs, third-party daemons, per-user
                                login items, and legacy startup items.

installed-applications.csv      Applications in /Applications with version and whether
                                they are code signed. Review for unnecessary or
                                unsupported software (Req 6.3.3, 2.2).

installed-packages.txt          Package receipts (pkgutil), macOS install history, and
                                Homebrew packages if present.

patch-status.txt                Available updates from Apple, automatic update settings,
                                the update schedule, and the last successful check
                                (Req 6.3.3).

logging-config.txt              Unified logging mode, log store size, newsyslog rotation,
                                legacy ASL config, and any log-shipping agent.

audit-config.txt                OpenBSM audit_control flags and retention, per-user audit
                                flags, auditd state, and the audit trail files (Req 10.2).

login-history.txt               Current sessions, console user, recent logins, failed
                                authentication attempts, and sudo usage (Req 10.2.1).

antimalware.txt                 Gatekeeper, SIP, XProtect version, and detection of common
                                third-party endpoint agents (Req 5.2, 5.3.2). No match
                                here is not proof that none is installed — confirm coverage
                                another way.

file-integrity-monitoring.txt   FIM tooling if present, plus SIP and authenticated-root.
                                Note that SIP protects system binaries but does NOT monitor
                                application or data directories, so it only partly answers
                                Req 11.5.

suid-sgid-files.txt             SUID/SGID binaries on both the system and data volumes
                                (macOS splits them into separate mounts).

world-writable.txt              World-writable directories without the sticky bit, key
                                file permissions with ACLs (ls -le), and home directory
                                permissions.

time-sync.txt                   Network time state, configured server, time zone, and the
                                timed daemon (Req 10.6).

login-banners.txt               Login window message, motd, SSH banner, and PolicyBanner
                                (Req 2.2.4).

system-info.txt                 macOS version and build, hostnames, hardware model and
                                serial, uptime, boot volume, and the collecting account.

collection-info.txt             Machine-readable collection metadata. The MANIFEST header
                                is built from this file.

checksums.sha256                SHA-256 hash of every evidence file, in the standard
                                "<hash> *<filename>" format.

MANIFEST.txt                    Chain-of-custody record: host, computer name, macOS
                                version and build, hardware model, collection time (UTC),
                                the account used on the target, whether it ran as root,
                                who retrieved and hashed the bundle, and every file's hash.


VERIFYING EVIDENCE INTEGRITY
----------------------------
The assessor (or anyone) can confirm the files have not been altered since
collection using the hashes in the MANIFEST or checksums.sha256:

  Verify all files at once against checksums.sha256:
    macOS       : shasum -a 256 -c checksums.sha256
    Linux       : sha256sum -c checksums.sha256
    (run from inside the export folder)

  Verify a single file's hash matches the MANIFEST:
    macOS       : shasum -a 256 local-users.csv
    Windows     : certutil -hashfile local-users.csv SHA256
    PowerShell  : Get-FileHash local-users.csv -Algorithm SHA256

If any hash does not match, the file was modified after collection — do not
rely on it; re-collect from the source system.


HOW TO REVIEW THE FILES
-----------------------
  CSV files — open in Numbers or Excel:
    - hardening-checks.csv: read Source, then compare CurrentValue against
      Recommended row by row.
    - local-users.csv: filter IsAdmin = yes, then review PasswordLastSet.
    - launchd-services.csv: filter Scope = third-party.
    - listening-ports.csv: sort by LocalPort.

  .txt files — any text editor, VS Code, or less.

  Reviewing many Macs:
    The run folder holds one folder per host with identical file names, so
    diffing two Macs is straightforward:
      diff macos-os-mac01-*/hardening-checks.csv macos-os-mac02-*/hardening-checks.csv


TROUBLESHOOTING
---------------
  I ran it with sudo and cannot find the output folder
      sudo sets HOME to /var/root, so the default OUTPUT_BASE lands in
      /var/root/macos-os-export and the files are owned by root. The script
      prints the resolved run folder ("Output : ...") at the start and end of
      every run. Set OUTPUT_BASE to an absolute path to control this. To hand
      the evidence to your own account afterwards:
        sudo chown -R $(whoami) /var/root/macos-os-export/macos-os-run-<DATE>

  "WARNING: not root and passwordless sudo is unavailable"
      The collection ran unprivileged. It still produced a full file set, but
      systemsetup values, FileVault detail, firewall detail, audit settings and
      profiles are labelled "(requires root)". Re-run with sudo.

  Values are empty or permission-denied
      Re-run as root (sudo ./macos-os-export.sh), or on remote targets confirm
      the account is root or has NOPASSWD sudo. See PRIVILEGES above.

  Remote: "SSH collection FAILED for <host>"
      Confirm Remote Login is enabled on the target (System Settings > General >
      Sharing > Remote Login) and test by hand:
        ssh -p <port> <user>@<host> "echo ok"
      If Remote Login is restricted to specific users, the account must be in
      the com.apple.access_ssh group.

  Remote: "could not unpack evidence bundle"
      Something on the target wrote to stdout and corrupted the tar stream —
      most often a shell profile (.zshrc / .bash_profile) that echoes a banner
      on non-interactive logins. Move that output to stderr or guard it with a
      check for an interactive shell.

  The run is slow
      "softwareupdate --list" contacts Apple's servers and often takes 30-60
      seconds per host. Set CHECK_FOR_UPDATES="no" to skip it. The SUID and
      world-writable scans walk both volumes and are capped at 300 seconds each
      where the "timeout" command is available (it is not part of stock macOS,
      so on an unmodified Mac they run uncapped).

  Screen lock values look wrong for some users
      Screen saver settings are per-user preferences. The script reports the
      console user's values. On shared Macs, enforce the setting by
      configuration profile and use configuration-profiles.txt as the evidence.

  "(XProtect bundle not found at either standard path)"
      Apple has moved this bundle between releases. Check the macOS version in
      system-info.txt and confirm XProtect state from the MDM console instead.


SECURITY NOTES
--------------
  - This export contains a full picture of each Mac's accounts, admin rights,
    services, installed software, network exposure, and hardening posture.
    Treat the run folder as sensitive.

  - Password hashes are never collected. Password age comes from the
    accountPolicyData metadata, not from any credential store.

  - Restrict the run folder to your account:
        chmod -R go-rwx <run folder>

  - For remote collection, evidence is written to a temporary directory on each
    target, streamed back over the encrypted SSH channel, and then deleted from
    the target along with the temporary copy of the script.

  - Do not hard-code passwords in the script. Use SSH keys or ssh-agent.

  - After the assessment: delete or securely archive the run folder. Its
    integrity hashes are in each MANIFEST, so archive them together.

================================================================================
