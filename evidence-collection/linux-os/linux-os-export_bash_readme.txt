================================================================================
  linux-os-export.sh  —  README
  Linux Operating System Configuration Export (Bash)
  Audience: Linux Administrator / Sysadmin
  PCI DSS 4.0.1 — System Hardening, Access Control, and Logging Controls
================================================================================

PURPOSE
-------
This script collects Linux host configuration evidence for PCI DSS system
hardening, access control, and logging control reviews. It is read-only and
makes NO changes to any system.

It can run two ways:
  - LOCAL   — collect from the machine the script is run on.
  - REMOTE  — collect from a list of hostnames (one per line in a text file)
              over SSH, from a single admin workstation. You do not have to
              log in to each server.

Each target gets its own timestamped evidence folder inside one run folder.
Every output file is hashed with SHA-256, and each host folder has its own
MANIFEST recording the collection date/time, the account used on the target,
whether it ran as root, the workstation that retrieved and hashed the bundle,
and every file's hash — so the assessor can verify the evidence has not been
altered since collection.

What is collected and why it matters for PCI DSS:

  System information        Context: distribution, kernel, uptime, and
                            virtualization for the host described by this
                            evidence set.

  Local user accounts       Req 8.2, 8.3: Every account with its password
                            status (set / locked / NO PASSWORD), last change
                            date, min/max age, warning period, expiry, and last
                            login. Used to find shared, stale, non-expiring, or
                            passwordless accounts.

  Groups and membership     Req 7.2: Every group with both its secondary member
                            list and its primary members (users whose passwd
                            GID points at the group). Primary membership is the
                            one most often missed in a least-privilege review.

  Privileged accounts       Req 7.2: UID 0 accounts, accounts with empty
                            passwords, members of root/wheel/sudo/adm/docker,
                            and every account with a real login shell.

  sudo configuration        Req 7.2: /etc/sudoers and /etc/sudoers.d, with
                            NOPASSWD entries called out separately — these
                            grant privilege escalation without re-authentication.

  Password policy           Req 8.3.4, 8.3.6, 8.3.7, 8.3.9: login.defs aging
                            rules, pwquality complexity settings, and per-account
                            chage output.

  PAM stack                 Req 8.3: The authentication, password, and account
                            module stacks that actually enforce policy —
                            login.defs alone does not tell the whole story.

  Account lockout           Req 8.3.4: pam_faillock / pam_tally2 configuration
                            (threshold and duration) and currently locked
                            accounts.

  Hardening scorecard       Req 2.2: Current vs. recommended values for SSH
                            server settings, password policy, and kernel
                            hardening sysctls, each with its PCI reference.
                            THE FILE TO READ FIRST.

  Kernel parameters         Req 2.2.6: Full sysctl -a output backing the
                            scorecard, plus loaded and blacklisted modules.

  SELinux / AppArmor        Req 2.2.6, 7.2: Mandatory access control status and
                            configured mode.

  auditd rules              Req 10.2, 10.3: The audit rules actually loaded
                            (auditctl -l), auditd.conf, and the rules.d files —
                            what administrative actions are being recorded.

  Logging configuration     Req 10.3.3, 10.5.1: rsyslog / syslog-ng / journald
                            config, remote log forwarding targets, logrotate
                            retention, journal disk usage, and /var/log
                            permissions.

  Firewall rules            Req 1.2, 1.3, 1.4: Every backend present —
                            firewalld, ufw, nftables, iptables, ip6tables —
                            plus TCP wrappers.

  Installed packages        Req 6.3.3, 2.2: Full package inventory with versions
                            and install dates, to review for unnecessary or
                            unsupported software.

  Patch status              Req 6.3.3: Outstanding updates (security updates
                            listed separately where the package manager supports
                            it), update history, automatic update configuration,
                            and whether a reboot is pending.

  Services and tasks        Req 2.2.4, 2.2.5: Every service with its boot state
                            and running state, the run-as user and command line
                            of each running service, cron jobs, and systemd
                            timers — only necessary services should be enabled.

  Network exposure          Req 1.2, 2.2.4: Listening ports with owning process,
                            interfaces, routes, established connections, and
                            NFS/Samba exports.

  SSH server configuration  Req 2.2.7, 8.2.2: Effective sshd configuration,
                            the config files, host key permissions, and the
                            authorized_keys entries per account.

  Anti-malware              Req 5.2, 5.3.2: Anti-malware service status and
                            signature age, plus a package-name sweep for common
                            endpoint agents.

  File integrity monitoring Req 11.5: AIDE / Tripwire / Samhain / Wazuh presence,
                            configuration, database age, scheduled runs, and
                            auditd file watch rules.

  Filesystems + encryption  Req 3.5: Mounts and their nodev/nosuid/noexec
                            options, fstab, block devices, LUKS status, and swap.

  SUID/SGID + permissions   Req 2.2, 7.2: SUID/SGID binaries, world-writable
                            files and directories, unowned files, and the
                            permissions on /etc/passwd, /etc/shadow, and sudoers.

  Time synchronization      Req 10.6: chrony / ntpd / timesyncd configuration
                            and sync state, so audit timestamps are accurate.

  Login history             Req 10.2.1: Current sessions, recent successful
                            logins, failed logins, and last login per account.

  Login banners             Req 2.2.4: /etc/issue, issue.net, motd, and the
                            SSH Banner directive.

  MANIFEST + checksums      Chain-of-custody record with SHA-256 hash of every
                            file, plus a checksums.sha256 file for independent
                            verification.


REQUIREMENTS
------------
  On the COLLECTOR machine (where you run the script):
  - bash, plus standard coreutils (tar, find, awk, sed, sha256sum).
    On macOS, shasum -a 256 is used automatically instead of sha256sum.
  - ssh, for remote collection only.
  - NO external packages or modules are required.

  On each TARGET:
  - bash and standard coreutils. Everything else the script uses is optional —
    if a tool is absent (auditd, firewalld, chrony, AIDE, …) the corresponding
    file records that it is not installed rather than failing.

  PRIVILEGES — this matters for evidence completeness:
  - Run as root, or with an account that has PASSWORDLESS sudo (the script uses
    "sudo -n" and never prompts).
  - Without root, the script still runs and clearly labels what it could not
    read, but the following are incomplete:
        - Password aging from /etc/shadow (shows "(no access to /etc/shadow)")
        - sudoers configuration
        - auditd rules and status
        - Firewall rules (all backends)
        - Effective SSH configuration (sshd -T)
        - faillock state and per-user crontabs
        - Failed login history (lastb)
  - The script warns on stderr at the start of each host when it is running
    unprivileged, so an incomplete collection is never silent.

  For REMOTE collection:
  - SSH access to each target. Key-based authentication (or ssh-agent) is
    strongly recommended — with password authentication you are prompted once
    per host.
  - Because the SSH session has no TTY, sudo CANNOT prompt for a password.
    For remote collection as a non-root user, the account must have NOPASSWD
    sudo, otherwise privileged evidence is skipped.


BEFORE YOU RUN — EDIT THESE SETTINGS IN THE SCRIPT
---------------------------------------------------
Open linux-os-export.sh in any text editor and update:

    HOST_LIST_FILE=""                  <-- path to a .txt file of hostnames,
                                           one per line. Leave "" for local only.
    HOSTS=()                           <-- OR list hosts inline, e.g.
                                           HOSTS=("web01" "web02" "10.0.5.10")
                                           (used only if HOST_LIST_FILE is "")
    OUTPUT_BASE="$HOME/linux-os-export" <-- where the run folder is created
    SSH_USER=""                        <-- blank uses your current username
    SSH_PORT="22"
    SSH_KEY=""                         <-- e.g. "$HOME/.ssh/id_ed25519"
    SSH_EXTRA_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
    USE_SUDO="auto"                    <-- "auto" uses root, else passwordless
                                           sudo. "no" collects unprivileged only.

If both HOST_LIST_FILE and HOSTS are empty, the script collects from the LOCAL
machine only.

HOST LIST FILE FORMAT
  One hostname or IP per line. Blank lines and anything after '#' are ignored.
  Example (hosts.txt):

      # Cardholder data environment — Linux servers
      app01.corp.local
      app02.corp.local
      db01.corp.local
      10.0.5.20


RUNNING THE SCRIPT
------------------
  LOCAL collection:
    1. chmod +x linux-os-export.sh
    2. Leave HOST_LIST_FILE / HOSTS empty.
    3. Run as root for a complete export:
         sudo ./linux-os-export.sh
       (Running without sudo works but produces an incomplete export — see
       PRIVILEGES above.)

  REMOTE collection (many hosts):
    1. Create your host list file, e.g. /home/you/pci/hosts.txt
    2. Set HOST_LIST_FILE="/home/you/pci/hosts.txt" in the script.
    3. Set SSH_USER / SSH_KEY if needed. Confirm the account is root or has
       NOPASSWD sudo on the targets.
    4. Run WITHOUT sudo on the collector — the privileges that matter are the
       ones on the targets:
         ./linux-os-export.sh

  How remote collection works:
    The script streams a copy of itself to the target over the SSH connection,
    runs it there in collection mode, and receives the finished evidence folder
    back as a tar stream. The temporary copy and the staging directory are
    always removed from the target. Nothing is left behind on the servers, and
    no files are written to them outside /tmp.

  A successful multi-host run looks like:

       ========================================
         Linux OS Configuration Export (PCI DSS)
         Collector : admin-ws01 (assessor)
         Targets   : 3  [app01 app02 db01]
         Output    : /home/you/linux-os-export/linux-os-run-20260727_143012
       ========================================

       ----------------------------------------
         Target: app01  (remote over SSH)
       ----------------------------------------
         Collecting over SSH...
           [ System information ]
             Host, OS, kernel, and uptime...                OK (4.2 KB)
           [ Accounts and groups ]
             Local user accounts...                         OK (9.9 KB)
             ... (all sections) ...
         Retrieving evidence (tar stream)...            OK
         Hashing evidence (SHA-256) + manifest...       OK (33 files)

       ========================================
         Export complete.
         Hosts collected: 3 / 3
       ========================================


RUN FOLDER LAYOUT
-----------------
  linux-os-run-<DATE>/
    RUN-SUMMARY.txt                     per-host status (OK/FAILED, file count)
    linux-os-app01-<DATE>/              one folder per target
        MANIFEST.txt                    chain-of-custody + SHA-256 hashes
        checksums.sha256                verifiable hash list
        hardening-checks.csv, local-users.csv, ... (all evidence files below)
    linux-os-app02-<DATE>/
        ...


OUTPUT FILES EXPLAINED
----------------------
All files saved in: linux-os-<HOSTNAME>-<DATE>_<TIME>
Example: /home/you/linux-os-export/linux-os-run-20260727_143012/linux-os-app01-20260727_143012

File                            What it contains and how to use it
----------------------------    ------------------------------------------------------
hardening-checks.csv            THE HARDENING SCORECARD — read this first. One row per
                                setting with Source, CurrentValue, Recommended, and
                                PCIReference. Any row where CurrentValue does not meet
                                Recommended is a candidate finding under Req 2.2.
                                Covers SSH server settings, password aging and quality,
                                account lockout, kernel hardening sysctls, mandatory
                                access control, host firewall, auditd, and time sync.

                                Read the Source column: "sshd -T (effective)" is the
                                configuration actually in force including compiled-in
                                defaults. "sshd_config (declared only)" means sshd -T
                                could not run, so options left at their default read
                                "(not set)" rather than their real value. Values that
                                could not be read at all say "(no access - re-run as
                                root)" — never confuse that with "not configured".

local-users.csv                 One row per account. Key columns:
                                  PasswordStatus     "NO PASSWORD SET" is a finding;
                                                     "locked" accounts cannot log in
                                  PasswordLastChange Age of the current password
                                  MaxDays            99999 = never expires (finding)
                                  AccountExpires     Blank/never on a leaver is a finding
                                  LastLogin          Identify stale/unused accounts
                                Open in a spreadsheet and sort by PasswordStatus.

local-groups.csv                Every group with SecondaryMembers (from /etc/group) and
                                PrimaryMembers (users whose passwd GID points here).
                                Check both columns for wheel/sudo/adm (Req 7.2).

privileged-accounts.txt         UID 0 accounts, empty-password accounts, privileged
                                group membership, accounts with a login shell, and
                                accounts that never expire — the least-privilege summary.

sudoers-config.txt              /etc/sudoers and /etc/sudoers.d with comments stripped,
                                plus every NOPASSWD entry called out. Each NOPASSWD rule
                                is privilege escalation without re-authentication.

password-policy.txt             /etc/login.defs, pwquality.conf, and chage -l per
                                interactive account (Req 8.3.4, 8.3.6, 8.3.9).

pam-config.txt                  The PAM stacks that actually enforce authentication and
                                password policy — system-auth, password-auth, common-*,
                                sshd, login, su, sudo.

account-lockout.txt             faillock.conf, the pam_faillock/pam_tally2 lines found in
                                /etc/pam.d, and currently locked accounts (Req 8.3.4).
                                "no lockout module configured" is a finding.

sysctl-all.txt                  Full kernel parameter dump backing the scorecard.

selinux-apparmor.txt            sestatus and /etc/selinux/config, or aa-status. Enforcing
                                (SELinux) or enabled (AppArmor) is expected (Req 2.2.6).

kernel-modules.txt              Loaded modules (lsmod) and blacklisted modules.

audit-rules.txt                 auditctl -l (the rules actually loaded right now),
                                auditctl -s, auditd.conf, and /etc/audit/rules.d.
                                Confirms admin actions are being logged (Req 10.2).

logging-config.txt              rsyslog / syslog-ng / journald configuration and the
                                remote forwarding targets. Req 10.3.3 expects logs to be
                                written to a system the host cannot alter.

log-retention.txt               logrotate configuration, journal disk usage, the oldest
                                journal entry, and /var/log permissions. Req 10.5.1
                                expects 12 months retention, 3 immediately available.

firewall-rules.txt              Every firewall backend present: firewalld zones, ufw
                                status, nftables ruleset, iptables/ip6tables save output,
                                and TCP wrappers (Req 1.2, 1.4).

installed-packages.csv          Full package inventory with version, vendor, and install
                                date. Review for unnecessary or unsupported software.

patch-status.txt                Outstanding updates (security updates listed separately
                                on dnf/yum), update history, automatic update settings,
                                and whether a reboot is pending (Req 6.3.3).

services.csv                    Every service with UnitFileState (enabled at boot),
                                LoadState, ActiveState, and SubState. Sort by
                                UnitFileState to review what starts automatically.

services-running-detail.txt     For each running service: the run-as User, ExecStart
                                command, and unit file path. Look for services running
                                as root from non-standard paths (Req 2.2.4/2.2.5).

cron-and-timers.txt             /etc/crontab, cron.d, the cron.* directories, per-user
                                crontabs, cron.allow/deny, and systemd timers.

listening-ports.csv             Listening TCP/UDP ports with address, port, and owning
                                process — the host's network attack surface (Req 1.2,
                                2.2.4). The Process column is only populated when the
                                collection ran as root.

network-config.txt              Interfaces, routes, /etc/hosts, DNS, established
                                connections, and NFS/Samba exports.

ssh-server-config.txt           Effective sshd configuration (sshd -T), the config files
                                including sshd_config.d, /etc/ssh permissions, and the
                                authorized_keys entries per account (Req 8.2.2).

antimalware.txt                 Anti-malware service status, ClamAV signature age, and a
                                package sweep for common endpoint agents (Req 5.2, 5.3.2).
                                "no common anti-malware service unit found" means you
                                must confirm coverage another way — it is not proof of
                                absence.

file-integrity-monitoring.txt   AIDE / Tripwire / Samhain / Wazuh / osquery presence,
                                AIDE configuration and database age, scheduled runs, and
                                auditd file watch rules (Req 11.5).

filesystems-and-encryption.txt  Mounts with their nodev/nosuid/noexec options, fstab,
                                block devices, LUKS status, and swap (Req 3.5).

suid-sgid-files.txt             Every SUID/SGID binary on local filesystems. Each one
                                runs with elevated privileges — review for unexpected
                                entries.

world-writable.txt              World-writable directories without the sticky bit,
                                world-writable files, unowned files, and the permissions
                                on /etc/passwd, /etc/shadow, /etc/group, and sudoers.

time-sync.txt                   chrony / ntpd / timesyncd configuration and sync state.
                                Audit timestamps are only meaningful if the clock is
                                synced to a trusted source (Req 10.6).

login-history.txt               Current sessions, recent successful logins, failed
                                logins (root only), and last login per account.

login-banners.txt               /etc/issue, issue.net, motd, and the SSH Banner directive.

system-info.txt                 Distribution, kernel, uptime, CPU/memory, virtualization,
                                and the identity of the collecting account.

collection-info.txt             Machine-readable collection metadata (host, distribution,
                                kernel, UTC timestamp, collecting account, whether it ran
                                as root). The MANIFEST header is built from this file.

checksums.sha256                SHA-256 hash of every evidence file, in the standard
                                "<hash> *<filename>" format.

MANIFEST.txt                    Chain-of-custody record: host, distribution, collection
                                time (UTC), the account used on the target, whether it
                                ran as root, who retrieved and hashed the bundle, and the
                                SHA-256 hash of every file.


VERIFYING EVIDENCE INTEGRITY
----------------------------
The assessor (or anyone) can confirm the files have not been altered since
collection using the hashes in the MANIFEST or checksums.sha256:

  Verify all files at once against checksums.sha256:
    Linux       : sha256sum -c checksums.sha256
    macOS       : shasum -a 256 -c checksums.sha256
    (run from inside the export folder)

  Verify a single file's hash matches the MANIFEST:
    Linux       : sha256sum local-users.csv
    Windows     : certutil -hashfile local-users.csv SHA256
    PowerShell  : Get-FileHash local-users.csv -Algorithm SHA256

If any hash does not match, the file was modified after collection — do not
rely on it; re-collect from the source system.


HOW TO REVIEW THE FILES
-----------------------
  CSV files — open in Excel or LibreOffice Calc:
    - hardening-checks.csv: read Source, then compare CurrentValue against
      Recommended row by row.
    - local-users.csv: sort by PasswordStatus, then review MaxDays and LastLogin.
    - services.csv: filter UnitFileState = enabled.
    - listening-ports.csv: sort by LocalPort.

  .txt files — any text editor, VS Code, or less:
    - VS Code: File > Open Folder on the export folder, then Ctrl+Shift+F to
      search across every host at once (useful for "which hosts have X").

  Reviewing many hosts:
    The run folder holds one folder per host with identical file names, so
    diffing two hosts is straightforward:
      diff linux-os-app01-*/hardening-checks.csv linux-os-app02-*/hardening-checks.csv


TROUBLESHOOTING
---------------
  I ran it with sudo and cannot find the output folder
      sudo resets HOME to /root on most distributions, so the default
      OUTPUT_BASE lands in /root/linux-os-export instead of your own home
      directory, and the files are owned by root. The script prints the
      resolved run folder ("Output : ...") at the start and end of every run.
      Set OUTPUT_BASE to an absolute path to control this, e.g.
        OUTPUT_BASE="/var/tmp/linux-os-export"
      To hand the evidence to a non-root account afterwards:
        sudo chown -R <user> /root/linux-os-export/linux-os-run-<DATE>

  "WARNING: not root and passwordless sudo is unavailable"
      The collection ran unprivileged. It still produced a full file set, but
      shadow aging, sudoers, audit rules, firewall rules, and effective SSH
      configuration are labelled "(no access ...)". Re-run as root, or grant
      the collecting account NOPASSWD sudo, for complete evidence.

  Remote: "SSH collection FAILED for <host>"
      Test the connection by hand:
        ssh -p <port> <user>@<host> "echo ok"
      Check the key, the port, and that the account is not blocked by
      AllowUsers / AllowGroups on the target.

  Remote: host key prompt or "Host key verification failed"
      The default SSH_EXTRA_OPTS uses StrictHostKeyChecking=accept-new, which
      accepts unknown hosts but still refuses CHANGED keys. If your OpenSSH is
      older than 7.6, change it to StrictHostKeyChecking=no, or pre-populate
      known_hosts with ssh-keyscan.

  Remote: the export is incomplete even though the account can sudo
      SSH sessions here have no TTY, so sudo cannot prompt for a password. The
      account needs NOPASSWD sudo, or collect as root.

  Remote: "could not unpack evidence bundle"
      Something on the target wrote to stdout and corrupted the tar stream —
      most often a shell profile (.bashrc / .profile) that echoes a banner on
      non-interactive logins. Move that output to stderr or guard it with a
      check for an interactive shell.

  "SUID / SGID binaries..." or "World-writable files..." takes a long time
      These walk every local filesystem. They are capped at 300 seconds each
      where the "timeout" command is available. Network filesystems are already
      excluded (find -xdev).

  Target host shows as "unknown"
      The host has no hostname binary and uname could not resolve a name either.
      Set a hostname on the target so the evidence identifies its source.

  "(no data)" next to a section
      The command produced no output on that host — usually because the
      subsystem is not installed. The file itself records what was missing.


SECURITY NOTES
--------------
  - This export contains a full picture of each host's accounts, privileged
    group membership, services, installed software, network exposure, and
    hardening posture. Treat the run folder as sensitive.

  - Password HASHES are never collected. The script reads /etc/shadow only to
    derive password status and aging metadata; no hash is written to any file.

  - Restrict the run folder to your account:
        chmod -R go-rwx <run folder>

  - For remote collection, evidence is written to a temporary directory on each
    target, streamed back over the encrypted SSH channel, and then deleted from
    the target along with the temporary copy of the script.

  - Do not hard-code passwords in the script. Use SSH keys or ssh-agent.

  - After the assessment: delete or securely archive the run folder. Its
    integrity hashes are in each MANIFEST, so archive them together.

================================================================================
