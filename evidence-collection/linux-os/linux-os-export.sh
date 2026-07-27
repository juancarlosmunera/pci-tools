#!/usr/bin/env bash
#
# linux-os-export.sh — Linux host configuration export for PCI DSS assessment
#
# Collects Linux operating system configuration evidence relevant to PCI DSS
# system hardening, access control, and logging control reviews. Runs against
# the local machine, or against a list of hosts (one hostname per line in a
# text file) over SSH from a single admin workstation — no need to log in to
# each server.
#
# For every target it collects:
#   - System information (distribution, kernel, uptime, virtualization)
#   - Local user accounts with password aging metadata (/etc/passwd + shadow)
#   - Groups, privileged group membership, and sudoers configuration
#   - Password quality / aging policy (login.defs, pwquality, PAM)
#   - Account lockout configuration (pam_faillock / pam_tally2)
#   - auditd rules and configuration; syslog/journald logging and retention
#   - Firewall rules (nftables, iptables, firewalld, ufw)
#   - Installed packages, available security updates, and patch history
#   - systemd services, timers, and cron jobs
#   - Listening ports, network configuration, and SSH server hardening
#   - SELinux / AppArmor status and kernel hardening sysctls
#   - Anti-malware and file integrity monitoring tooling
#   - Filesystem mounts, encryption, SUID/SGID and world-writable files
#   - Time synchronization, login history, and login banners
#   - A hardening scorecard comparing current vs. recommended values
#
# Each host gets its own timestamped evidence folder under a single run folder.
# Every file is hashed with SHA-256 and recorded in a per-host MANIFEST for
# chain-of-custody and integrity verification, plus a checksums.sha256 file
# that an assessor can verify independently.
#
# This script is READ-ONLY. It makes no changes to any target system.
#
# See linux-os-export_bash_readme.txt for full instructions.

# ==============================================================================
# CONFIG — update these before running
# ==============================================================================

# Path to a text file with one hostname (or IP) per line. Lines that are blank
# or start with '#' are ignored. Leave "" to collect from the local machine only.
HOST_LIST_FILE=""

# Alternatively, list hosts inline here (used only if HOST_LIST_FILE is blank).
# Leave empty to collect from the local machine.
HOSTS=()

# Where to create the run folder on THIS (collector) machine.
# NOTE: when you run this with sudo, most distributions reset HOME to /root, so
# the default lands in /root/linux-os-export and the files are root-owned. Set
# an absolute path here if you want the evidence somewhere else. Either way the
# script prints the resolved run folder at the start and end of every run.
OUTPUT_BASE="$HOME/linux-os-export"

# SSH settings for remote targets. Leave SSH_USER blank to use your current
# username. Key-based authentication (or ssh-agent) is strongly recommended;
# with password authentication you are prompted once per host.
SSH_USER=""
SSH_PORT="22"
SSH_KEY=""            # e.g. "$HOME/.ssh/id_ed25519" — leave "" for the default
SSH_EXTRA_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

# Privilege escalation on the target. "auto" uses root directly if the account
# is root, otherwise tries passwordless sudo (sudo -n). "no" collects only what
# an unprivileged account can read.
USE_SUDO="auto"       # auto | no
# ==============================================================================


# ==============================================================================
# COLLECTION — everything below runs ON THE TARGET
# Progress goes to stderr so that in remote mode stdout carries only the
# evidence tarball. Hashing and the MANIFEST are produced by the collector
# after the folder is retrieved, so hashes cover the assembled bundle.
# ==============================================================================

EXPORT_DIR=""     # set by collect_evidence
IS_ROOT="no"
SUDO_OK="no"

have() { command -v "$1" >/dev/null 2>&1; }

# Host identity, used for folder names and the MANIFEST. The `hostname` binary
# is absent on minimal and container images, so fall back to uname and to the
# kernel's own value — evidence that cannot name its source host is not much
# use in a chain-of-custody record.
host_name() {
    local h
    h=$(hostname -s 2>/dev/null)
    [ -n "$h" ] || h=$(uname -n 2>/dev/null | cut -d. -f1)
    [ -n "$h" ] || h=$(cut -d. -f1 /proc/sys/kernel/hostname 2>/dev/null)
    [ -n "$h" ] || h="unknown"
    printf '%s' "$h"
}

host_fqdn() {
    local h
    h=$(hostname -f 2>/dev/null)
    [ -n "$h" ] || h=$(uname -n 2>/dev/null)
    [ -n "$h" ] || h=$(cat /proc/sys/kernel/hostname 2>/dev/null)
    [ -n "$h" ] || h="unknown"
    printf '%s' "$h"
}

# Run a command with root privileges if we have them, else fail quietly (126)
# so the caller can record the item as unavailable rather than crash.
priv() {
    if [ "$IS_ROOT" = "yes" ]; then "$@"; return $?; fi
    if [ "$SUDO_OK" = "yes" ]; then sudo -n "$@"; return $?; fi
    return 126
}

_label() { printf '    %-46s' "$1..." >&2; }
_done()  { printf ' %s\n' "$1" >&2; }
_head()  { printf '  [ %s ]\n' "$1" >&2; }

file_kb() {
    local bytes
    bytes=$(wc -c < "$1" 2>/dev/null || echo 0)
    awk -v b="$bytes" 'BEGIN { printf "%.1f", b/1024 }'
}

# Quote every field so commas and quotes inside values cannot break the CSV.
csv() {
    local out="" f
    for f in "$@"; do
        f=${f//\"/\"\"}
        out="${out}\"${f}\","
    done
    printf '%s\n' "${out%,}"
}

# cap <label> <output file> <shell body>
# Runs the body, writing stdout+stderr to the output file. A non-zero exit is
# not treated as failure — several tools (dnf check-update, ufw when inactive)
# exit non-zero as a normal result and their output is still evidence.
cap() {
    local label="$1" file="$2" body="$3"
    local path="$EXPORT_DIR/$file"
    _label "$label"
    eval "$body" > "$path" 2>&1
    if [ -s "$path" ]; then
        _done "OK ($(file_kb "$path") KB)"
    else
        printf '# No output produced on this host.\n' > "$path"
        _done "OK (no data)"
    fi
}

# ------------------------------------------------------------------------------
# Structured emitters — used by cap for the CSV outputs. These are functions
# rather than inline bodies so their awk/quoting stays readable.
# ------------------------------------------------------------------------------

# One row per local account, joining /etc/passwd with /etc/shadow aging data.
# Reading /etc/shadow needs root; without it the aging columns show "(no access)".
emit_users_csv() {
    local shadow_tmp lastlog_tmp
    shadow_tmp=$(mktemp) ; lastlog_tmp=$(mktemp)
    priv cat /etc/shadow > "$shadow_tmp" 2>/dev/null || : > "$shadow_tmp"
    # lastlog was dropped from shadow-utils on newer distros in favour of lastlog2
    if have lastlog; then
        lastlog 2>/dev/null | tail -n +2 > "$lastlog_tmp" || : > "$lastlog_tmp"
    elif have lastlog2; then
        lastlog2 2>/dev/null | tail -n +2 > "$lastlog_tmp" || : > "$lastlog_tmp"
    else
        : > "$lastlog_tmp"
    fi

    csv "Username" "UID" "GID" "Comment" "HomeDirectory" "Shell" \
        "PasswordStatus" "PasswordLastChange" "MinDays" "MaxDays" "WarnDays" \
        "InactiveDays" "AccountExpires" "LastLogin"

    local name pw uid gid gecos home shell
    local sline hash lastchg mind maxd warnd inact expire status lastlogin
    while IFS=: read -r name pw uid gid gecos home shell; do
        [ -n "$name" ] || continue

        sline=$(awk -F: -v n="$name" '$1 == n { print; exit }' "$shadow_tmp")
        if [ -n "$sline" ]; then
            hash=$(printf '%s' "$sline"    | cut -d: -f2)
            lastchg=$(printf '%s' "$sline" | cut -d: -f3)
            mind=$(printf '%s' "$sline"    | cut -d: -f4)
            maxd=$(printf '%s' "$sline"    | cut -d: -f5)
            warnd=$(printf '%s' "$sline"   | cut -d: -f6)
            inact=$(printf '%s' "$sline"   | cut -d: -f7)
            expire=$(printf '%s' "$sline"  | cut -d: -f8)

            # The hash field tells us whether the account can authenticate.
            case "$hash" in
                "")       status="NO PASSWORD SET (finding)" ;;
                "!"|"!!"|"*"|"x") status="locked / no password login" ;;
                "!"*)     status="locked" ;;
                "*"*)     status="no password login" ;;
                *)        status="password set" ;;
            esac

            # lastchg and expire are days since 1970-01-01; render them as dates.
            if [ "$lastchg" = "0" ]; then
                lastchg="0 (change forced at next login)"
            elif [ -n "$lastchg" ]; then
                lastchg=$(date -u -d "@$(( lastchg * 86400 ))" +%Y-%m-%d 2>/dev/null || echo "$lastchg")
            else
                lastchg="(never)"
            fi
            if [ -n "$expire" ]; then
                expire=$(date -u -d "@$(( expire * 86400 ))" +%Y-%m-%d 2>/dev/null || echo "$expire")
            else
                expire="(never)"
            fi
            [ -n "$maxd" ] || maxd="(unset)"
            case "$maxd" in 99999) maxd="99999 (never expires)" ;; esac
        else
            status="(no access to /etc/shadow)"
            lastchg="(no access)"; mind="(no access)"; maxd="(no access)"
            warnd="(no access)";  inact="(no access)"; expire="(no access)"
        fi

        lastlogin=$(awk -v n="$name" '$1 == n { $1=""; sub(/^[ \t]+/, ""); print; exit }' "$lastlog_tmp")
        [ -n "$lastlogin" ] || lastlogin="(unknown)"

        csv "$name" "$uid" "$gid" "$gecos" "$home" "$shell" \
            "$status" "$lastchg" "$mind" "$maxd" "$warnd" "$inact" "$expire" "$lastlogin"
    done < /etc/passwd

    rm -f "$shadow_tmp" "$lastlog_tmp"
}

# Groups with both their explicit member list and their primary members
# (users whose passwd GID points at the group but who are not listed in
# /etc/group — a common way privileged membership is missed in a review).
emit_groups_csv() {
    csv "GroupName" "GID" "SecondaryMembers" "PrimaryMembers"
    local gname gpw ggid gmembers primary
    while IFS=: read -r gname gpw ggid gmembers; do
        [ -n "$gname" ] || continue
        primary=$(awk -F: -v g="$ggid" '$4 == g { printf "%s ", $1 }' /etc/passwd)
        csv "$gname" "$ggid" "$gmembers" "${primary% }"
    done < /etc/group
}

emit_packages_csv() {
    if have rpm; then
        csv "Package" "Version" "Vendor" "InstalledOn"
        rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME:date}\n' 2>/dev/null |
            sort |
            while IFS=$'\t' read -r n v ven d; do csv "$n" "$v" "$ven" "$d"; done
    elif have dpkg-query; then
        csv "Package" "Version" "Maintainer" "Status"
        dpkg-query -W -f='${Package}\t${Version}\t${Maintainer}\t${Status}\n' 2>/dev/null |
            sort |
            while IFS=$'\t' read -r n v m s; do csv "$n" "$v" "$m" "$s"; done
    elif have apk; then
        csv "Package" "Version" "Vendor" "InstalledOn"
        apk info -v 2>/dev/null | sort | while read -r p; do csv "$p" "" "alpine" ""; done
    else
        csv "Package" "Version" "Vendor" "InstalledOn"
        csv "(no supported package manager found: rpm, dpkg, apk)" "" "" ""
    fi
}

# Merges "is this unit enabled at boot" with "is it running right now".
emit_services_csv() {
    if ! have systemctl; then
        csv "Service" "UnitFileState" "LoadState" "ActiveState" "SubState"
        if have chkconfig; then
            chkconfig --list 2>/dev/null | while read -r line; do csv "$line" "" "" "" ""; done
        elif have service; then
            service --status-all 2>&1 | while read -r line; do csv "$line" "" "" "" ""; done
        else
            csv "(no systemctl, chkconfig, or service command found)" "" "" "" ""
        fi
        return
    fi

    local units_tmp files_tmp
    units_tmp=$(mktemp) ; files_tmp=$(mktemp)
    systemctl list-units      --type=service --all --no-pager --no-legend 2>/dev/null > "$units_tmp"
    systemctl list-unit-files --type=service      --no-pager --no-legend 2>/dev/null > "$files_tmp"

    csv "Service" "UnitFileState" "LoadState" "ActiveState" "SubState"
    awk '
        # systemd prefixes units in a problem state with a "●" bullet, which
        # shifts every column. Strip any leading non-alphanumeric bytes so the
        # unit name is always field 1.
        { sub(/^[^A-Za-z0-9]+/, "") }
        NR == FNR { state[$1] = $2; next }
        {
            printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", $1, ($1 in state ? state[$1] : ""), $2, $3, $4
            seen[$1] = 1
        }
        END {
            for (u in state) if (!(u in seen)) printf "\"%s\",\"%s\",\"\",\"\",\"\"\n", u, state[u]
        }
    ' "$files_tmp" "$units_tmp" | sort -t'"' -k2,2
    rm -f "$units_tmp" "$files_tmp"
}

emit_ports_csv() {
    csv "Protocol" "State" "LocalAddress" "LocalPort" "Process"
    if have ss; then
        ss -tulpnH 2>/dev/null | awk '
            {
                local = $5
                port = local; sub(/.*:/, "", port)
                addr = local; sub(/:[^:]*$/, "", addr)
                proc = ""
                for (i = 7; i <= NF; i++) proc = proc $i " "
                gsub(/"/, "\"\"", proc)
                sub(/[ \t]+$/, "", proc)
                printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", $1, $2, addr, port, proc
            }' | sort -t'"' -k8,8n
    elif have netstat; then
        netstat -tulpn 2>/dev/null | awk '
            NR > 2 {
                local = $4
                port = local; sub(/.*:/, "", port)
                addr = local; sub(/:[^:]*$/, "", addr)
                printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", $1, $6, addr, port, $7
            }'
    else
        csv "(neither ss nor netstat is available on this host)" "" "" "" ""
    fi
}

# ------------------------------------------------------------------------------
# Hardening scorecard — current value vs. recommended, with the PCI reference.
# This is the file an assessor reads first: every deviation is a candidate
# finding under Req 2.2 (secure configuration).
# ------------------------------------------------------------------------------
SSHD_EFFECTIVE=""
SSHD_SOURCE=""

sysctl_val() { sysctl -n "$1" 2>/dev/null || echo "(not set)"; }

# Loads the SSH server configuration and records WHERE it came from.
# "sshd -T" prints the effective configuration including compiled-in defaults —
# that is what actually applies. If it cannot run (not root, sshd not installed,
# or missing host keys) we fall back to the config files, which show only what
# is explicitly declared. The two are not interchangeable evidence, so the
# scorecard names the source it used.
load_sshd_config() {
    SSHD_EFFECTIVE=$(mktemp)
    if { priv sshd -T > "$SSHD_EFFECTIVE" 2>/dev/null || sshd -T > "$SSHD_EFFECTIVE" 2>/dev/null; } &&
       [ -s "$SSHD_EFFECTIVE" ]; then
        SSHD_SOURCE="sshd -T (effective)"
        return
    fi
    {
        priv cat /etc/ssh/sshd_config 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null
        for f in /etc/ssh/sshd_config.d/*.conf; do
            [ -e "$f" ] || continue
            priv cat "$f" 2>/dev/null || cat "$f" 2>/dev/null
        done
    } | grep -Ev "^[[:space:]]*#|^[[:space:]]*$" | tr 'A-Z' 'a-z' > "$SSHD_EFFECTIVE"

    if [ -s "$SSHD_EFFECTIVE" ]; then
        SSHD_SOURCE="sshd_config (declared only)"
    else
        SSHD_SOURCE="(no access)"
    fi
}

# Returns the effective sshd value. If the configuration could not be read at
# all, say so explicitly — "(not set)" would read like a finding when the real
# answer is "unknown", which is worse than no evidence.
sshd_val() {
    local key v
    if [ "$SSHD_SOURCE" = "(no access)" ] || [ ! -s "$SSHD_EFFECTIVE" ]; then
        printf '(no access - re-run as root)'
        return
    fi
    key=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    v=$(awk -v k="$key" '$1 == k { $1=""; sub(/^[ \t]+/, ""); print; exit }' "$SSHD_EFFECTIVE" 2>/dev/null)
    [ -n "$v" ] && printf '%s' "$v" || printf '(not set)'
}

# Value of KEY from a "KEY value" or "KEY = value" style config file.
# "not present" and "cannot read" are reported differently on purpose — they
# mean different things to an assessor.
conf_val() {
    local file="$1" key="$2" v
    [ -e "$file" ] || { printf '(file not present)'; return; }
    [ -r "$file" ] || { printf '(no access - re-run as root)'; return; }
    v=$(grep -Ei "^[[:space:]]*${key}[[:space:]]*=?[[:space:]]" "$file" 2>/dev/null |
        grep -v "^[[:space:]]*#" | tail -1 |
        sed -E "s/^[[:space:]]*${key}[[:space:]]*=?[[:space:]]*//I; s/[[:space:]]*(#.*)?$//")
    [ -n "$v" ] && printf '%s' "$v" || printf '(not set)'
}

# Value of an option (e.g. deny=5) on a PAM module line anywhere in /etc/pam.d.
pam_opt() {
    local mod="$1" opt="$2" v
    [ -r /etc/pam.d ] || { printf '(no access - re-run as root)'; return; }
    v=$(grep -rhs -- "$mod" /etc/pam.d/ 2>/dev/null |
        grep -v "^[[:space:]]*#" |
        grep -oE "${opt}=[^[:space:]]+" | head -1 | cut -d= -f2)
    [ -n "$v" ] && printf '%s' "$v" || printf '(not set)'
}

emit_hardening_csv() {
    load_sshd_config

    csv "Setting" "Source" "CurrentValue" "Recommended" "PCIReference"

    # --- SSH server (remote administrative access) ---
    csv "Root login over SSH"            "$SSHD_SOURCE" "$(sshd_val permitrootlogin)"       "no (use named accounts + sudo)" "Req 8.2.2 / 7.2"
    csv "Empty passwords permitted"      "$SSHD_SOURCE" "$(sshd_val permitemptypasswords)"  "no"                             "Req 8.3.1"
    csv "Password authentication"        "$SSHD_SOURCE" "$(sshd_val passwordauthentication)" "no if keys/MFA are the control" "Req 8.3 / 8.4.3"
    csv "Max authentication attempts"    "$SSHD_SOURCE" "$(sshd_val maxauthtries)"          "<= 4"                           "Req 8.3.4"
    csv "Idle session timeout (secs)"    "$SSHD_SOURCE" "$(sshd_val clientaliveinterval)"   "<= 900 (15 min), CountMax 0-1"  "Req 8.2.8"
    csv "Idle timeout count max"         "$SSHD_SOURCE" "$(sshd_val clientalivecountmax)"   "0 or 1 with the interval above" "Req 8.2.8"
    csv "Login grace time (secs)"        "$SSHD_SOURCE" "$(sshd_val logingracetime)"        "<= 60"                          "Req 2.2.4"
    csv "X11 forwarding"                 "$SSHD_SOURCE" "$(sshd_val x11forwarding)"         "no"                             "Req 2.2.4"
    csv "PAM enabled for SSH"            "$SSHD_SOURCE" "$(sshd_val usepam)"                "yes (enforces lockout policy)"  "Req 8.3.4"
    csv "Pre-login banner"               "$SSHD_SOURCE" "$(sshd_val banner)"                "set to an authorized-use notice" "Req 2.2.4"
    csv "SSH ciphers offered"            "$SSHD_SOURCE" "$(sshd_val ciphers)"               "strong only, no CBC/arcfour/3DES" "Req 4.2.1 / 2.2.7"
    csv "SSH MACs offered"               "$SSHD_SOURCE" "$(sshd_val macs)"                  "SHA-2 based only, no MD5/SHA1-96" "Req 4.2.1 / 2.2.7"
    csv "SSH key exchange algorithms"    "$SSHD_SOURCE" "$(sshd_val kexalgorithms)"         "no diffie-hellman-group1/group14-sha1" "Req 4.2.1 / 2.2.7"

    # --- Password aging and quality ---
    csv "Max password age (days)"        "/etc/login.defs" "$(conf_val /etc/login.defs PASS_MAX_DAYS)" "<= 90 when passwords are the only factor" "Req 8.3.9"
    csv "Min password age (days)"        "/etc/login.defs" "$(conf_val /etc/login.defs PASS_MIN_DAYS)" ">= 1"                "Req 8.3.7"
    csv "Password expiry warning (days)" "/etc/login.defs" "$(conf_val /etc/login.defs PASS_WARN_AGE)" ">= 7"                "Req 8.3.9"
    csv "Default umask"                  "/etc/login.defs" "$(conf_val /etc/login.defs UMASK)"         "027 or stricter"     "Req 7.2"
    csv "Password hashing method"        "/etc/login.defs" "$(conf_val /etc/login.defs ENCRYPT_METHOD)" "SHA512 or yescrypt" "Req 8.3.2"
    csv "Minimum password length"        "pwquality"       "$(conf_val /etc/security/pwquality.conf minlen)"   ">= 12"       "Req 8.3.6"
    csv "Password character classes"     "pwquality"       "$(conf_val /etc/security/pwquality.conf minclass)" ">= 3 (or credit rules set)" "Req 8.3.6"
    csv "Password history remembered"    "pam_pwhistory"   "$(pam_opt pam_pwhistory remember)"                 ">= 4"        "Req 8.3.7"

    # --- Account lockout ---
    csv "Lockout threshold"              "pam_faillock"    "$(pam_opt pam_faillock deny)"        "<= 10 failed attempts" "Req 8.3.4"
    csv "Lockout duration (secs)"        "pam_faillock"    "$(pam_opt pam_faillock unlock_time)" ">= 1800 (30 min) or manual unlock" "Req 8.3.4"

    # --- Kernel hardening ---
    csv "Address space randomization"    "sysctl" "$(sysctl_val kernel.randomize_va_space)"          "2"          "Req 2.2.6"
    csv "Restrict dmesg access"          "sysctl" "$(sysctl_val kernel.dmesg_restrict)"              "1"          "Req 7.2"
    csv "Restrict kernel pointers"       "sysctl" "$(sysctl_val kernel.kptr_restrict)"               "1 or 2"     "Req 7.2"
    csv "SUID core dumps disabled"       "sysctl" "$(sysctl_val fs.suid_dumpable)"                   "0"          "Req 2.2.6"
    csv "IP forwarding"                  "sysctl" "$(sysctl_val net.ipv4.ip_forward)"                "0 unless the host routes traffic" "Req 1.3"
    csv "Accept ICMP redirects"          "sysctl" "$(sysctl_val net.ipv4.conf.all.accept_redirects)" "0"          "Req 1.4"
    csv "Send ICMP redirects"            "sysctl" "$(sysctl_val net.ipv4.conf.all.send_redirects)"   "0"          "Req 1.4"
    csv "Accept source routing"          "sysctl" "$(sysctl_val net.ipv4.conf.all.accept_source_route)" "0"       "Req 1.4"
    csv "Reverse path filtering"         "sysctl" "$(sysctl_val net.ipv4.conf.all.rp_filter)"        "1"          "Req 1.4"
    csv "Log martian packets"            "sysctl" "$(sysctl_val net.ipv4.conf.all.log_martians)"     "1"          "Req 10.2"
    csv "Ignore broadcast ICMP"          "sysctl" "$(sysctl_val net.ipv4.icmp_echo_ignore_broadcasts)" "1"        "Req 1.4"
    csv "TCP SYN cookies"                "sysctl" "$(sysctl_val net.ipv4.tcp_syncookies)"            "1"          "Req 1.4"
    csv "Accept IPv6 redirects"          "sysctl" "$(sysctl_val net.ipv6.conf.all.accept_redirects)" "0"          "Req 1.4"

    # --- Platform controls (derived, not a single config value) ---
    local mac_status fw_status audit_status time_status
    if have getenforce; then mac_status="SELinux: $(getenforce 2>/dev/null)"
    elif have aa-status; then mac_status="AppArmor: $(priv aa-status --enabled >/dev/null 2>&1 && echo enabled || echo "not enabled/unknown")"
    else mac_status="(no SELinux or AppArmor tooling found)"; fi
    csv "Mandatory access control"       "SELinux / AppArmor" "$mac_status" "SELinux Enforcing, or AppArmor enabled" "Req 2.2.6 / 7.2"

    fw_status="(none detected)"
    if have firewall-cmd && priv firewall-cmd --state >/dev/null 2>&1; then fw_status="firewalld: running"
    elif have ufw && priv ufw status 2>/dev/null | grep -qi "^Status: active"; then fw_status="ufw: active"
    elif have nft && [ -n "$(priv nft list ruleset 2>/dev/null)" ]; then fw_status="nftables: ruleset present"
    elif have iptables && priv iptables -S 2>/dev/null | grep -qv "^-P"; then fw_status="iptables: rules present"; fi
    csv "Host firewall"                  "firewalld / ufw / nft / iptables" "$fw_status" "Active with a default-deny inbound policy" "Req 1.2 / 1.4"

    if have systemctl; then
        audit_status=$(systemctl is-active auditd 2>/dev/null || echo "unknown")
    elif have auditctl; then
        audit_status=$(priv auditctl -s 2>/dev/null | head -1 || echo "unknown")
    else
        audit_status="(auditd not installed)"
    fi
    csv "Audit daemon (auditd)"          "systemd / auditctl" "$audit_status" "active — required to log admin actions" "Req 10.2"

    if have timedatectl; then
        time_status=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "unknown")
        time_status="NTPSynchronized=$time_status"
    else
        time_status="(timedatectl not available)"
    fi
    csv "Time synchronization"           "timedatectl" "$time_status" "yes — synced to a trusted time source" "Req 10.6"

    rm -f "$SSHD_EFFECTIVE"
}

# ------------------------------------------------------------------------------
# collect_evidence <output base dir> — writes every evidence file and sets
# EXPORT_DIR to the folder it created.
# ------------------------------------------------------------------------------
collect_evidence() {
    local out_base="$1"
    local host_short start_utc

    host_short=$(host_name)
    start_utc=$(date -u '+%Y-%m-%d %H:%M:%S')
    EXPORT_DIR="${out_base}/linux-os-${host_short}-$(date '+%Y%m%d_%H%M%S')"
    mkdir -p "$EXPORT_DIR" || return 1

    [ "$(id -u)" = "0" ] && IS_ROOT="yes"
    if [ "$IS_ROOT" = "no" ] && [ "$USE_SUDO" != "no" ] && have sudo && sudo -n true 2>/dev/null; then
        SUDO_OK="yes"
    fi

    if [ "$IS_ROOT" = "no" ] && [ "$SUDO_OK" = "no" ]; then
        printf '  WARNING: not root and passwordless sudo is unavailable.\n' >&2
        printf '           Shadow aging data, audit rules, firewall rules, and some\n' >&2
        printf '           config files will be incomplete for this host.\n' >&2
    fi

    # Chain-of-custody metadata the collector reads back when writing MANIFEST.
    {
        echo "TARGET_HOST=$(host_fqdn)"
        echo "DISTRIBUTION=$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -s )"
        echo "KERNEL=$(uname -r)"
        echo "COLLECTED_UTC=$start_utc"
        echo "COLLECTED_BY=$(id -un 2>/dev/null || echo unknown)"
        echo "RAN_AS_ROOT=$IS_ROOT"
        echo "SUDO_AVAILABLE=$SUDO_OK"
    } > "$EXPORT_DIR/collection-info.txt"

    # ===== 1. SYSTEM INFORMATION =====
    _head "System information"
    cap "Host, OS, kernel, and uptime" "system-info.txt" '
        echo "===== /etc/os-release ====="; cat /etc/os-release 2>/dev/null
        echo; echo "===== uname -a ====="; uname -a
        echo; echo "===== hostnamectl ====="; hostnamectl 2>/dev/null || echo "(hostnamectl not available)"
        echo; echo "===== uptime ====="; uptime
        echo; echo "===== last boot ====="; who -b 2>/dev/null; date -u "+now (UTC): %Y-%m-%d %H:%M:%S"
        echo; echo "===== CPU / memory ====="; lscpu 2>/dev/null | head -20; echo; free -h 2>/dev/null
        echo; echo "===== virtualization ====="; systemd-detect-virt 2>/dev/null || echo "(systemd-detect-virt not available)"
        echo; echo "===== collected by ====="; id
    '

    # ===== 2. ACCOUNTS AND GROUPS =====
    _head "Accounts and groups"
    cap "Local user accounts"            "local-users.csv"        'emit_users_csv'
    cap "Local groups and membership"    "local-groups.csv"       'emit_groups_csv'
    cap "Privileged and risky accounts"  "privileged-accounts.txt" '
        echo "===== UID 0 accounts (should be root only) ====="
        awk -F: "\$3 == 0 { print \$1 }" /etc/passwd
        echo; echo "===== Accounts with an empty password field in /etc/shadow ====="
        priv awk -F: "\$2 == \"\" { print \$1 }" /etc/shadow 2>/dev/null || echo "(requires root)"
        echo; echo "===== Members of privileged groups ====="
        for g in root wheel sudo admin adm docker; do
            if getent group "$g" >/dev/null 2>&1; then
                echo "  $g: $(getent group "$g" | cut -d: -f4)"
            fi
        done
        echo; echo "===== Accounts with a login shell ====="
        awk -F: "\$7 !~ /(nologin|false|sync|shutdown|halt)$/ { print \$1 \"  \" \$7 }" /etc/passwd
        echo; echo "===== Accounts that never expire (shadow field 8 empty) ====="
        priv awk -F: "\$8 == \"\" { print \$1 }" /etc/shadow 2>/dev/null || echo "(requires root)"
    '
    cap "sudo configuration"             "sudoers-config.txt" '
        echo "===== /etc/sudoers ====="
        priv cat /etc/sudoers 2>/dev/null | grep -v "^[[:space:]]*#" | grep -v "^[[:space:]]*$" || echo "(requires root)"
        echo; echo "===== /etc/sudoers.d/ ====="
        for f in /etc/sudoers.d/*; do
            [ -e "$f" ] || continue
            echo "--- $f ---"
            priv cat "$f" 2>/dev/null | grep -v "^[[:space:]]*#" | grep -v "^[[:space:]]*$" || echo "(requires root)"
        done
        echo; echo "===== NOPASSWD entries (review each one) ====="
        priv grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo "(none found, or requires root)"
    '

    # ===== 3. PASSWORD AND LOCKOUT POLICY =====
    _head "Password and lockout policy"
    cap "Password aging and quality policy" "password-policy.txt" '
        echo "===== /etc/login.defs (active settings) ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/login.defs 2>/dev/null
        echo; echo "===== /etc/security/pwquality.conf ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/security/pwquality.conf 2>/dev/null || echo "(not present)"
        echo; echo "===== /etc/security/pwquality.conf.d/ ====="
        grep -rEv "^[[:space:]]*#|^[[:space:]]*$" /etc/security/pwquality.conf.d/ 2>/dev/null || echo "(not present)"
        echo; echo "===== chage -l for interactive accounts ====="
        awk -F: "\$3 >= 1000 && \$7 !~ /(nologin|false)$/ { print \$1 }" /etc/passwd | while read -r u; do
            echo "--- $u ---"
            priv chage -l "$u" 2>/dev/null || echo "(requires root)"
        done
    '
    cap "PAM authentication stack"       "pam-config.txt" '
        for f in /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password \
                 /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/sshd /etc/pam.d/login \
                 /etc/pam.d/su /etc/pam.d/sudo; do
            [ -r "$f" ] || continue
            echo "===== $f ====="
            grep -Ev "^[[:space:]]*#|^[[:space:]]*$" "$f"
            echo
        done
    '
    cap "Account lockout configuration"  "account-lockout.txt" '
        echo "===== /etc/security/faillock.conf ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/security/faillock.conf 2>/dev/null || echo "(not present)"
        echo; echo "===== pam_faillock / pam_tally2 lines in /etc/pam.d ====="
        grep -rn "pam_faillock\|pam_tally2" /etc/pam.d/ 2>/dev/null || echo "(no lockout module configured — Req 8.3.4 finding)"
        echo; echo "===== Currently locked accounts (faillock) ====="
        priv faillock 2>/dev/null || echo "(faillock not available or requires root)"
    '

    # ===== 4. HARDENING SCORECARD =====
    _head "Hardening"
    cap "Hardening scorecard (current vs recommended)" "hardening-checks.csv" 'emit_hardening_csv'
    cap "All kernel parameters (sysctl -a)" "sysctl-all.txt" '
        priv sysctl -a 2>/dev/null || sysctl -a 2>/dev/null || echo "(sysctl unavailable)"
    '
    cap "SELinux / AppArmor status"      "selinux-apparmor.txt" '
        echo "===== SELinux ====="
        if command -v sestatus >/dev/null 2>&1; then
            sestatus 2>/dev/null
            echo; echo "--- /etc/selinux/config ---"
            grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/selinux/config 2>/dev/null
        else
            echo "(SELinux tooling not installed)"
        fi
        echo; echo "===== AppArmor ====="
        if command -v aa-status >/dev/null 2>&1; then
            priv aa-status 2>/dev/null || aa-status 2>/dev/null || echo "(requires root)"
        else
            echo "(AppArmor tooling not installed)"
        fi
    '
    cap "Loaded and blacklisted kernel modules" "kernel-modules.txt" '
        echo "===== lsmod ====="; lsmod 2>/dev/null
        echo; echo "===== blacklisted modules ====="
        grep -rhs "^blacklist\|^install .* /bin/\(true\|false\)" /etc/modprobe.d/ /usr/lib/modprobe.d/ 2>/dev/null || echo "(none configured)"
    '

    # ===== 5. LOGGING AND AUDIT =====
    _head "Logging and audit"
    cap "auditd rules and configuration" "audit-rules.txt" '
        echo "===== auditctl -l (rules loaded right now) ====="
        priv auditctl -l 2>/dev/null || echo "(auditd not installed or requires root)"
        echo; echo "===== auditctl -s (status) ====="
        priv auditctl -s 2>/dev/null || echo "(unavailable)"
        echo; echo "===== /etc/audit/auditd.conf ====="
        priv grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/audit/auditd.conf 2>/dev/null || echo "(unavailable)"
        echo; echo "===== /etc/audit/rules.d/ ====="
        priv grep -rEv "^[[:space:]]*#|^[[:space:]]*$" /etc/audit/rules.d/ 2>/dev/null || echo "(unavailable)"
    '
    cap "Syslog and journald configuration" "logging-config.txt" '
        echo "===== /etc/rsyslog.conf ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/rsyslog.conf 2>/dev/null || echo "(not present)"
        echo; echo "===== /etc/rsyslog.d/ ====="
        grep -rEv "^[[:space:]]*#|^[[:space:]]*$" /etc/rsyslog.d/ 2>/dev/null || echo "(not present)"
        echo; echo "===== syslog-ng ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/syslog-ng/syslog-ng.conf 2>/dev/null || echo "(not present)"
        echo; echo "===== Remote log forwarding targets (Req 10.3.3) ====="
        grep -rhs "^[^#]*@@\?[0-9a-zA-Z]" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null || echo "(no rsyslog forwarding rules found)"
        grep -rhs "destination.*network\|destination.*syslog(" /etc/syslog-ng/ 2>/dev/null
        echo; echo "===== /etc/systemd/journald.conf ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/systemd/journald.conf 2>/dev/null || echo "(not present)"
    '
    cap "Log retention and permissions"  "log-retention.txt" '
        echo "===== /etc/logrotate.conf ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/logrotate.conf 2>/dev/null || echo "(not present)"
        echo; echo "===== /etc/logrotate.d/ ====="
        grep -rEv "^[[:space:]]*#|^[[:space:]]*$" /etc/logrotate.d/ 2>/dev/null || echo "(not present)"
        echo; echo "===== journal disk usage ====="
        journalctl --disk-usage 2>/dev/null || echo "(journalctl not available)"
        echo; echo "===== oldest journal entry (retention evidence) ====="
        journalctl --no-pager -n 1 -o short-iso 2>/dev/null | head -1 || echo "(unavailable)"
        echo; echo "===== /var/log permissions ====="
        ls -la /var/log 2>/dev/null | head -40
    '

    # ===== 6. FIREWALL =====
    _head "Firewall"
    cap "Firewall rules (all backends present)" "firewall-rules.txt" '
        echo "===== firewalld ====="
        if command -v firewall-cmd >/dev/null 2>&1; then
            priv firewall-cmd --state 2>/dev/null
            priv firewall-cmd --list-all-zones 2>/dev/null || echo "(requires root)"
        else echo "(firewalld not installed)"; fi
        echo; echo "===== ufw ====="
        if command -v ufw >/dev/null 2>&1; then
            priv ufw status verbose 2>/dev/null || echo "(requires root)"
        else echo "(ufw not installed)"; fi
        echo; echo "===== nftables ====="
        if command -v nft >/dev/null 2>&1; then
            priv nft list ruleset 2>/dev/null || echo "(requires root)"
        else echo "(nft not installed)"; fi
        echo; echo "===== iptables (IPv4) ====="
        if command -v iptables-save >/dev/null 2>&1; then
            priv iptables-save 2>/dev/null || echo "(requires root)"
        else echo "(iptables-save not installed)"; fi
        echo; echo "===== ip6tables (IPv6) ====="
        if command -v ip6tables-save >/dev/null 2>&1; then
            priv ip6tables-save 2>/dev/null || echo "(requires root)"
        else echo "(ip6tables-save not installed)"; fi
        echo; echo "===== TCP wrappers ====="
        cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -Ev "^[[:space:]]*#|^[[:space:]]*$" || echo "(no entries)"
    '

    # ===== 7. SOFTWARE AND PATCHES =====
    _head "Software and patches"
    cap "Installed packages"             "installed-packages.csv" 'emit_packages_csv'
    cap "Patch status and update history" "patch-status.txt" '
        echo "===== Available updates ====="
        if command -v dnf >/dev/null 2>&1; then
            priv dnf -q check-update 2>/dev/null || dnf -q check-update 2>/dev/null
            echo; echo "--- security updates only ---"
            priv dnf -q updateinfo list security 2>/dev/null || echo "(unavailable)"
        elif command -v yum >/dev/null 2>&1; then
            priv yum -q check-update 2>/dev/null
            echo; echo "--- security updates only ---"
            priv yum -q updateinfo list security 2>/dev/null || echo "(unavailable)"
        elif command -v apt >/dev/null 2>&1; then
            apt list --upgradable 2>/dev/null
        elif command -v apk >/dev/null 2>&1; then
            apk version -l "<" 2>/dev/null
        else echo "(no supported package manager found)"; fi
        echo; echo "===== Update history (most recent first) ====="
        if command -v dnf >/dev/null 2>&1; then
            priv dnf history list 2>/dev/null | head -25 || echo "(requires root)"
        elif command -v yum >/dev/null 2>&1; then
            priv yum history list 2>/dev/null | head -25 || echo "(requires root)"
        elif [ -r /var/log/dpkg.log ]; then
            grep " upgrade " /var/log/dpkg.log 2>/dev/null | tail -25
        else echo "(no update history available)"; fi
        echo; echo "===== Automatic update configuration ====="
        for f in /etc/dnf/automatic.conf /etc/yum/yum-cron.conf /etc/apt/apt.conf.d/20auto-upgrades \
                 /etc/apt/apt.conf.d/50unattended-upgrades; do
            [ -r "$f" ] || continue
            echo "--- $f ---"
            grep -Ev "^[[:space:]]*#|^[[:space:]]*$" "$f"
        done
        echo; echo "===== Reboot required? ====="
        [ -f /var/run/reboot-required ] && echo "YES — /var/run/reboot-required exists" || echo "no flag file present"
        command -v needs-restarting >/dev/null 2>&1 && priv needs-restarting -r 2>/dev/null
    '

    # ===== 8. SERVICES, TASKS, AND STARTUP =====
    _head "Services and scheduled tasks"
    cap "Services (enabled and running state)" "services.csv" 'emit_services_csv'
    cap "Running service detail (user + command)" "services-running-detail.txt" '
        if command -v systemctl >/dev/null 2>&1; then
            for u in $(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk "{print \$1}"); do
                echo "--- $u ---"
                systemctl show "$u" -p Id -p User -p Group -p ExecStart -p FragmentPath 2>/dev/null
                echo
            done
        else
            ps -eo user,pid,ppid,cmd --sort=user 2>/dev/null
        fi
    '
    cap "Cron jobs and systemd timers"   "cron-and-timers.txt" '
        echo "===== /etc/crontab ====="; cat /etc/crontab 2>/dev/null
        echo; echo "===== /etc/cron.d/ ====="; grep -rs "" /etc/cron.d/ 2>/dev/null
        echo; echo "===== /etc/cron.{hourly,daily,weekly,monthly} ====="
        ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
        echo; echo "===== Per-user crontabs ====="
        for u in $(cut -d: -f1 /etc/passwd); do
            out=$(priv crontab -l -u "$u" 2>/dev/null)
            [ -n "$out" ] && { echo "--- $u ---"; echo "$out"; }
        done
        echo; echo "===== cron.allow / cron.deny ====="
        cat /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>/dev/null || echo "(none present)"
        echo; echo "===== systemd timers ====="
        systemctl list-timers --all --no-pager 2>/dev/null || echo "(systemctl not available)"
    '

    # ===== 9. NETWORK EXPOSURE =====
    _head "Network exposure"
    cap "Listening ports"                "listening-ports.csv" 'emit_ports_csv'
    cap "Network interfaces and routing" "network-config.txt" '
        echo "===== ip addr ====="; ip addr 2>/dev/null || ifconfig -a 2>/dev/null
        echo; echo "===== ip route ====="; ip route 2>/dev/null || route -n 2>/dev/null
        echo; echo "===== /etc/hosts ====="; cat /etc/hosts 2>/dev/null
        echo; echo "===== DNS resolution ====="; cat /etc/resolv.conf 2>/dev/null
        echo; echo "===== Established connections ====="
        ss -tunap 2>/dev/null | head -100 || netstat -tunap 2>/dev/null | head -100
        echo; echo "===== NFS / Samba exports ====="
        cat /etc/exports 2>/dev/null || echo "(no /etc/exports)"
        command -v testparm >/dev/null 2>&1 && testparm -s 2>/dev/null | head -40
    '
    cap "SSH server configuration"       "ssh-server-config.txt" '
        echo "===== Effective configuration (sshd -T) ====="
        priv sshd -T 2>/dev/null || sshd -T 2>/dev/null || \
            echo "(sshd -T unavailable: requires root, or sshd is not installed / has no host keys.
 The declared configuration below still applies, but options left at their
 compiled-in defaults will not appear in it.)"
        echo; echo "===== /etc/ssh/sshd_config ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config 2>/dev/null
        echo; echo "===== /etc/ssh/sshd_config.d/ ====="
        grep -rEv "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config.d/ 2>/dev/null || echo "(not present)"
        echo; echo "===== Host key algorithms and permissions ====="
        ls -la /etc/ssh/ 2>/dev/null
        echo; echo "===== Authorized keys per account (Req 8.2.2) ====="
        awk -F: "{ print \$1 \" \" \$6 }" /etc/passwd | while read -r u h; do
            if [ -f "$h/.ssh/authorized_keys" ]; then
                echo "--- $u ($h/.ssh/authorized_keys) ---"
                priv awk "{ print \$1, \$3 }" "$h/.ssh/authorized_keys" 2>/dev/null || echo "(requires root)"
            fi
        done
    '

    # ===== 10. ENDPOINT PROTECTION AND FILE INTEGRITY =====
    _head "Endpoint protection"
    cap "Anti-malware status"            "antimalware.txt" '
        found=no
        for p in clamd clamav-daemon freshclam sophos-spd falcon-sensor ds_agent \
                 mdatp xagt cbagent osqueryd wazuh-agent; do
            if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q "^${p}"; then
                echo "--- $p ---"
                systemctl status "$p" --no-pager 2>/dev/null | head -8
                found=yes
            fi
        done
        [ "$found" = "no" ] && echo "(no common anti-malware service unit found — confirm coverage per Req 5.2)"
        echo; echo "===== ClamAV signature age (Req 5.3.2) ====="
        if command -v freshclam >/dev/null 2>&1; then
            ls -la /var/lib/clamav/ 2>/dev/null
            command -v sigtool >/dev/null 2>&1 && sigtool --info /var/lib/clamav/daily.cvd 2>/dev/null | head -5
        else echo "(ClamAV not installed)"; fi
        echo; echo "===== Anti-malware related packages installed ====="
        if command -v rpm >/dev/null 2>&1; then
            rpm -qa 2>/dev/null | grep -iE "clamav|sophos|mcafee|trend|falcon|defender|symantec|eset|wazuh|osquery"
        elif command -v dpkg-query >/dev/null 2>&1; then
            dpkg-query -W -f="\${Package}\n" 2>/dev/null | grep -iE "clamav|sophos|mcafee|trend|falcon|defender|symantec|eset|wazuh|osquery"
        fi
        echo "(end of package match)"
    '
    cap "File integrity monitoring"      "file-integrity-monitoring.txt" '
        echo "===== FIM tooling present (Req 11.5) ====="
        for t in aide tripwire samhain ossec-syscheckd wazuh-agent osqueryd; do
            command -v "$t" >/dev/null 2>&1 && echo "  FOUND: $t ($(command -v $t))"
        done
        echo; echo "===== AIDE ====="
        if command -v aide >/dev/null 2>&1; then
            aide --version 2>&1 | head -3
            echo "--- database ---"; ls -la /var/lib/aide/ 2>/dev/null
            echo "--- config ---"
            grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/aide.conf 2>/dev/null | head -40
            echo "--- scheduled runs ---"
            grep -rs "aide" /etc/cron.d/ /etc/cron.daily/ /etc/crontab 2>/dev/null
        else echo "(AIDE not installed)"; fi
        echo; echo "===== auditd watch rules (file integrity via audit) ====="
        priv auditctl -l 2>/dev/null | grep -- "-w " || echo "(none, or requires root)"
    '

    # ===== 11. FILESYSTEMS AND PERMISSIONS =====
    _head "Filesystems and permissions"
    cap "Mounts, fstab, and encryption"  "filesystems-and-encryption.txt" '
        echo "===== Mounted filesystems ====="; df -hT 2>/dev/null
        echo; echo "===== mount options (nodev/nosuid/noexec) ====="; mount | sort
        echo; echo "===== /etc/fstab ====="; grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/fstab 2>/dev/null
        echo; echo "===== Block devices ====="; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>/dev/null
        echo; echo "===== LUKS encryption status (Req 3.5) ====="
        if command -v lsblk >/dev/null 2>&1; then
            lsblk -o NAME,FSTYPE,TYPE,MOUNTPOINT 2>/dev/null | grep -i "crypt" || echo "(no LUKS/crypt devices detected)"
        fi
        for d in $(lsblk -pnro NAME 2>/dev/null); do
            if command -v cryptsetup >/dev/null 2>&1 && priv cryptsetup isLuks "$d" 2>/dev/null; then
                echo "--- LUKS: $d ---"
                priv cryptsetup luksDump "$d" 2>/dev/null | head -15
            fi
        done
        echo; echo "===== Swap ====="; swapon --show 2>/dev/null || cat /proc/swaps 2>/dev/null
    '
    cap "SUID / SGID binaries"           "suid-sgid-files.txt" '
        echo "# SUID and SGID files on local filesystems (-xdev). Review for"
        echo "# unexpected entries — each one runs with elevated privileges."
        echo
        if command -v timeout >/dev/null 2>&1; then
            timeout 300 find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ld {} + 2>/dev/null
        else
            find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ld {} + 2>/dev/null
        fi
    '
    cap "World-writable files and dirs"  "world-writable.txt" '
        echo "===== World-writable directories WITHOUT the sticky bit ====="
        if command -v timeout >/dev/null 2>&1; then
            timeout 300 find / -xdev -type d -perm -0002 ! -perm -1000 -exec ls -ld {} + 2>/dev/null
        else
            find / -xdev -type d -perm -0002 ! -perm -1000 -exec ls -ld {} + 2>/dev/null
        fi
        echo; echo "===== World-writable files ====="
        if command -v timeout >/dev/null 2>&1; then
            timeout 300 find / -xdev -type f -perm -0002 -exec ls -ld {} + 2>/dev/null | head -200
        else
            find / -xdev -type f -perm -0002 -exec ls -ld {} + 2>/dev/null | head -200
        fi
        echo; echo "===== Files with no owner or no group ====="
        if command -v timeout >/dev/null 2>&1; then
            timeout 120 find / -xdev \( -nouser -o -nogroup \) -exec ls -ld {} + 2>/dev/null | head -100
        fi
        echo; echo "===== Permissions on key files ====="
        ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/crontab 2>/dev/null
    '

    # ===== 12. TIME SYNC, LOGIN HISTORY, BANNERS =====
    _head "Time, sessions, and banners"
    cap "Time synchronization"           "time-sync.txt" '
        echo "===== timedatectl ====="; timedatectl 2>/dev/null || date
        echo; echo "===== chrony ====="
        if command -v chronyc >/dev/null 2>&1; then
            chronyc tracking 2>/dev/null; echo; chronyc sources -v 2>/dev/null
            echo; grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/chrony.conf 2>/dev/null || \
                  grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/chrony/chrony.conf 2>/dev/null
        else echo "(chrony not installed)"; fi
        echo; echo "===== ntpd ====="
        if command -v ntpq >/dev/null 2>&1; then
            ntpq -p 2>/dev/null
            grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/ntp.conf 2>/dev/null
        else echo "(ntpd not installed)"; fi
        echo; echo "===== systemd-timesyncd ====="
        if [ -r /etc/systemd/timesyncd.conf ]; then
            grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/systemd/timesyncd.conf
            timedatectl show-timesync 2>/dev/null
        else echo "(timesyncd not configured)"; fi
    '
    cap "Login history and active sessions" "login-history.txt" '
        echo "===== Currently logged in ====="; who -a 2>/dev/null; echo; w 2>/dev/null
        echo; echo "===== Recent successful logins (last 50) ====="; last -n 50 2>/dev/null
        echo; echo "===== Recent failed logins (last 50) ====="
        priv lastb -n 50 2>/dev/null || echo "(requires root, or btmp not enabled)"
        echo; echo "===== Last login per account ====="; lastlog 2>/dev/null
    '
    cap "Login banners"                  "login-banners.txt" '
        for f in /etc/issue /etc/issue.net /etc/motd; do
            echo "===== $f ====="
            cat "$f" 2>/dev/null || echo "(not present or empty)"
            echo
        done
        echo "===== SSH Banner directive ====="
        grep -i "^[[:space:]]*banner" /etc/ssh/sshd_config 2>/dev/null || echo "(no Banner directive set)"
    '

    return 0
}


# ==============================================================================
# COLLECTOR SIDE — hashing, manifest, and the per-target run loop
# ==============================================================================

# sha256sum on Linux, shasum -a 256 on macOS/BSD
if command -v sha256sum >/dev/null 2>&1; then
    HASH_CMD="sha256sum"
else
    HASH_CMD="shasum -a 256"
fi

meta_val() {  # meta_val <folder> <KEY>
    local v
    v=$(grep -m1 "^$2=" "$1/collection-info.txt" 2>/dev/null | cut -d= -f2-)
    [ -n "$v" ] && printf '%s' "$v" || printf '(unknown)'
}

# Writes checksums.sha256 and MANIFEST.txt into a retrieved evidence folder.
# Echoes the number of files hashed.
write_manifest_and_hashes() {
    local folder="$1"
    local checksums="$folder/checksums.sha256"
    local manifest="$folder/MANIFEST.txt"

    # Relative paths so the checksum file verifies from inside the folder no
    # matter where it is later copied.
    (
        cd "$folder" || exit 1
        find . -type f ! -name MANIFEST.txt ! -name checksums.sha256 |
            sed "s|^\./||" | sort |
            while IFS= read -r f; do ${HASH_CMD} "$f"; done
    ) > "$checksums"

    {
        echo "Linux OS Configuration Export Manifest (PCI DSS)"
        echo "================================================"
        echo "Target host        : $(meta_val "$folder" TARGET_HOST)"
        echo "Distribution       : $(meta_val "$folder" DISTRIBUTION)"
        echo "Kernel             : $(meta_val "$folder" KERNEL)"
        echo "Collected (UTC)    : $(meta_val "$folder" COLLECTED_UTC) UTC"
        echo "Collected by       : $(meta_val "$folder" COLLECTED_BY)  (account used on the target)"
        echo "Ran as root        : $(meta_val "$folder" RAN_AS_ROOT)"
        echo "Passwordless sudo  : $(meta_val "$folder" SUDO_AVAILABLE)"
        echo "Retrieved/hashed by: ${COLLECTOR_USER} on ${COLLECTOR_HOST}"
        echo "Hashed (UTC)       : $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
        echo "Hash algorithm     : SHA-256"
        echo ""
        echo "Files and integrity hashes:"
        echo ""
        while read -r hash name; do
            name="${name#\*}"
            printf '  %s\n' "$name"
            printf '      Size   : %s KB\n' "$(file_kb "$folder/$name")"
            printf '      SHA-256: %s\n' "$hash"
            echo ""
        done < "$checksums"
        echo "checksums.sha256 lists all hashes in a format verifiable with:"
        echo "  Linux   : sha256sum -c checksums.sha256"
        echo "  macOS   : shasum -a 256 -c checksums.sha256"
        echo "  Windows : certutil -hashfile <file> SHA256"
    } > "$manifest"

    grep -c "" "$checksums"
}

is_local_target() {
    case "$1" in
        localhost|127.0.0.1|::1|"$(host_name)"|"$(host_fqdn)") return 0 ;;
        *) return 1 ;;
    esac
}

main() {
    # --- resolve the target list ---
    local targets=()
    if [ -n "$HOST_LIST_FILE" ]; then
        if [ ! -r "$HOST_LIST_FILE" ]; then
            echo "ERROR: host list file not found or not readable: $HOST_LIST_FILE" >&2
            exit 1
        fi
        while IFS= read -r line; do
            line="${line%%#*}"
            line="$(printf '%s' "$line" | tr -d '[:space:]')"
            [ -n "$line" ] && targets+=("$line")
        done < "$HOST_LIST_FILE"
    elif [ ${#HOSTS[@]} -gt 0 ]; then
        targets=("${HOSTS[@]}")
    else
        targets=("localhost")
    fi

    if [ ${#targets[@]} -eq 0 ]; then
        echo "ERROR: no targets resolved. Check HOST_LIST_FILE or HOSTS." >&2
        exit 1
    fi

    COLLECTOR_USER=$(id -un 2>/dev/null || echo unknown)
    COLLECTOR_HOST=$(host_name)

    local run_date run_dir
    run_date=$(date '+%Y%m%d_%H%M%S')
    run_dir="${OUTPUT_BASE}/linux-os-run-${run_date}"
    mkdir -p "$run_dir" || { echo "ERROR: cannot create $run_dir" >&2; exit 1; }

    echo "========================================"
    echo "  Linux OS Configuration Export (PCI DSS)"
    echo "  Collector : $COLLECTOR_HOST ($COLLECTOR_USER)"
    echo "  Targets   : ${#targets[@]}  [${targets[*]}]"
    echo "  Output    : $run_dir"
    echo "========================================"

    # --- per-target collection ---
    local summary_file
    summary_file=$(mktemp)
    local ok_count=0

    local target status folder file_count
    for target in "${targets[@]}"; do
        status="FAILED"; folder=""; file_count=0
        echo ""
        echo "----------------------------------------"
        if is_local_target "$target"; then
            echo "  Target: $target  (local)"
            echo "----------------------------------------"
            if collect_evidence "$run_dir"; then
                folder="$EXPORT_DIR"
            fi
        else
            echo "  Target: $target  (remote over SSH)"
            echo "----------------------------------------"

            local ssh_cmd=(ssh -p "$SSH_PORT")
            [ -n "$SSH_KEY" ] && ssh_cmd+=(-i "$SSH_KEY")
            # shellcheck disable=SC2206
            ssh_cmd+=($SSH_EXTRA_OPTS)
            ssh_cmd+=("${SSH_USER:+$SSH_USER@}$target")

            # Stream this script to the target, run it there in --collect mode,
            # and receive the evidence folder back as a tarball on stdout. The
            # script is written to a temp file first so that stdin is exhausted
            # before collection starts. The temp copy is always removed.
            local bundle remote_sh
            bundle=$(mktemp)
            remote_sh='T=$(mktemp /tmp/linux-os-export.XXXXXX) && cat > "$T" && bash "$T" --collect; rc=$?; rm -f "$T"; exit $rc'

            printf '  %-46s' "Collecting over SSH..."
            echo ""
            if "${ssh_cmd[@]}" "$remote_sh" < "$SCRIPT_PATH" > "$bundle"; then
                printf '  %-46s' "Retrieving evidence (tar stream)..."
                local top
                top=$(tar tzf "$bundle" 2>/dev/null | head -1 | cut -d/ -f1)
                if [ -n "$top" ] && tar xzf "$bundle" -C "$run_dir" 2>/dev/null; then
                    folder="$run_dir/$top"
                    echo " OK"
                else
                    echo " FAILED (could not unpack evidence bundle)"
                fi
            else
                echo "  SSH collection FAILED for $target"
            fi
            rm -f "$bundle"
        fi

        if [ -n "$folder" ] && [ -d "$folder" ]; then
            printf '  %-46s' "Hashing evidence (SHA-256) + manifest..."
            file_count=$(write_manifest_and_hashes "$folder")
            echo " OK ($file_count files)"
            status="OK"
            ok_count=$((ok_count + 1))
        fi

        printf '  %-30s %-8s %4s files   %s\n' \
            "$target" "$status" "$file_count" "$(basename "${folder:-}")" >> "$summary_file"
    done

    # --- run summary ---
    {
        echo "Linux OS Export — Run Summary"
        echo "============================="
        echo "Collector : $COLLECTOR_HOST ($COLLECTOR_USER)"
        echo "Started   : $run_date"
        echo "Targets   : ${#targets[@]}"
        echo ""
        cat "$summary_file"
    } > "$run_dir/RUN-SUMMARY.txt"
    rm -f "$summary_file"

    echo ""
    echo "========================================"
    echo "  Export complete."
    echo "  Hosts collected: $ok_count / ${#targets[@]}"
    echo "  Run folder     : $run_dir"
    echo ""
    echo "  Each host folder contains a MANIFEST.txt with SHA-256 integrity"
    echo "  hashes. RUN-SUMMARY.txt lists per-host status."
    echo ""
    echo "  Key files per host for assessor review:"
    echo "  - hardening-checks.csv    -- current vs recommended, with PCI refs"
    echo "  - local-users.csv         -- accounts, password aging, last login"
    echo "  - sudoers-config.txt      -- who can escalate to root"
    echo "  - audit-rules.txt         -- what is being logged (Req 10.2)"
    echo "  - firewall-rules.txt      -- host firewall posture (Req 1)"
    echo "  - patch-status.txt        -- outstanding security updates (Req 6.3.3)"
    echo "========================================"
}


# ==============================================================================
# ENTRY POINT
# --collect is used internally when this script is streamed to a remote target:
# it collects into a staging directory and writes a tarball to stdout.
# ==============================================================================
SCRIPT_PATH="${BASH_SOURCE[0]}"

if [ "${1:-}" = "--collect" ]; then
    STAGE=$(mktemp -d "${TMPDIR:-/tmp}/pci-linux-os.XXXXXX") || exit 1
    if collect_evidence "$STAGE"; then
        tar czf - -C "$STAGE" "$(basename "$EXPORT_DIR")" 2>/dev/null
        rc=$?
    else
        rc=1
    fi
    rm -rf "$STAGE"
    exit $rc
fi

main "$@"
