#!/usr/bin/env bash
#
# macos-os-export.sh — macOS host configuration export for PCI DSS assessment
#
# Collects macOS operating system configuration evidence relevant to PCI DSS
# system hardening, access control, and logging control reviews. Runs against
# the local machine, or against a list of Macs (one hostname per line in a text
# file) over SSH from a single admin workstation — no need to log in to each
# machine.
#
# For every target it collects:
#   - System information (macOS version/build, hardware model, serial, uptime)
#   - Local accounts from Directory Services with admin rights and password age
#   - Groups, admin/wheel membership, and sudoers configuration
#   - Password policy (pwpolicy account policies) and screen lock settings
#   - FileVault disk encryption status and enabled users
#   - Application Firewall state, stealth mode, logging, and per-app rules; pf
#   - System Integrity Protection, Gatekeeper, XProtect, and MRT versions
#   - Installed applications, package receipts, available and installed updates
#   - launchd daemons/agents, sharing services, and login items
#   - Listening ports, network configuration, and SSH server hardening
#   - Unified logging configuration and OpenBSM audit settings
#   - Configuration profiles and MDM enrolment state
#   - Filesystems, APFS encryption, SUID/SGID and world-writable files
#   - Time synchronization, login history, and the login window banner
#   - A hardening scorecard comparing current vs. recommended values
#
# Each host gets its own timestamped evidence folder under a single run folder.
# Every file is hashed with SHA-256 and recorded in a per-host MANIFEST for
# chain-of-custody and integrity verification, plus a checksums.sha256 file
# that an assessor can verify independently.
#
# This script is READ-ONLY. It makes no changes to any target system.
# Written for the bash 3.2 and BSD userland that ship with macOS.
#
# See macos-os-export_bash_readme.txt for full instructions.

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
# NOTE: when you run this with sudo, HOME becomes /var/root, so the default
# lands in /var/root/macos-os-export and the files are root-owned. Set an
# absolute path here if you want the evidence somewhere else. Either way the
# script prints the resolved run folder at the start and end of every run.
OUTPUT_BASE="$HOME/macos-os-export"

# SSH settings for remote targets. Remote Login must be enabled on each target
# (System Settings > General > Sharing > Remote Login). Key-based authentication
# is strongly recommended; with password auth you are prompted once per host.
SSH_USER=""
SSH_PORT="22"
SSH_KEY=""            # e.g. "$HOME/.ssh/id_ed25519" — leave "" for the default
SSH_EXTRA_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

# Privilege escalation on the target. "auto" uses root directly if the account
# is root, otherwise tries passwordless sudo (sudo -n). "no" collects only what
# an unprivileged account can read.
USE_SUDO="auto"       # auto | no

# "softwareupdate --list" contacts Apple's servers and can take 30-60 seconds
# per host. Set to "no" to skip it (patch evidence is then limited to the
# install history and the automatic-update settings).
CHECK_FOR_UPDATES="yes"   # yes | no
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
ADMIN_MEMBERS=""  # cached membership of the admin group
CONSOLE_USER=""   # the user logged in at the physical console, if any

have() { command -v "$1" >/dev/null 2>&1; }

# BSD mktemp needs an explicit template — bare "mktemp" is a GNU convenience
# and fails on stock macOS.
mktmp()  { mktemp "${TMPDIR:-/tmp}/pci-macos.XXXXXX"; }
mktmpd() { mktemp -d "${TMPDIR:-/tmp}/pci-macos.XXXXXX"; }

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

# Epoch seconds -> YYYY-MM-DD. BSD date uses -r, GNU date uses -d @N; try both
# so the helper also works if this file is ever run on a Linux collector.
epoch_to_date() {
    local e="$1"
    [ -n "$e" ] || { printf '(unknown)'; return; }
    e=${e%%.*}                      # accountPolicyData stores a float
    case "$e" in ''|*[!0-9]*) printf '(unknown)'; return ;; esac
    date -u -r "$e" "+%Y-%m-%d" 2>/dev/null && return
    date -u -d "@$e" "+%Y-%m-%d" 2>/dev/null && return
    printf '%s' "$e"
}

# Host identity, used for folder names and the MANIFEST. Fall back through
# uname and scutil — evidence that cannot name its source host is not much use
# in a chain-of-custody record.
host_name() {
    local h
    h=$(hostname -s 2>/dev/null)
    [ -n "$h" ] || h=$(uname -n 2>/dev/null | cut -d. -f1)
    [ -n "$h" ] || h=$(scutil --get ComputerName 2>/dev/null)
    [ -n "$h" ] || h="unknown"
    printf '%s' "$h" | tr ' ' '-'
}

host_fqdn() {
    local h
    h=$(hostname -f 2>/dev/null)
    [ -n "$h" ] || h=$(uname -n 2>/dev/null)
    [ -n "$h" ] || h="unknown"
    printf '%s' "$h"
}

# Quote every field so commas and quotes inside values cannot break the CSV.
csv() {
    local out="" f
    for f in "$@"; do
        f=$(printf '%s' "$f" | tr -d '\n\r')
        f=${f//\"/\"\"}
        out="${out}\"${f}\","
    done
    printf '%s\n' "${out%,}"
}

# cap <label> <output file> <shell body>
# Runs the body, writing stdout+stderr to the output file. A non-zero exit is
# not treated as failure — several macOS tools (spctl, pfctl when disabled)
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
# Small readers for macOS-specific configuration stores
# ------------------------------------------------------------------------------

# Read one attribute of a Directory Services record, stripping the "key: " label.
ds_val() {
    local path="$1" key="$2" v
    v=$(dscl . -read "$path" "$key" 2>/dev/null | sed -e "s/^${key}: //" -e '/^$/d' | head -1)
    # Multi-line values put the data on the following line instead
    if [ -z "$v" ] || [ "$v" = "$key:" ]; then
        v=$(dscl . -read "$path" "$key" 2>/dev/null | sed -n '2p' | sed 's/^ *//')
    fi
    printf '%s' "$v"
}

# Read a value out of a defaults domain, reporting "not set" distinctly from
# "could not read" — the two mean different things to an assessor.
def_val() {
    local domain="$1" key="$2" v
    v=$(defaults read "$domain" "$key" 2>/dev/null) && { printf '%s' "$v"; return; }
    v=$(priv defaults read "$domain" "$key" 2>/dev/null) && { printf '%s' "$v"; return; }
    printf '(not set)'
}

# Same, for the -currentHost scoped preferences the screen saver uses.
def_val_host() {
    local domain="$1" key="$2" v
    v=$(defaults -currentHost read "$domain" "$key" 2>/dev/null) && { printf '%s' "$v"; return; }
    printf '(not set)'
}

# Read a screen-saver / screen-lock preference for the console user. When this
# runs as root the root domain is the wrong one to read, so ask the console
# user's own preference domain.
user_def_val() {
    local domain="$1" key="$2" v
    if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ] && have sudo; then
        v=$(priv -u "$CONSOLE_USER" defaults -currentHost read "$domain" "$key" 2>/dev/null) &&
            { printf '%s' "$v"; return; }
        v=$(priv -u "$CONSOLE_USER" defaults read "$domain" "$key" 2>/dev/null) &&
            { printf '%s' "$v"; return; }
    fi
    def_val_host "$domain" "$key"
}

APF="/usr/libexec/ApplicationFirewall/socketfilterfw"

alf_val() {
    [ -x "$APF" ] || { printf '(Application Firewall tool not present)'; return; }
    local v
    v=$("$APF" "$1" 2>/dev/null) || v=$(priv "$APF" "$1" 2>/dev/null)
    [ -n "$v" ] && printf '%s' "$v" || printf '(unavailable)'
}

# Pull an integer out of the pwpolicy account-policy plist. The policy is XML;
# each parameter appears as <key>NAME</key><integer>VALUE</integer>.
PWPOLICY_XML=""

pwpolicy_int() {
    local key="$1" v
    [ -s "$PWPOLICY_XML" ] || { printf '(no policy readable)'; return; }
    v=$(grep -A2 "<key>${key}</key>" "$PWPOLICY_XML" 2>/dev/null |
        grep -o "<integer>[0-9]*</integer>" | head -1 |
        tr -dc '0-9')
    [ -n "$v" ] && printf '%s' "$v" || printf '(not set)'
}

# ------------------------------------------------------------------------------
# Structured emitters — used by cap for the CSV outputs.
# ------------------------------------------------------------------------------

# One row per local account from Directory Services. macOS has no /etc/shadow;
# password age lives in the accountPolicyData plist, read via dscl -readpl.
emit_users_csv() {
    csv "Username" "UID" "PrimaryGroupID" "RealName" "HomeDirectory" "Shell" \
        "IsAdmin" "IsHidden" "PasswordLastSet" "FailedLoginCount" \
        "SecureToken" "LastLogin"

    local u uid gid real home shell isadmin hidden lastset failed token lastlogin

    dscl . -list /Users UniqueID 2>/dev/null | sort -k2 -n | while read -r u uid; do
        [ -n "$u" ] || continue

        gid=$(ds_val "/Users/$u" PrimaryGroupID)
        real=$(ds_val "/Users/$u" RealName)
        home=$(ds_val "/Users/$u" NFSHomeDirectory)
        shell=$(ds_val "/Users/$u" UserShell)

        case " $ADMIN_MEMBERS " in
            *" $u "*) isadmin="yes" ;;
            *)        isadmin="no"  ;;
        esac

        hidden=$(ds_val "/Users/$u" IsHidden)
        if [ -z "$hidden" ]; then
            # Accounts below UID 500 are hidden from the login window by default
            if [ -n "$uid" ] && [ "$uid" -lt 500 ] 2>/dev/null; then hidden="yes (UID < 500)"; else hidden="no"; fi
        fi

        lastset=$(dscl . -readpl "/Users/$u" accountPolicyData passwordLastSetTime 2>/dev/null |
                  awk '{print $NF}')
        if [ -n "$lastset" ]; then
            lastset=$(epoch_to_date "$lastset")
        else
            lastset="(not recorded)"
        fi

        failed=$(dscl . -readpl "/Users/$u" accountPolicyData failedLoginCount 2>/dev/null |
                 awk '{print $NF}')
        [ -n "$failed" ] || failed="0"

        if have sysadminctl; then
            token=$(priv sysadminctl -secureTokenStatus "$u" 2>&1 |
                    sed -n 's/.*Secure token is \([A-Za-z]*\).*/\1/p' | head -1)
            [ -n "$token" ] || token="(unknown)"
        else
            token="(sysadminctl unavailable)"
        fi

        lastlogin=$(last -1 "$u" 2>/dev/null | head -1 | sed 's/  */ /g')
        [ -n "$lastlogin" ] || lastlogin="(none recorded)"

        csv "$u" "$uid" "$gid" "$real" "$home" "$shell" \
            "$isadmin" "$hidden" "$lastset" "$failed" "$token" "$lastlogin"
    done
}

emit_groups_csv() {
    csv "GroupName" "GroupID" "Members" "NestedGroups"
    local g gid members nested
    dscl . -list /Groups 2>/dev/null | sort | while read -r g; do
        [ -n "$g" ] || continue
        gid=$(ds_val "/Groups/$g" PrimaryGroupID)
        members=$(dscl . -read "/Groups/$g" GroupMembership 2>/dev/null |
                  sed 's/^GroupMembership: //' | tr '\n' ' ' | sed 's/  */ /g;s/^ *//;s/ *$//')
        nested=$(dscl . -read "/Groups/$g" NestedGroups 2>/dev/null |
                 sed 's/^NestedGroups: //' | tr '\n' ' ' | sed 's/  */ /g;s/^ *//;s/ *$//')
        csv "$g" "$gid" "$members" "$nested"
    done
}

# Applications from /Applications with their bundle version. system_profiler's
# application list is authoritative but routinely takes 30+ seconds; reading
# Info.plist directly gives the same name/version far more cheaply.
emit_apps_csv() {
    csv "Application" "Version" "Path" "Signed"
    local app name ver signed d
    for d in /Applications /Applications/Utilities; do
        [ -d "$d" ] || continue
        for app in "$d"/*.app; do
            [ -e "$app" ] || continue
            name=$(basename "$app" .app)
            ver=$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null)
            [ -n "$ver" ] || ver="(unknown)"
            if have codesign; then
                if codesign -dv "$app" >/dev/null 2>&1; then signed="yes"; else signed="no / unsigned"; fi
            else
                signed="(codesign unavailable)"
            fi
            csv "$name" "$ver" "$app" "$signed"
        done
    done
}

# launchd jobs. Third-party items live outside the Apple-signed directories and
# are the ones worth reviewing for Req 2.2.4.
emit_launchd_csv() {
    csv "Label" "PID" "LastExitStatus" "Scope" "Source"
    local pid status label scope d f

    launchctl list 2>/dev/null | tail -n +2 | while read -r pid status label; do
        [ -n "$label" ] || continue
        case "$label" in
            com.apple.*) scope="Apple" ;;
            *)           scope="third-party" ;;
        esac
        csv "$label" "$pid" "$status" "$scope" "(running list)"
    done

    for d in /Library/LaunchDaemons /Library/LaunchAgents \
             /System/Library/LaunchDaemons /System/Library/LaunchAgents; do
        [ -d "$d" ] || continue
        for f in "$d"/*.plist; do
            [ -e "$f" ] || continue
            label=$(basename "$f" .plist)
            case "$d" in
                /System/*) scope="Apple (system)" ;;
                *)         scope="third-party / admin installed" ;;
            esac
            csv "$label" "" "" "$scope" "$f"
        done
    done
}

emit_ports_csv() {
    csv "Protocol" "LocalAddress" "LocalPort" "Process" "PID" "User"
    if have lsof; then
        { priv lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null; } |
            tail -n +2 |
            awk '{
                addr = $9
                port = addr; sub(/.*:/, "", port)
                host = addr; sub(/:[^:]*$/, "", host)
                gsub(/"/, "\"\"", $1)
                printf "\"TCP\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", host, port, $1, $2, $3
            }' | sort -u
        { priv lsof -nP -iUDP 2>/dev/null || lsof -nP -iUDP 2>/dev/null; } |
            tail -n +2 |
            awk '{
                addr = $9
                port = addr; sub(/.*:/, "", port)
                host = addr; sub(/:[^:]*$/, "", host)
                gsub(/"/, "\"\"", $1)
                printf "\"UDP\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", host, port, $1, $2, $3
            }' | sort -u
    elif have netstat; then
        netstat -an 2>/dev/null | awk '
            /LISTEN/ {
                addr = $4
                port = addr; sub(/.*\./, "", port)
                host = addr; sub(/\.[^.]*$/, "", host)
                printf "\"%s\",\"%s\",\"%s\",\"(netstat: no process info)\",\"\",\"\"\n", $1, host, port
            }'
    else
        csv "(neither lsof nor netstat is available)" "" "" "" "" ""
    fi
}

# ------------------------------------------------------------------------------
# Hardening scorecard — current value vs. recommended, with the PCI reference.
# This is the file an assessor reads first: every deviation is a candidate
# finding under Req 2.2 (secure configuration).
# ------------------------------------------------------------------------------
SSHD_EFFECTIVE=""
SSHD_SOURCE=""

# "sshd -T" prints the effective configuration including compiled-in defaults —
# that is what actually applies. If it cannot run we fall back to the config
# files, which show only what is explicitly declared. The two are not
# interchangeable evidence, so the scorecard names the source it used.
load_sshd_config() {
    SSHD_EFFECTIVE=$(mktmp)
    local sshd_bin="/usr/sbin/sshd"
    have sshd && sshd_bin="sshd"

    if { priv "$sshd_bin" -T > "$SSHD_EFFECTIVE" 2>/dev/null ||
         "$sshd_bin" -T > "$SSHD_EFFECTIVE" 2>/dev/null; } && [ -s "$SSHD_EFFECTIVE" ]; then
        SSHD_SOURCE="sshd -T (effective)"
        return
    fi
    {
        priv cat /etc/ssh/sshd_config 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null
        for f in /etc/ssh/sshd_config.d/*; do
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

emit_hardening_csv() {
    load_sshd_config

    PWPOLICY_XML=$(mktmp)
    { priv pwpolicy -getaccountpolicies 2>/dev/null || pwpolicy -getaccountpolicies 2>/dev/null; } |
        tail -n +2 > "$PWPOLICY_XML"

    csv "Setting" "Source" "CurrentValue" "Recommended" "PCIReference"

    # --- Disk encryption ---
    local fv
    if have fdesetup; then
        fv=$(priv fdesetup status 2>/dev/null || fdesetup status 2>/dev/null)
        [ -n "$fv" ] || fv="(unavailable)"
    else
        fv="(fdesetup not present)"
    fi
    csv "FileVault disk encryption" "fdesetup status" "$fv" "On for all volumes holding CHD" "Req 3.5.1"

    # --- Platform integrity and malware defences ---
    local sip gk
    sip=$(csrutil status 2>/dev/null | sed -e 's/System Integrity Protection status: //' -e 's/\.$//')
    [ -n "$sip" ] || sip="(csrutil unavailable)"
    csv "System Integrity Protection" "csrutil status" "$sip" "enabled" "Req 2.2.6 / 11.5"

    gk=$(spctl --status 2>/dev/null)
    [ -n "$gk" ] || gk="(spctl unavailable)"
    csv "Gatekeeper assessment" "spctl --status" "$gk" "assessments enabled" "Req 5.2 / 2.2.6"

    csv "XProtect malware definitions" "system version plist" "$(xprotect_version)" \
        "Current — updated automatically by Apple" "Req 5.3.2"

    # --- Application Firewall (Req 1) ---
    csv "Application Firewall"        "socketfilterfw" "$(alf_val --getglobalstate)"  "enabled (State = 1)"          "Req 1.2.1"
    csv "Firewall block all incoming" "socketfilterfw" "$(alf_val --getblockall)"     "enabled where the role allows" "Req 1.2.1"
    csv "Firewall stealth mode"       "socketfilterfw" "$(alf_val --getstealthmode)"  "enabled"                       "Req 1.4.1"
    csv "Firewall logging"            "socketfilterfw" "$(alf_val --getloggingmode)"  "enabled"                       "Req 10.2"

    # --- Remote access and sharing services (Req 2.2.4) ---
    local remotelogin remoteevents
    if have systemsetup; then
        remotelogin=$(priv systemsetup -getremotelogin 2>/dev/null | sed 's/Remote Login: //')
        remoteevents=$(priv systemsetup -getremoteappleevents 2>/dev/null | sed 's/Remote Apple Events: //')
        [ -n "$remotelogin" ]  || remotelogin="(requires root)"
        [ -n "$remoteevents" ] || remoteevents="(requires root)"
    else
        remotelogin="(systemsetup unavailable)"; remoteevents="(systemsetup unavailable)"
    fi
    csv "Remote Login (SSH)"      "systemsetup" "$remotelogin"  "Off unless remote administration is required" "Req 2.2.4"
    csv "Remote Apple Events"     "systemsetup" "$remoteevents" "Off"                                          "Req 2.2.4"
    csv "Screen Sharing service"  "launchctl"   "$(service_state com.apple.screensharing)" "Off unless required" "Req 2.2.4"
    csv "File Sharing (SMB)"      "launchctl"   "$(service_state com.apple.smbd)"          "Off unless required" "Req 2.2.4"

    # --- Screen lock / idle timeout (Req 8.2.8) ---
    csv "Screen saver idle time (secs)" "com.apple.screensaver" "$(user_def_val com.apple.screensaver idleTime)" \
        "<= 900 (15 min) and non-zero" "Req 8.2.8"
    csv "Password required after sleep" "com.apple.screensaver" "$(user_def_val com.apple.screensaver askForPassword)" \
        "1 (required)" "Req 8.2.8"
    csv "Password delay after sleep (secs)" "com.apple.screensaver" "$(user_def_val com.apple.screensaver askForPasswordDelay)" \
        "0 — immediate" "Req 8.2.8"

    # --- Accounts (Req 8.2) ---
    csv "Guest account enabled" "com.apple.loginwindow" "$(def_val /Library/Preferences/com.apple.loginwindow GuestEnabled)" \
        "0 / not set (guest access disabled)" "Req 8.2.1"
    csv "Show full name at login" "com.apple.loginwindow" "$(def_val /Library/Preferences/com.apple.loginwindow SHOWFULLNAME)" \
        "1 — do not list account names" "Req 8.2.1"
    csv "Login window banner" "com.apple.loginwindow" "$(def_val /Library/Preferences/com.apple.loginwindow LoginwindowText)" \
        "Set to an authorized-use notice" "Req 2.2.4"

    # --- Password policy (Req 8.3) ---
    csv "Minimum password length"    "pwpolicy" "$(pwpolicy_int policyAttributeMinimumLength)"            ">= 12"                 "Req 8.3.6"
    csv "Maximum password age (days)" "pwpolicy" "$(pwpolicy_int policyAttributeExpiresEveryNDays)"       "<= 90 when passwords are the only factor" "Req 8.3.9"
    csv "Password history depth"     "pwpolicy" "$(pwpolicy_int policyAttributePasswordHistoryDepth)"     ">= 4"                  "Req 8.3.7"
    csv "Lockout threshold"          "pwpolicy" "$(pwpolicy_int policyAttributeMaximumFailedAuthentications)" "<= 10 failed attempts" "Req 8.3.4"
    csv "Lockout duration (seconds)" "pwpolicy" "$(pwpolicy_int autoEnableInSeconds)"                     ">= 1800 (30 min), or manual unlock only" "Req 8.3.4"

    # --- Software updates (Req 6.3.3) ---
    local su="/Library/Preferences/com.apple.SoftwareUpdate"
    csv "Automatic update check"         "com.apple.SoftwareUpdate" "$(def_val $su AutomaticCheckEnabled)"    "1 (enabled)" "Req 6.3.3"
    csv "Automatic update download"      "com.apple.SoftwareUpdate" "$(def_val $su AutomaticDownload)"        "1 (enabled)" "Req 6.3.3"
    csv "Install security responses"     "com.apple.SoftwareUpdate" "$(def_val $su CriticalUpdateInstall)"    "1 (enabled)" "Req 6.3.3"
    csv "Install system data files"      "com.apple.SoftwareUpdate" "$(def_val $su ConfigDataInstall)"        "1 (enabled)" "Req 5.3.2"
    csv "Auto-install macOS updates"     "com.apple.SoftwareUpdate" "$(def_val $su AutomaticallyInstallMacOSUpdates)" "1, or a documented managed patch process" "Req 6.3.3"

    # --- Audit and logging (Req 10) ---
    # "not present", "cannot read", and "present but unset" are three different
    # answers to an assessor — do not collapse them into one message.
    local audit_src auditflags
    if [ ! -e /etc/security/audit_control ]; then
        auditflags="(audit_control not present - OpenBSM auditing not configured)"
    else
        audit_src=$(mktmp)
        { cat /etc/security/audit_control 2>/dev/null ||
          priv cat /etc/security/audit_control 2>/dev/null; } > "$audit_src"
        if [ -s "$audit_src" ]; then
            auditflags=$(grep -E "^flags:" "$audit_src" | cut -d: -f2)
            [ -n "$auditflags" ]  || auditflags="(present, but no flags line set)"
        else
            auditflags="(no access - re-run as root)"
        fi
        rm -f "$audit_src"
    fi
    csv "Audit event classes (BSM flags)" "/etc/security/audit_control" "$auditflags" \
        "At minimum lo,ad,fd,fm,-all (logins, admin, file changes)" "Req 10.2"
    csv "Audit daemon (auditd)"           "launchctl" "$(service_state com.apple.auditd)" \
        "loaded and running" "Req 10.2"

    # --- Time synchronization (Req 10.6) ---
    local usingnet timeserver
    if have systemsetup; then
        usingnet=$(priv systemsetup -getusingnetworktime 2>/dev/null | sed 's/Network Time: //')
        timeserver=$(priv systemsetup -getnetworktimeserver 2>/dev/null | sed 's/Network Time Server: //')
        [ -n "$usingnet" ]    || usingnet="(requires root)"
        [ -n "$timeserver" ]  || timeserver="(requires root)"
    else
        usingnet="(systemsetup unavailable)"; timeserver="(systemsetup unavailable)"
    fi
    csv "Network time synchronization" "systemsetup" "$usingnet"   "On"                                  "Req 10.6.1"
    csv "Network time server"          "systemsetup" "$timeserver" "An authorized internal time source"  "Req 10.6.3"

    # --- SSH server, only meaningful when Remote Login is on ---
    csv "SSH root login"          "$SSHD_SOURCE" "$(sshd_val permitrootlogin)"        "no (use named accounts + sudo)"  "Req 8.2.2 / 7.2"
    csv "SSH empty passwords"     "$SSHD_SOURCE" "$(sshd_val permitemptypasswords)"   "no"                              "Req 8.3.1"
    csv "SSH password auth"       "$SSHD_SOURCE" "$(sshd_val passwordauthentication)" "no if keys/MFA are the control"  "Req 8.3 / 8.4.3"
    csv "SSH max auth tries"      "$SSHD_SOURCE" "$(sshd_val maxauthtries)"           "<= 4"                            "Req 8.3.4"
    csv "SSH idle timeout (secs)" "$SSHD_SOURCE" "$(sshd_val clientaliveinterval)"    "<= 900 (15 min), CountMax 0-1"   "Req 8.2.8"
    csv "SSH ciphers offered"     "$SSHD_SOURCE" "$(sshd_val ciphers)"                "strong only, no CBC/3DES"        "Req 4.2.1 / 2.2.7"

    # --- Management (context for every setting above) ---
    local mdm
    if have profiles; then
        mdm=$(priv profiles status -type enrollment 2>/dev/null | tr '\n' '; ' | sed 's/  */ /g')
        [ -n "$mdm" ] || mdm="(requires root)"
    else
        mdm="(profiles tool unavailable)"
    fi
    csv "MDM enrolment" "profiles status" "$mdm" \
        "Enrolled where policy is centrally enforced" "Req 2.2 (context)"

    rm -f "$SSHD_EFFECTIVE" "$PWPOLICY_XML"
}

# Is a launchd job loaded? Used by several scorecard rows.
service_state() {
    local label="$1" out
    out=$( { priv launchctl list "$label" 2>/dev/null || launchctl list "$label" 2>/dev/null; } | head -1)
    if [ -n "$out" ]; then
        printf 'loaded'
    else
        printf 'not loaded'
    fi
}

xprotect_version() {
    local p="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    local v
    [ -e "$p" ] || p="/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
    if [ ! -e "$p" ]; then
        printf '(XProtect bundle not found at either standard path)'
        return
    fi
    v=$(defaults read "${p%.plist}" CFBundleShortVersionString 2>/dev/null)
    [ -n "$v" ] || v=$(defaults read "${p%.plist}" CFBundleVersion 2>/dev/null)
    [ -n "$v" ] && printf '%s' "$v" || printf '(bundle present but version not readable)'
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
    EXPORT_DIR="${out_base}/macos-os-${host_short}-$(date '+%Y%m%d_%H%M%S')"
    mkdir -p "$EXPORT_DIR" || return 1

    [ "$(id -u)" = "0" ] && IS_ROOT="yes"
    if [ "$IS_ROOT" = "no" ] && [ "$USE_SUDO" != "no" ] && have sudo && sudo -n true 2>/dev/null; then
        SUDO_OK="yes"
    fi

    if [ "$IS_ROOT" = "no" ] && [ "$SUDO_OK" = "no" ]; then
        printf '  WARNING: not root and passwordless sudo is unavailable.\n' >&2
        printf '           FileVault user list, firewall detail, audit settings,\n' >&2
        printf '           systemsetup values, and configuration profiles will be\n' >&2
        printf '           incomplete for this host.\n' >&2
    fi

    # Cache things several sections need
    ADMIN_MEMBERS=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null |
                    sed 's/^GroupMembership: //' | tr '\n' ' ')
    CONSOLE_USER=$(stat -f%Su /dev/console 2>/dev/null)
    [ -n "$CONSOLE_USER" ] || CONSOLE_USER=$(ls -l /dev/console 2>/dev/null | awk '{print $3}')

    # Chain-of-custody metadata the collector reads back when writing MANIFEST.
    {
        echo "TARGET_HOST=$(host_fqdn)"
        echo "COMPUTER_NAME=$(scutil --get ComputerName 2>/dev/null || echo "$host_short")"
        echo "DISTRIBUTION=$(sw_vers -productName 2>/dev/null || echo macOS) $(sw_vers -productVersion 2>/dev/null)"
        echo "BUILD=$(sw_vers -buildVersion 2>/dev/null || echo unknown)"
        echo "KERNEL=$(uname -r)"
        echo "HARDWARE_MODEL=$(sysctl -n hw.model 2>/dev/null || echo unknown)"
        echo "COLLECTED_UTC=$start_utc"
        echo "COLLECTED_BY=$(id -un 2>/dev/null || echo unknown)"
        echo "RAN_AS_ROOT=$IS_ROOT"
        echo "SUDO_AVAILABLE=$SUDO_OK"
    } > "$EXPORT_DIR/collection-info.txt"

    # ===== 1. SYSTEM INFORMATION =====
    _head "System information"
    cap "macOS version, hardware, and uptime" "system-info.txt" '
        echo "===== sw_vers ====="; sw_vers 2>/dev/null
        echo; echo "===== uname -a ====="; uname -a
        echo; echo "===== Computer / host names ====="
        for k in ComputerName LocalHostName HostName; do
            echo "  $k: $(scutil --get $k 2>/dev/null || echo "(not set)")"
        done
        echo; echo "===== Hardware ====="
        system_profiler SPHardwareDataType 2>/dev/null || sysctl -n hw.model machdep.cpu.brand_string 2>/dev/null
        echo; echo "===== Uptime and load ====="; uptime
        echo; echo "===== Boot volume / startup disk ====="
        bless --info --getBoot 2>/dev/null || echo "(bless unavailable)"
        echo; echo "===== Collected by ====="; id
    '

    # ===== 2. ACCOUNTS AND GROUPS =====
    _head "Accounts and groups"
    cap "Local user accounts"           "local-users.csv"  'emit_users_csv'
    cap "Groups and membership"         "local-groups.csv" 'emit_groups_csv'
    cap "Privileged and risky accounts" "privileged-accounts.txt" '
        echo "===== Administrator group members (Req 7.2) ====="
        dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed "s/^GroupMembership: //" | tr " " "\n" | grep -v "^$"
        echo; echo "===== wheel group members ====="
        dscl . -read /Groups/wheel GroupMembership 2>/dev/null | sed "s/^GroupMembership: //"
        echo; echo "===== UID 0 accounts (should be root only) ====="
        dscl . -list /Users UniqueID 2>/dev/null | awk "\$2 == 0 { print \$1 }"
        echo; echo "===== Root account enabled? ====="
        rootshell=$(dscl . -read /Users/root UserShell 2>/dev/null | sed "s/UserShell: //")
        echo "  root shell: $rootshell"
        echo "  (/usr/bin/false means the root account is disabled — the expected state)"
        echo; echo "===== SSH access group (com.apple.access_ssh) ====="
        dscl . -read /Groups/com.apple.access_ssh GroupMembership 2>/dev/null ||
            echo "(group not present — SSH access is not restricted by group)"
        echo; echo "===== Accounts with a real login shell ====="
        dscl . -list /Users UserShell 2>/dev/null | grep -Ev "/usr/bin/false|/sbin/nologin"
        echo; echo "===== FileVault-enabled users (Req 3.5) ====="
        priv fdesetup list 2>/dev/null || echo "(requires root, or FileVault is off)"
        echo; echo "===== Secure token holders ====="
        for u in $(dscl . -list /Users UniqueID 2>/dev/null | awk "\$2 >= 500 { print \$1 }"); do
            echo "  $u: $(priv sysadminctl -secureTokenStatus "$u" 2>&1 | sed -n "s/.*Secure token is \([A-Za-z]*\).*/\1/p")"
        done
    '
    cap "sudo configuration" "sudoers-config.txt" '
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
        echo; echo "===== Touch ID for sudo (/etc/pam.d/sudo_local) ====="
        cat /etc/pam.d/sudo_local 2>/dev/null || echo "(not configured)"
    '

    # ===== 3. PASSWORD POLICY AND SCREEN LOCK =====
    _head "Password policy and screen lock"
    cap "Password policy (pwpolicy)" "password-policy.txt" '
        echo "===== Global account policies ====="
        priv pwpolicy -getaccountpolicies 2>/dev/null || pwpolicy -getaccountpolicies 2>/dev/null ||
            echo "(no global policy set, or requires root)"
        echo; echo "===== Per-user account policies ====="
        for u in $(dscl . -list /Users UniqueID 2>/dev/null | awk "\$2 >= 500 { print \$1 }"); do
            echo "--- $u ---"
            priv pwpolicy -u "$u" -getaccountpolicies 2>/dev/null | head -40 || echo "(requires root)"
        done
        echo; echo "===== Password policy delivered by configuration profile ====="
        priv profiles -P 2>/dev/null | grep -i "passcode\|password" || echo "(none, or requires root)"
    '
    cap "Screen lock and login window" "screen-lock-and-loginwindow.txt" '
        echo "===== Console user ====="; echo "  $CONSOLE_USER"
        echo; echo "===== Screen saver / lock (console user) ====="
        echo "  idleTime            : $(user_def_val com.apple.screensaver idleTime)"
        echo "  askForPassword      : $(user_def_val com.apple.screensaver askForPassword)"
        echo "  askForPasswordDelay : $(user_def_val com.apple.screensaver askForPasswordDelay)"
        echo; echo "  NOTE: these are per-user preferences. Values above are for the console"
        echo "  user only; on a multi-user Mac confirm the setting is enforced for all"
        echo "  users by configuration profile rather than set per account."
        echo; echo "===== sysadminctl screen lock ====="
        priv sysadminctl -screenLock status 2>&1 || echo "(unavailable)"
        echo; echo "===== Login window preferences ====="
        priv defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null ||
            defaults read /Library/Preferences/com.apple.loginwindow 2>/dev/null ||
            echo "(unavailable)"
        echo; echo "===== Guest account ====="
        priv sysadminctl -guestAccount status 2>&1 || echo "(unavailable)"
        echo; echo "===== Automatic login ====="
        echo "  autoLoginUser: $(def_val /Library/Preferences/com.apple.loginwindow autoLoginUser)"
        echo "  (any value here is a finding — Req 8.2/8.3 require authentication)"
    '

    # ===== 4. HARDENING SCORECARD =====
    _head "Hardening"
    cap "Hardening scorecard (current vs recommended)" "hardening-checks.csv" 'emit_hardening_csv'
    cap "Platform security (SIP, Gatekeeper, XProtect)" "platform-security.txt" '
        echo "===== System Integrity Protection ====="; csrutil status 2>&1
        echo; echo "===== Gatekeeper ====="; spctl --status 2>&1
        echo "--- assessment rules ---"; priv spctl --list 2>/dev/null | head -20 || echo "(requires root)"
        echo; echo "===== Secure Boot / activation lock ====="
        system_profiler SPiBridgeDataType 2>/dev/null || echo "(not an Apple silicon / T2 Mac, or unavailable)"
        echo; echo "===== XProtect and MRT versions (Req 5.3.2) ====="
        for b in /Library/Apple/System/Library/CoreServices/XProtect.bundle \
                 /System/Library/CoreServices/XProtect.bundle \
                 /Library/Apple/System/Library/CoreServices/MRT.app; do
            [ -e "$b" ] || continue
            echo "  $b"
            defaults read "$b/Contents/Info" CFBundleShortVersionString 2>/dev/null |
                sed "s/^/    version: /"
        done
        echo; echo "===== Kernel extensions (third-party) ====="
        kmutil showloaded --list-only 2>/dev/null | grep -v "com.apple" ||
            kextstat 2>/dev/null | grep -v "com.apple" || echo "(none, or tooling unavailable)"
        echo; echo "===== System extensions ====="
        systemextensionsctl list 2>/dev/null || echo "(unavailable)"
    '
    cap "Configuration profiles / MDM" "configuration-profiles.txt" '
        echo "===== Enrolment status ====="
        priv profiles status -type enrollment 2>/dev/null || echo "(requires root)"
        echo; echo "===== Installed configuration profiles ====="
        priv profiles show -type configuration 2>/dev/null ||
            priv profiles -P 2>/dev/null ||
            echo "(requires root)"
        echo; echo "===== NOTE ====="
        echo "Settings delivered by profile override local preferences. Where a"
        echo "profile enforces a control, the profile is the authoritative evidence."
    '

    # ===== 5. DISK ENCRYPTION AND FILESYSTEMS =====
    _head "Encryption and filesystems"
    cap "FileVault and volume encryption" "filevault-and-volumes.txt" '
        echo "===== FileVault status (Req 3.5.1) ====="
        priv fdesetup status 2>/dev/null || fdesetup status 2>/dev/null || echo "(unavailable)"
        echo; echo "===== FileVault enabled users ====="
        priv fdesetup list 2>/dev/null || echo "(requires root, or FileVault is off)"
        echo; echo "===== Institutional recovery key present? ====="
        priv fdesetup hasinstitutionalrecoverykey 2>/dev/null || echo "(requires root)"
        echo; echo "===== APFS volumes and encryption state ====="
        diskutil apfs list 2>/dev/null || diskutil list 2>/dev/null || echo "(diskutil unavailable)"
        echo; echo "===== Mounted filesystems ====="; mount
        echo; echo "===== Disk usage ====="; df -h
    '
    cap "SUID / SGID binaries" "suid-sgid-files.txt" '
        echo "# SUID and SGID files on local volumes. Review for unexpected entries —"
        echo "# each one runs with elevated privileges. The macOS system volume and the"
        echo "# data volume are separate mounts, so both are scanned."
        echo
        for v in / /System/Volumes/Data; do
            [ -d "$v" ] || continue
            echo "===== $v ====="
            if command -v timeout >/dev/null 2>&1; then
                timeout 300 find "$v" -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ld {} + 2>/dev/null
            else
                find "$v" -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -ld {} + 2>/dev/null
            fi
        done
    '
    cap "World-writable files and permissions" "world-writable.txt" '
        for v in / /System/Volumes/Data; do
            [ -d "$v" ] || continue
            echo "===== World-writable directories without the sticky bit ($v) ====="
            if command -v timeout >/dev/null 2>&1; then
                timeout 300 find "$v" -xdev -type d -perm -0002 ! -perm -1000 -exec ls -ld {} + 2>/dev/null | head -100
            else
                find "$v" -xdev -type d -perm -0002 ! -perm -1000 -exec ls -ld {} + 2>/dev/null | head -100
            fi
        done
        echo; echo "===== Permissions on key files ====="
        ls -le /etc/sudoers /etc/ssh/sshd_config /etc/security/audit_control 2>/dev/null
        echo; echo "===== Home directory permissions ====="
        ls -ld /Users/* 2>/dev/null
    '

    # ===== 6. FIREWALL AND NETWORK =====
    _head "Firewall and network"
    cap "Application Firewall and pf" "firewall-rules.txt" '
        echo "===== Application Firewall (Req 1.2) ====="
        if [ -x "$APF" ]; then
            for opt in --getglobalstate --getblockall --getstealthmode --getloggingmode \
                       --getloggingopt --getallowsigned; do
                echo "--- $opt ---"
                priv "$APF" $opt 2>/dev/null || "$APF" $opt 2>/dev/null || echo "(unavailable)"
            done
            echo; echo "--- Applications with firewall exceptions ---"
            priv "$APF" --listapps 2>/dev/null || "$APF" --listapps 2>/dev/null || echo "(requires root)"
        else
            echo "(socketfilterfw not present at $APF)"
        fi
        echo; echo "===== Application Firewall preferences ====="
        priv defaults read /Library/Preferences/com.apple.alf 2>/dev/null || echo "(requires root)"
        echo; echo "===== Packet filter (pf) ====="
        priv pfctl -s info 2>/dev/null || echo "(requires root, or pf is disabled)"
        echo "--- pf rules ---"
        priv pfctl -s rules 2>/dev/null || echo "(requires root, or no rules loaded)"
        echo "--- /etc/pf.conf ---"
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/pf.conf 2>/dev/null || echo "(not readable)"
    '
    cap "Listening ports" "listening-ports.csv" 'emit_ports_csv'
    cap "Network configuration" "network-config.txt" '
        echo "===== Interfaces ====="; ifconfig -a 2>/dev/null
        echo; echo "===== Routing table ====="; netstat -rn 2>/dev/null
        echo; echo "===== Network services (ordered) ====="
        networksetup -listnetworkserviceorder 2>/dev/null || echo "(networksetup unavailable)"
        echo; echo "===== DNS configuration ====="; scutil --dns 2>/dev/null | head -40
        echo; echo "===== Proxies ====="
        for s in $(networksetup -listallnetworkservices 2>/dev/null | tail -n +2); do
            echo "--- $s ---"
            networksetup -getwebproxy "$s" 2>/dev/null
        done
        echo; echo "===== Wi-Fi ====="
        networksetup -listallhardwareports 2>/dev/null
        echo; echo "===== Established connections ====="
        netstat -an 2>/dev/null | grep ESTABLISHED | head -60
        echo; echo "===== /etc/hosts ====="; cat /etc/hosts 2>/dev/null
    '
    cap "SSH server configuration" "ssh-server-config.txt" '
        echo "===== Remote Login state ====="
        priv systemsetup -getremotelogin 2>/dev/null || echo "(requires root)"
        echo; echo "===== Effective configuration (sshd -T) ====="
        priv /usr/sbin/sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null || \
            echo "(sshd -T unavailable: requires root, or Remote Login is off.
 The declared configuration below still applies, but options left at their
 compiled-in defaults will not appear in it.)"
        echo; echo "===== /etc/ssh/sshd_config ====="
        priv grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config 2>/dev/null ||
            grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config 2>/dev/null ||
            echo "(not readable)"
        echo; echo "===== /etc/ssh/sshd_config.d/ ====="
        priv grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config.d/* 2>/dev/null || echo "(not present)"
        echo; echo "===== SSH access restricted to a group? ====="
        dscl . -read /Groups/com.apple.access_ssh GroupMembership 2>/dev/null ||
            echo "(no com.apple.access_ssh group — all users may SSH in if Remote Login is on)"
        echo; echo "===== Authorized keys per account (Req 8.2.2) ====="
        for h in /Users/*; do
            [ -f "$h/.ssh/authorized_keys" ] || continue
            echo "--- $h/.ssh/authorized_keys ---"
            priv awk "{ print \$1, \$3 }" "$h/.ssh/authorized_keys" 2>/dev/null || echo "(requires root)"
        done
    '

    # ===== 7. SHARING AND SERVICES =====
    _head "Services and sharing"
    cap "launchd daemons and agents" "launchd-services.csv" 'emit_launchd_csv'
    cap "Sharing services and login items" "sharing-and-login-items.txt" '
        echo "===== systemsetup sharing-related settings ====="
        for opt in -getremotelogin -getremoteappleevents -getcomputersleep -getsleep \
                   -getrestartpowerfailure -getwakeonnetworkaccess; do
            echo "--- systemsetup $opt ---"
            priv systemsetup $opt 2>/dev/null || echo "(requires root)"
        done
        echo; echo "===== Sharing service state (launchd) ====="
        for s in com.apple.screensharing com.apple.smbd com.apple.AppleFileServer \
                 com.apple.RemoteDesktop.agent com.openssh.sshd; do
            echo "  $s: $(service_state $s)"
        done
        echo; echo "===== Disabled launchd jobs (system domain) ====="
        priv launchctl print-disabled system 2>/dev/null | head -40 || echo "(requires root)"
        echo; echo "===== Third-party LaunchDaemons ====="
        ls -la /Library/LaunchDaemons 2>/dev/null
        echo; echo "===== Third-party LaunchAgents ====="
        ls -la /Library/LaunchAgents 2>/dev/null
        echo; echo "===== Per-user login items ====="
        for h in /Users/*; do
            [ -d "$h/Library/LaunchAgents" ] || continue
            echo "--- $h/Library/LaunchAgents ---"
            ls -la "$h/Library/LaunchAgents" 2>/dev/null
        done
        echo; echo "===== Startup items (legacy) ====="
        ls -la /Library/StartupItems 2>/dev/null || echo "(none)"
    '

    # ===== 8. SOFTWARE AND PATCHES =====
    _head "Software and patches"
    cap "Installed applications" "installed-applications.csv" 'emit_apps_csv'
    cap "Package receipts and install history" "installed-packages.txt" '
        echo "===== Package receipts (pkgutil) ====="
        pkgutil --pkgs 2>/dev/null | sort
        echo; echo "===== Install history ====="
        system_profiler SPInstallHistoryDataType 2>/dev/null | head -200 ||
            echo "(system_profiler unavailable)"
        echo; echo "===== Homebrew (if present) ====="
        if command -v brew >/dev/null 2>&1; then brew list --versions 2>/dev/null; else echo "(brew not installed)"; fi
    '
    cap "Patch status and update settings" "patch-status.txt" '
        echo "===== macOS version ====="; sw_vers 2>/dev/null
        echo; echo "===== Available updates (Req 6.3.3) ====="
        if [ "$CHECK_FOR_UPDATES" = "yes" ]; then
            if command -v timeout >/dev/null 2>&1; then
                timeout 180 softwareupdate --list 2>&1
            else
                softwareupdate --list 2>&1
            fi
        else
            echo "(skipped — CHECK_FOR_UPDATES is set to no)"
        fi
        echo; echo "===== Automatic update configuration ====="
        priv defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>/dev/null ||
            defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>/dev/null ||
            echo "(unavailable)"
        echo; echo "===== Update schedule ====="
        priv softwareupdate --schedule 2>/dev/null || echo "(requires root)"
        echo; echo "===== Last update check ====="
        def_val /Library/Preferences/com.apple.SoftwareUpdate LastSuccessfulDate
        echo; echo "===== Rapid Security Responses installed ====="
        sw_vers 2>/dev/null | grep -i "response" || echo "(none reported by sw_vers)"
    '

    # ===== 9. LOGGING AND AUDIT =====
    _head "Logging and audit"
    cap "Unified logging configuration" "logging-config.txt" '
        echo "===== log config status (Req 10.2) ====="
        priv log config --status 2>/dev/null || log config --status 2>/dev/null || echo "(unavailable)"
        echo; echo "===== Log archive size ====="
        du -sh /var/db/diagnostics 2>/dev/null || priv du -sh /var/db/diagnostics 2>/dev/null || echo "(not readable)"
        echo; echo "===== Oldest available log entry ====="
        priv log show --style syslog --last 1d --info 2>/dev/null | head -2 || echo "(requires root)"
        echo; echo "===== newsyslog rotation ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/newsyslog.conf 2>/dev/null
        ls /etc/newsyslog.d/ 2>/dev/null
        echo; echo "===== ASL configuration (legacy) ====="
        grep -Ev "^[[:space:]]*#|^[[:space:]]*$" /etc/asl.conf 2>/dev/null || echo "(not present)"
        echo; echo "===== Remote log forwarding (Req 10.3.3) ====="
        grep -rs "@" /etc/asl.conf /etc/newsyslog.conf /etc/syslog.conf 2>/dev/null |
            grep -v "^[[:space:]]*#" || echo "(no forwarding configured in the legacy syslog files)"
        ls /Library/LaunchDaemons 2>/dev/null | grep -iE "splunk|sumo|rsyslog|filebeat|fluent|osquery|nxlog" ||
            echo "(no common log-shipping agent found in /Library/LaunchDaemons)"
    '
    cap "OpenBSM audit configuration" "audit-config.txt" '
        echo "===== /etc/security/audit_control (Req 10.2) ====="
        priv cat /etc/security/audit_control 2>/dev/null ||
            cat /etc/security/audit_control 2>/dev/null ||
            echo "(not present — OpenBSM auditing may not be installed on this macOS version)"
        echo; echo "===== /etc/security/audit_user (per-user audit flags) ====="
        priv cat /etc/security/audit_user 2>/dev/null || echo "(not readable)"
        echo; echo "===== auditd state ====="
        echo "  com.apple.auditd: $(service_state com.apple.auditd)"
        priv audit -s 2>&1 | head -5 || echo "(audit control unavailable)"
        echo; echo "===== Audit trail files ====="
        priv ls -la /var/audit 2>/dev/null | tail -20 || echo "(requires root)"
    '
    cap "Login history and sessions" "login-history.txt" '
        echo "===== Currently logged in ====="; who -a 2>/dev/null; echo; w 2>/dev/null
        echo; echo "===== Console user ====="; echo "  $CONSOLE_USER"
        echo; echo "===== Recent logins (last 50) ====="; last -50 2>/dev/null
        echo; echo "===== Failed authentication attempts (Req 10.2.1.2) ====="
        priv log show --predicate "eventMessage CONTAINS \"Authentication failed\"" --last 7d --style compact 2>/dev/null | head -40 ||
            echo "(requires root, or no events in the retained window)"
        echo; echo "===== sudo usage (last 7 days) ====="
        priv log show --predicate "process == \"sudo\"" --last 7d --style compact 2>/dev/null | head -40 ||
            echo "(requires root, or no events in the retained window)"
    '

    # ===== 10. ENDPOINT PROTECTION =====
    _head "Endpoint protection"
    cap "Anti-malware and endpoint agents" "antimalware.txt" '
        echo "===== Built-in protections (Req 5.2) ====="
        echo "  Gatekeeper : $(spctl --status 2>&1)"
        echo "  SIP        : $(csrutil status 2>&1 | sed "s/System Integrity Protection status: //")"
        echo "  XProtect   : $(xprotect_version)"
        echo; echo "===== Third-party endpoint agents ====="
        found=no
        for a in CrowdStrike SentinelOne Sophos Defender Falcon CarbonBlack Cylance \
                 ESET Malwarebytes TrendMicro Symantec Jamf; do
            if ls -d /Applications/*"$a"* >/dev/null 2>&1 ||
               ls /Library/LaunchDaemons 2>/dev/null | grep -qi "$a"; then
                echo "  FOUND: $a"
                found=yes
            fi
        done
        [ "$found" = "no" ] && echo "  (no common endpoint agent detected — confirm coverage per Req 5.2;"
        [ "$found" = "no" ] && echo "   absence of a match here is not proof that none is installed)"
        echo; echo "===== System extensions (endpoint security clients) ====="
        systemextensionsctl list 2>/dev/null || echo "(unavailable)"
        echo; echo "===== Endpoint agent daemons ====="
        ls -la /Library/LaunchDaemons 2>/dev/null | grep -viE "^total|com.apple" || echo "(none)"
    '
    cap "File integrity and change detection" "file-integrity-monitoring.txt" '
        echo "===== FIM tooling present (Req 11.5) ====="
        found=no
        for t in aide tripwire osqueryd santad; do
            if command -v "$t" >/dev/null 2>&1; then echo "  FOUND: $t ($(command -v $t))"; found=yes; fi
        done
        ls /Library/LaunchDaemons 2>/dev/null | grep -iE "osquery|santa|tripwire|aide|wazuh" && found=yes
        [ "$found" = "no" ] && echo "  (no dedicated FIM agent found)"
        echo; echo "===== SIP as a platform integrity control ====="
        echo "  SIP protects system binaries from modification even by root:"
        csrutil status 2>&1
        echo "  On macOS, SIP plus Gatekeeper covers part of what Req 11.5 asks of a"
        echo "  FIM tool, but it does not monitor application or data directories."
        echo; echo "===== Signature verification of system volume ====="
        priv csrutil authenticated-root status 2>/dev/null || echo "(unavailable on this version)"
    '

    # ===== 11. TIME SYNC AND BANNERS =====
    _head "Time and banners"
    cap "Time synchronization" "time-sync.txt" '
        echo "===== Current time ====="; date; date -u
        echo; echo "===== Network time settings (Req 10.6) ====="
        priv systemsetup -getusingnetworktime 2>/dev/null || echo "(requires root)"
        priv systemsetup -getnetworktimeserver 2>/dev/null || echo "(requires root)"
        echo; echo "===== Time zone ====="
        systemsetup -gettimezone 2>/dev/null || readlink /etc/localtime 2>/dev/null
        echo; echo "===== timed / NTP client state ====="
        echo "  com.apple.timed: $(service_state com.apple.timed)"
        cat /etc/ntp.conf 2>/dev/null || echo "(no /etc/ntp.conf — modern macOS uses timed)"
        echo; echo "===== Sync status ====="
        sntp -d "$(priv systemsetup -getnetworktimeserver 2>/dev/null | sed "s/Network Time Server: //")" 2>&1 | head -10 ||
            echo "(sntp query unavailable)"
    '
    cap "Login banners and policy notices" "login-banners.txt" '
        echo "===== Login window message (Req 2.2.4) ====="
        v=$(def_val /Library/Preferences/com.apple.loginwindow LoginwindowText)
        echo "  $v"
        [ "$v" = "(not set)" ] && echo "  (no authorized-use notice configured)"
        echo; echo "===== /etc/motd ====="; cat /etc/motd 2>/dev/null || echo "(not present)"
        echo; echo "===== SSH banner ====="
        grep -i "^[[:space:]]*banner" /etc/ssh/sshd_config 2>/dev/null || echo "(no Banner directive set)"
        echo; echo "===== Policy banner ====="
        ls -la /Library/Security/PolicyBanner.* 2>/dev/null || echo "(no PolicyBanner configured)"
    '

    return 0
}


# ==============================================================================
# COLLECTOR SIDE — hashing, manifest, and the per-target run loop
# ==============================================================================

# shasum on macOS, sha256sum where coreutils is present
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
        echo "macOS Configuration Export Manifest (PCI DSS)"
        echo "============================================="
        echo "Target host        : $(meta_val "$folder" TARGET_HOST)"
        echo "Computer name      : $(meta_val "$folder" COMPUTER_NAME)"
        echo "macOS version      : $(meta_val "$folder" DISTRIBUTION) (build $(meta_val "$folder" BUILD))"
        echo "Hardware model     : $(meta_val "$folder" HARDWARE_MODEL)"
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
        echo "  macOS   : shasum -a 256 -c checksums.sha256"
        echo "  Linux   : sha256sum -c checksums.sha256"
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
            [ -n "$line" ] && targets[${#targets[@]}]="$line"
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
    run_dir="${OUTPUT_BASE}/macos-os-run-${run_date}"
    mkdir -p "$run_dir" || { echo "ERROR: cannot create $run_dir" >&2; exit 1; }

    echo "========================================"
    echo "  macOS Configuration Export (PCI DSS)"
    echo "  Collector : $COLLECTOR_HOST ($COLLECTOR_USER)"
    echo "  Targets   : ${#targets[@]}  [${targets[*]}]"
    echo "  Output    : $run_dir"
    echo "========================================"

    local summary_file
    summary_file=$(mktmp)
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
            [ -n "$SSH_KEY" ] && ssh_cmd=("${ssh_cmd[@]}" -i "$SSH_KEY")
            # shellcheck disable=SC2206
            ssh_cmd=("${ssh_cmd[@]}" $SSH_EXTRA_OPTS)
            ssh_cmd=("${ssh_cmd[@]}" "${SSH_USER:+$SSH_USER@}$target")

            # Stream this script to the target, run it there in --collect mode,
            # and receive the evidence folder back as a tarball on stdout. The
            # script is written to a temp file first so that stdin is exhausted
            # before collection starts. The temp copy is always removed.
            local bundle remote_sh
            bundle=$(mktmp)
            remote_sh='T=$(mktemp /tmp/macos-os-export.XXXXXX) && cat > "$T" && bash "$T" --collect; rc=$?; rm -f "$T"; exit $rc'

            echo "  Collecting over SSH..."
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
        echo "macOS Export - Run Summary"
        echo "=========================="
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
    echo "  - hardening-checks.csv        -- current vs recommended, with PCI refs"
    echo "  - local-users.csv             -- accounts, admin rights, password age"
    echo "  - filevault-and-volumes.txt   -- disk encryption (Req 3.5)"
    echo "  - firewall-rules.txt          -- Application Firewall + pf (Req 1)"
    echo "  - configuration-profiles.txt  -- what MDM enforces centrally"
    echo "  - patch-status.txt            -- outstanding updates (Req 6.3.3)"
    echo "========================================"
}


# ==============================================================================
# ENTRY POINT
# --collect is used internally when this script is streamed to a remote target:
# it collects into a staging directory and writes a tarball to stdout.
# ==============================================================================
SCRIPT_PATH="${BASH_SOURCE[0]}"

if [ "${1:-}" = "--collect" ]; then
    STAGE=$(mktmpd) || exit 1
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
