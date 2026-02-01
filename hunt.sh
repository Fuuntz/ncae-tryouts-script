#!/bin/bash
# NCAE Passive Threat Scanner
# Usage: sudo ./hunt.sh
# "Report, Don't Pause"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

echo -e "${BLUE}=== NCAE Security Report ===${NC}"

# --- Helper Functions ---
pass() {
    echo -e "${GREEN}[ OK ]${NC} $1"
}

warn() {
    echo -e "${RED}[WARN]${NC} $1"
    echo -e "       ${YELLOW}FIX:${NC} $2"
}

# --- 1. Shell Hygiene ---

# Check Aliases
if [ -n "$(alias)" ]; then
    warn "Malicious aliases detected (commands might be hijacked)." \
         "unalias -a"
else
    pass "No aliases found (Clean Shell)"
fi

# Check .bashrc Immutability
# Note: Checking root and current user
IMMUTABLE=$(lsattr /root/.bashrc /home/*/.bashrc 2>/dev/null | grep "\-i\-")
if [ -n "$IMMUTABLE" ]; then
    warn ".bashrc is IMMUTABLE (cannot be edited, likely malicious)." \
         "chattr -i <file>"
else
    pass ".bashrc attributes are mutable (Normal)"
fi

# --- 2. Identity ---

# Check UID 0
FAKE_ROOTS=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [ -n "$FAKE_ROOTS" ]; then
    warn "Found unauthorized UID 0 users: $FAKE_ROOTS" \
         "userdel -f -r $FAKE_ROOTS"
else
    pass "No fake root accounts (UID 0 Check Clean)"
fi

# Check Sudoers
# Users in sudo group other than 'user'
SUDO_USERS=$(grep '^sudo:' /etc/group | cut -d: -f4 | tr ',' ' ')
BAD_ADMINS=""
for u in $SUDO_USERS; do
    if [[ "$u" != "user" && "$u" != "ssh-user" ]]; then
        BAD_ADMINS="$BAD_ADMINS $u"
    fi
done

if [ -n "$BAD_ADMINS" ]; then
    warn "Unauthorized admins found in 'sudo' group: $BAD_ADMINS" \
         "gpasswd -d <user> sudo"
else
    pass "Sudo group is clean (Only authorized admins)"
fi

# Check Shells
# Users with /bin/sh or other shells who are standard users (UID >= 1000)
# We expect /bin/bash. /bin/esrever is definitely bad.
BAD_SHELLS=$(awk -F: '($3 >= 1000 && $7 !~ /\/bin\/bash/ && $7 !~ /nologin/ && $7 !~ /false/) {print $1 " (" $7 ")"}' /etc/passwd)
if [ -n "$BAD_SHELLS" ]; then
    warn "Suspicious shells found for users: $BAD_SHELLS" \
         "chsh -s /bin/bash <user>"
else
    pass "User shells look normal (/bin/bash)"
fi

# --- 3. Network & Persistence ---

# Check Listeners
# Looking for common backdoor ports or netcat
SUS_PORTS=$(ss -tulpn | grep -E ":(4444|1337|23|666|8000)")
if [ -n "$SUS_PORTS" ]; then
    warn "Suspicious ports detected (4444, 23, 8000, etc)!" \
         "Identify with 'ss -tulpn', then 'systemctl stop <service>' or 'kill <pid>'"
else
    pass "No common backdoor ports (4444, 23, 8000) listening"
fi

# Check SUID
# Fast check for dangerous GTFOBins
DANGEROUS=("vim" "nano" "cp" "find" "python3" "bash" "sh" "awk" "sed" "nmap")
FOUND_SUID=""
for bin in "${DANGEROUS[@]}"; do
    if [ -u "$(which $bin 2>/dev/null)" ]; then
        FOUND_SUID="$FOUND_SUID $bin"
    fi
done

if [ -n "$FOUND_SUID" ]; then
    warn "Dangerous SUID binaries found:$FOUND_SUID" \
         "chmod u-s \$(which <binary>)"
else
    pass "No common GTFOBins have SUID set"
fi

# Check Systemd (Modifications in last 24h)
RECENT_SERVICES=$(find /etc/systemd/system -type f -mtime -1 2>/dev/null)
if [ -n "$RECENT_SERVICES" ]; then
    warn "Systemd services modified in the last 24 hours:" \
         "Check these files: \n$RECENT_SERVICES"
else
    pass "No recent changes to Systemd services"
fi

# Check PAM
if grep -q "pam_permit.so" /etc/pam.d/common-auth; then
    warn "PAM backdoor detected (pam_permit.so)!" \
         "Edit /etc/pam.d/common-auth and remove the line."
else
    pass "PAM authentication looks clean"
fi

echo -e "${BLUE}=== Scanner Complete ===${NC}"
