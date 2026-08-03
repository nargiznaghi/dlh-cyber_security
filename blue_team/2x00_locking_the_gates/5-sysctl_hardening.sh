#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_BACKUP="/etc/sysctl.conf.bak"

echo "[*] Backing up /etc/sysctl.conf"
cp "$SYSCTL_CONF" "$SYSCTL_BACKUP"

# Array of sysctl settings to apply
declare -A PARAMS=(
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv6.conf.all.disable_ipv6"]="1"
    ["net.ipv6.conf.default.disable_ipv6"]="1"
    ["kernel.randomize_va_space"]="2"
    ["fs.suid_dumpable"]="0"
    ["kernel.dmesg_restrict"]="1"
    ["kernel.kptr_restrict"]="2"
)

# List of keys in exact required display order
PARAM_ORDER=(
    "net.ipv4.ip_forward"
    "net.ipv4.conf.all.accept_redirects"
    "net.ipv4.conf.default.accept_redirects"
    "net.ipv4.conf.all.send_redirects"
    "net.ipv4.conf.all.accept_source_route"
    "net.ipv4.conf.all.log_martians"
    "net.ipv4.tcp_syncookies"
    "net.ipv4.icmp_echo_ignore_broadcasts"
    "net.ipv6.conf.all.disable_ipv6"
    "net.ipv6.conf.default.disable_ipv6"
    "kernel.randomize_va_space"
    "fs.suid_dumpable"
    "kernel.dmesg_restrict"
    "kernel.kptr_restrict"
)

# Apply parameters to /etc/sysctl.conf
for key in "${PARAM_ORDER[@]}"; do
    val="${PARAMS[$key]}"
    if grep -qE "^[#]*\s*${key}\s*=" "$SYSCTL_CONF"; then
        sed -i -E "s|^[#]*\s*(${key}\s*=).*|\1 ${val}|" "$SYSCTL_CONF"
    else
        echo "${key} = ${val}" >> "$SYSCTL_CONF"
    fi
done

# Reload sysctl settings
sysctl -p >/dev/null 2>&1 || true

echo "[*] Applying kernel hardening parameters..."

PASS_COUNT=0
FAIL_COUNT=0

# Helper function to convert sysctl key to /proc/sys path
key_to_proc() {
    local key="$1"
    echo "/proc/sys/${key//./\/}"
}

for key in "${PARAM_ORDER[@]}"; do
    expected="${PARAMS[$key]}"
    proc_path=$(key_to_proc "$key")
    
    # Apply to current running kernel interface directly as fallback
    if [ -f "$proc_path" ]; then
        echo "$expected" > "$proc_path" 2>/dev/null || true
        actual=$(cat "$proc_path" 2>/dev/null || echo "N/A")
    else
        actual="N/A"
    fi

    if [ "$actual" = "$expected" ]; then
        printf "%-42s [PASS]\n" "${key} = ${expected}"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        printf "%-42s [FAIL]\n" "${key} = ${expected}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
done

TOTAL_APPLIED=${#PARAM_ORDER[@]}

echo "Parameters applied: ${TOTAL_APPLIED}"
echo "Verified PASS: ${PASS_COUNT}"
echo "Verified FAIL: ${FAIL_COUNT}"
