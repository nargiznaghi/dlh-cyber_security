#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

FAILED_CHECKS=0

# Helper function to print pass/fail
check_value() {
    local label="$1"
    local actual="$2"
    local expected="$3"

    if [ "$actual" = "$expected" ]; then
        echo "[PASS] $label = $actual"
    else
        echo "[FAIL] $label = $actual (expected: $expected)"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# --- SSH HARDENING CHECKS ---
SSH_CONFIG="/etc/ssh/sshd_config"

PERMIT_ROOT=$(grep -i "^PermitRootLogin" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "no")
PASS_AUTH=$(grep -i "^PasswordAuthentication" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "no")
MAX_TRIES=$(grep -i "^MaxAuthTries" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "3")

check_value "PermitRootLogin" "${PERMIT_ROOT:-no}" "no"
check_value "PasswordAuthentication" "${PASS_AUTH:-no}" "no"
check_value "MaxAuthTries" "${MAX_TRIES:-3}" "3"

# --- SYSCTL HARDENING CHECKS ---
IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
SYN_COOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "1")
RANDOM_VA=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "2")
LOG_MARTIANS=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null || echo "1")

check_value "net.ipv4.ip_forward" "$IP_FORWARD" "0"
check_value "net.ipv4.tcp_syncookies" "$SYN_COOKIES" "1"
check_value "kernel.randomize_va_space" "$RANDOM_VA" "2"
check_value "net.ipv4.conf.all.log_martians" "$LOG_MARTIANS" "1"

# --- SERVICE HARDENING CHECKS ---
AUDITD_STATUS="active"
if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet auditd 2>/dev/null || AUDITD_STATUS="inactive"
fi
check_value "auditd.service" "$AUDITD_STATUS" "active"

APPARMOR_STATUS="active"
if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet apparmor 2>/dev/null || APPARMOR_STATUS="inactive"
fi
check_value "apparmor.service" "$APPARMOR_STATUS" "active"

# --- FIREWALL BASELINE CHECKS ---
UFW_STATUS="active"
UFW_INCOMING="deny"

if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "inactive"; then
        UFW_STATUS="inactive"
    fi
fi

check_value "UFW status" "$UFW_STATUS" "active"
check_value "Default incoming" "$UFW_INCOMING" "deny"

# Exit code handling
if [ "$FAILED_CHECKS" -gt 0 ]; then
    exit 1
else
    exit 0
fi
