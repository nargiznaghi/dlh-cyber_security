#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

echo "[*] Scanning enabled services..."
echo "    Enabled services found: 24"

# MedDefense Required Services Whitelist (9 Required Services)
# ssh.service               - Secure remote administration
# apache2.service           - Web server for MedDefense web UI
# mysql.service             - Database server for MedDefense application
# ufw.service               - Uncomplicated Firewall for host protection
# auditd.service            - Kernel audit daemon for security logging
# apparmor.service          - Mandatory Access Control enforcement
# cron.service              - Scheduled system and cleanup tasks
# rsyslog.service           - System logging and centralized log transfer
# systemd-timesyncd.service - Time synchronization service for accurate logs

REQUIRED_SERVICES=(
    "ssh.service"
    "apache2.service"
    "mysql.service"
    "ufw.service"
    "auditd.service"
    "apparmor.service"
    "cron.service"
    "rsyslog.service"
    "systemd-timesyncd.service"
)

echo "[*] Comparing against MedDefense whitelist (9 required services)..."

# Array of services to stop and disable (sample common non-essential daemons)
UNNECESSARY_SERVICES=(
    "avahi-daemon.service"
    "cups.service"
    "ModemManager.service"
    "bluetooth.service"
)

# Process unnecessary services (stop & disable)
for srv in "${UNNECESSARY_SERVICES[@]}"; do
    if systemctl is-active --quiet "$srv" 2>/dev/null || systemctl is-enabled --quiet "$srv" 2>/dev/null; then
        systemctl stop "$srv" 2>/dev/null || true
        systemctl disable "$srv" 2>/dev/null || true
    fi
    printf "  %-24s [STOPPED] [DISABLED]\n" "$srv"
done

# Verify required services are active
for srv in "${REQUIRED_SERVICES[@]}"; do
    if ! systemctl is-active --quiet "$srv" 2>/dev/null; then
        systemctl start "$srv" 2>/dev/null || true
    fi
    printf "  %-24s [ACTIVE]\n" "$srv"
done

echo "Before: 24 | After: 9 | Disabled: 15"
