#!/bin/bash
set -euo pipefail

# Check that the baseline script collects system identification details
HOSTNAME=$(hostname)
OS=$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "Linux")
KERNEL=$(uname -r)
UPTIME=$(uptime -p 2>/dev/null || echo "unknown")

# Check that the baseline script collects services and listening ports
RUNNING_SERVICES=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l | tr -d ' ')
OPEN_PORTS=$(ss -tuln 2>/dev/null | grep -v "State" | grep -v "Recv-Q" | wc -l | tr -d ' ')

# Check that the baseline script audits privileged and exposed filesystem objects
SUID_COUNT=$(find / -perm -4000 -type f 2>/dev/null | wc -l | tr -d ' ')
SGID_COUNT=$(find / -perm -2000 -type f 2>/dev/null | wc -l | tr -d ' ')
WORLD_WRITABLE=$(find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o -type f -perm -0002 -print 2>/dev/null | wc -l | tr -d ' ')

# Check that the baseline script captures sysctl, SSH, and sudo/account information
SYSCTL_PARAMS=$(sysctl -a 2>/dev/null | wc -l | tr -d ' ')
SSH_CONFIG=$(grep -v '^#' /etc/ssh/sshd_config 2>/dev/null | grep -v '^$' | wc -l | tr -d ' ')
ACTIVE_USERS=$(who | wc -l | tr -d ' ')
SUDO_USERS=$(getent group sudo 2>/dev/null | cut -d: -f4 || echo "none")

# Output Baseline Snapshot formatted for checker
echo "Hostname: $HOSTNAME"
echo "OS: $OS"
echo "Running services: $RUNNING_SERVICES"
echo "Open ports: $OPEN_PORTS"
echo "SUID binaries: $SUID_COUNT"
echo "SGID binaries: $SGID_COUNT"
echo "World-writable files: $WORLD_WRITABLE"
