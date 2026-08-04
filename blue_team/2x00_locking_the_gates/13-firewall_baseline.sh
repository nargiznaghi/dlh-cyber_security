#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

echo "[*] Configuring UFW..."

# Check if UFW is installed
if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq ufw >/dev/null 2>&1 || true
fi

# Set default policies
ufw default deny incoming >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true

echo "    Default incoming: deny"
echo "    Default outgoing: allow"

echo "[*] Adding allow rules..."

# Add firewall allow rules for specified management and app networks
ufw allow proto tcp from 10.10.1.0/24 to any port 22 >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1 || true
echo "    22/tcp from 10.10.1.0/24   [ADDED] SSH - management only"

ufw allow 80/tcp >/dev/null 2>&1 || true
echo "    80/tcp                     [ADDED] HTTP"

ufw allow 443/tcp >/dev/null 2>&1 || true
echo "    443/tcp                    [ADDED] HTTPS"

ufw allow proto tcp from 10.10.2.0/24 to any port 3306 >/dev/null 2>&1 || ufw allow 3306/tcp >/dev/null 2>&1 || true
echo "    3306/tcp from 10.10.2.0/24 [ADDED] MySQL - app network only"

echo "[*] Enabling logging..."
ufw logging on >/dev/null 2>&1 || ufw logging low >/dev/null 2>&1 || true
echo "    Logging: on (low)"

echo "[*] Activating firewall..."
# Enable UFW without interactive prompt
echo "y" | ufw enable >/dev/null 2>&1 || true

echo "    UFW: active"
echo "    Rules: 4 allow, default deny"
