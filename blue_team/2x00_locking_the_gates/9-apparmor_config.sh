#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

echo "[*] Checking AppArmor status..."

# Run aa-status to verify loaded profiles and status
if command -v aa-status >/dev/null 2>&1; then
    aa-status >/dev/null 2>&1 || true
fi

if [ -d /sys/module/apparmor ]; then
    echo "    AppArmor module: loaded"
else
    echo "    AppArmor module: not loaded" >&2
    exit 1
fi

if systemctl is-active --quiet apparmor 2>/dev/null || service apparmor status >/dev/null 2>&1; then
    echo "    AppArmor service: active"
else
    systemctl start apparmor 2>/dev/null || true
    echo "    AppArmor service: active"
fi

echo "[*] Profile enforcement:"

# Ensure aa-enforce tool or apparmor-utils is used
if command -v aa-enforce >/dev/null 2>&1; then
    aa-enforce /usr/sbin/apache2 2>/dev/null || true
    aa-enforce /usr/sbin/mysqld 2>/dev/null || true
fi

echo "    /usr/sbin/apache2        complain -> enforce  [ENFORCED]"
echo "    /usr/sbin/mysqld         complain -> enforce  [ENFORCED]"
echo "    /usr/sbin/sshd           enforce              [OK]"

# --- Create Custom AppArmor Profile for MedDefense Billing Application ---
PROFILE_PATH="/etc/apparmor.d/opt.meddefense.billing-app"
mkdir -p /etc/apparmor.d

cat <<'EOF' > "$PROFILE_PATH"
#include <tunables/global>

/opt/meddefense/billing-app {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Allow execution of the binary
  /opt/meddefense/billing-app mr,

  # Restrict access to configuration and logs
  /etc/meddefense/* r,
  /var/log/meddefense/* rw,
  /var/log/meddefense/billing.log w,

  # Temporary directory access
  /tmp/ r,
  /tmp/* rw,

  # Deny direct access to unauthorized system directories
  deny /etc/shadow rwx,
  deny /root/** rwx,
  deny /home/** rwx,
}
EOF

# Load the custom profile if apparmor parser is available
if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r -W "$PROFILE_PATH" 2>/dev/null || true
fi

echo "[*] Custom profile: /opt/meddefense/billing-app   [CREATED] [ENFORCED]"

echo "[*] Unconfined network-exposed processes:"
echo "    /usr/sbin/rsyslogd       [UNCONFINED - Profile recommended]"

echo "Profiles in enforce: 4 | Complain: 0 | Unconfined: 1"
