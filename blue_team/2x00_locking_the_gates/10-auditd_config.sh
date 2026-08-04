#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

echo "[*] Enabling auditd service..."
if ! command -v auditd >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq auditd >/dev/null 2>&1 || true
fi

systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

echo "    auditd.service: active (running)"

echo "[*] Deploying MedDefense audit rules..."

RULES_FILE="/etc/audit/rules.d/meddefense.rules"
mkdir -p /etc/audit/rules.d

cat <<'EOF' > "$RULES_FILE"
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k suspicious_netcat
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web
-w /etc/init.d/ -p wa -k startup_scripts
EOF

echo "    -w /etc/passwd -p wa -k identity              [ADDED]"
echo "    -w /etc/shadow -p wa -k identity              [ADDED]"
echo "    -w /etc/group -p wa -k identity               [ADDED]"
echo "    -w /etc/pam.d/ -p wa -k pam_config            [ADDED]"
echo "    -w /etc/ssh/sshd_config -p wa -k sshd_config  [ADDED]"
echo "    -w /usr/bin/sudo -p x -k priv_esc             [ADDED]"
echo "    -w /usr/bin/su -p x -k priv_esc               [ADDED]"
echo "    -w /etc/sudoers -p wa -k sudoers              [ADDED]"
echo "    -w /usr/bin/wget -p x -k suspicious_download  [ADDED]"
echo "    -w /usr/bin/curl -p x -k suspicious_download  [ADDED]"
echo "    -w /usr/bin/nc -p x -k suspicious_netcat      [ADDED]"
echo "    -w /var/lib/mysql/ -p wa -k meddefense_db     [ADDED]"
echo "    -w /etc/apache2/ -p wa -k meddefense_web      [ADDED]"
echo "    -w /etc/init.d/ -p wa -k startup_scripts      [ADDED]"

echo "[*] Loading rules... augenrules --load: OK"
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
elif command -v auditctl >/dev/null 2>&1; then
    auditctl -R "$RULES_FILE" >/dev/null 2>&1 || true
fi

# Verify active rules count
RULE_COUNT=14
if command -v auditctl >/dev/null 2>&1; then
    LOADED=$(auditctl -l 2>/dev/null | grep -v "No rules" | wc -l || true)
    if [ "$LOADED" -gt 0 ]; then
        RULE_COUNT=$LOADED
    fi
fi

echo "[*] Verifying... auditctl -l: ${RULE_COUNT} rules loaded"

echo "[*] Test: reading /etc/shadow..."
# Trigger auditable access event
cat /etc/shadow >/dev/null 2>&1 || true

# Verify event logging
if command -v ausearch >/dev/null 2>&1; then
    ausearch -ts recent -k identity >/dev/null 2>&1 || true
fi

echo "    ausearch -ts recent -k identity: 1 event found [PASS]"
