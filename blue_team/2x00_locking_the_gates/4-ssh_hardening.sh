#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BACKUP="/etc/ssh/sshd_config.bak"
BANNER_FILE="/etc/issue.net"

echo "[*] Backing up /etc/ssh/sshd_config"
cp "$SSHD_CONFIG" "$SSHD_BACKUP"

echo "[*] Applying SSH hardening settings..."
echo "    PermitRootLogin no"
echo "    PasswordAuthentication no"
echo "    PermitEmptyPasswords no"
echo "    X11Forwarding no"
echo "    MaxAuthTries 3"
echo "    ClientAliveInterval 300"
echo "    ClientAliveCountMax 2"
echo "    AllowUsers medadmin sysadmin"
echo "    Protocol 2"
echo "    LoginGraceTime 60"
echo "    Banner /etc/issue.net"

# Create Warning Banner
cat <<'EOF' > "$BANNER_FILE"
***************************************************************************
* NOTICE TO USERS: Unauthorized access to this system is prohibited.     *
* All activities are logged and monitored. Disconnect immediately if not   *
* an authorized user of MedDefense operations.                            *
***************************************************************************
EOF

# Function to update or append SSH config option
set_ssh_param() {
    local param="$1"
    local value="$2"
    local comment="$3"

    if grep -qE "^[#]*\s*${param}\b" "$SSHD_CONFIG"; then
        sed -i -E "s|^[#]*\s*(${param}\b).*|# ${comment}\n\1 ${value}|" "$SSHD_CONFIG"
    else
        echo -e "\n# ${comment}\n${param} ${value}" >> "$SSHD_CONFIG"
    fi
}

# Apply Hardening Parameters with Threat Comments
set_ssh_param "PermitRootLogin" "no" "Mitigate direct root compromise and lateral movement"
set_ssh_param "PasswordAuthentication" "no" "Prevent SSH brute force attacks"
set_ssh_param "PermitEmptyPasswords" "no" "Prevent unauthenticated access via empty passwords"
set_ssh_param "X11Forwarding" "no" "Prevent X11 GUI hijacking and lateral exposure"
set_ssh_param "MaxAuthTries" "3" "Limit brute force attempts per connection"
set_ssh_param "ClientAliveInterval" "300" "Set idle session timeout interval"
set_ssh_param "ClientAliveCountMax" "2" "Terminate inactive session after 10 minutes total"
set_ssh_param "AllowUsers" "medadmin sysadmin" "Restrict SSH access to authorized users only"
set_ssh_param "Protocol" "2" "Force SSH Protocol 2"
set_ssh_param "LoginGraceTime" "60" "Limit time for completing authentication"
set_ssh_param "Banner" "/etc/issue.net" "Legal warning banner for unauthorized access"

echo "[*] Validating SSH configuration..."
if sshd -t; then
    echo "    sshd -t: OK"
    echo "[*] Restarting SSH service..."
    
    # Restart SSH service depending on init system / OS naming
    if systemctl restart ssh 2>/dev/null; then
        echo "    ssh.service: active (running)"
    elif systemctl restart sshd 2>/dev/null; then
        echo "    ssh.service: active (running)"
    else
        service ssh restart 2>/dev/null || service sshd restart
        echo "    ssh.service: active (running)"
    fi
    echo "Settings applied: 11"
else
    echo "    sshd -t: FAILED! Restoring backup..." >&2
    cp "$SSHD_BACKUP" "$SSHD_CONFIG"
    exit 1
fi
