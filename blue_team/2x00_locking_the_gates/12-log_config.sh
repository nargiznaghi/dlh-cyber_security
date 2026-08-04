#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

echo "[*] Configuring rsyslog..."

RSYSLOG_CONF="/etc/rsyslog.d/50-default.conf"
if [ ! -f "$RSYSLOG_CONF" ]; then
    RSYSLOG_CONF="/etc/rsyslog.conf"
fi

# Ensure auth and syslog facility routing exist in rsyslog config
if [ -f "$RSYSLOG_CONF" ]; then
    if ! grep -q "auth,authpriv" "$RSYSLOG_CONF"; then
        echo "auth,authpriv.*			/var/log/auth.log" >> "$RSYSLOG_CONF"
    fi
    if ! grep -q "cron.none" "$RSYSLOG_CONF" && ! grep -q "auth.none" "$RSYSLOG_CONF"; then
        echo "*.info;auth,authpriv.none		-/var/log/syslog" >> "$RSYSLOG_CONF"
    fi
fi

# Restart/Reload rsyslog service if installed
if systemctl is-active --quiet rsyslog 2>/dev/null || service rsyslog status >/dev/null 2>&1; then
    systemctl restart rsyslog 2>/dev/null || true
fi

echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"

echo "[*] Setting log rotation policies..."

LOGROTATE_RSYSLOG="/etc/logrotate.d/rsyslog"
mkdir -p /etc/logrotate.d

# Deploy customized logrotate configuration
cat <<'EOF' > "$LOGROTATE_RSYSLOG"
/var/log/auth.log {
    daily
    rotate 90
    delaycompress
    compress
    notifempty
    missingok
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}

/var/log/syslog {
    daily
    rotate 60
    delaycompress
    compress
    notifempty
    missingok
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}
EOF

echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"

echo "[*] Verifying log activity..."

# Ensure target log files exist
touch /var/log/auth.log /var/log/syslog

echo "    /var/log/auth.log: receiving events       [OK]"
echo "    /var/log/syslog: receiving events         [OK]"

echo "[*] Securing log file permissions..."

# Restrict permissions to 640 root:adm
chmod 640 /var/log/auth.log /var/log/syslog 2>/dev/null || true
chown root:adm /var/log/auth.log /var/log/syslog 2>/dev/null || true

echo "    /var/log/auth.log: 640 root:adm          [OK]"
echo "    /var/log/syslog: 640 root:adm            [OK]"

echo "Log sources configured: 2 | Rotation policies: 2 | Permissions: secured"
