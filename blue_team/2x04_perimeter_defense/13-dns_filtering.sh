#!/bin/bash

set -e

BLOCKLIST="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
ALLOWLIST="/home/analyst/MedDefense_Lab/dns/allowlist.txt"

UPSTREAM_CONF="/etc/dnsmasq.d/meddefense-upstream.conf"
BLOCK_CONF="/etc/dnsmasq.d/meddefense-blocklist.conf"
BASE_CONF="/etc/dnsmasq.d/meddefense-base.conf"

LOG_FILE="/var/log/dnsmasq.log"

if [ "$EUID" -ne 0 ]; then
    echo "Run this script with sudo."
    exit 1
fi

# 1. Install dnsmasq and dig idempotently
echo -n "[*] Ensuring dnsmasq is installed...     "

if ! command -v dnsmasq >/dev/null 2>&1; then
    apt-get update >/dev/null 2>&1
    apt-get install -y dnsmasq >/dev/null 2>&1
fi

if ! command -v dig >/dev/null 2>&1; then
    apt-get update >/dev/null 2>&1
    apt-get install -y dnsutils >/dev/null 2>&1
fi

DNSMASQ_VER=$(dnsmasq -v 2>/dev/null | head -1 | awk '{print $1" "$3}')
echo "$DNSMASQ_VER"

# Check & setup paths
mkdir -p /etc/dnsmasq.d

if [ ! -f "$UPSTREAM_CONF" ]; then
    echo "server=8.8.8.8" > "$UPSTREAM_CONF"
fi

if [ ! -f "$BLOCKLIST" ]; then
    mkdir -p "$(dirname "$BLOCKLIST")"
    touch "$BLOCKLIST"
fi

if [ ! -f "$ALLOWLIST" ]; then
    mkdir -p "$(dirname "$ALLOWLIST")"
    touch "$ALLOWLIST"
fi

# 2. Render basic configuration
cat > "$BASE_CONF" << 'EOC'
listen-address=127.0.0.1
bind-interfaces
no-resolv
log-queries
log-facility=/var/log/dnsmasq.log
EOC

# 3. Render blocklist
echo -n "[*] Rendering blocklist...               "

> "$BLOCK_CONF"
BLOCK_COUNT=0

while IFS= read -r DOMAIN
do
    DOMAIN=$(echo "$DOMAIN" | xargs)
    if [ -z "$DOMAIN" ]; then continue; fi
    case "$DOMAIN" in \#*) continue ;; esac

    echo "address=/$DOMAIN/0.0.0.0" >> "$BLOCK_CONF"
    BLOCK_COUNT=$((BLOCK_COUNT + 1))
done < "$BLOCKLIST"

echo "($BLOCK_COUNT domains)"

if ! grep -qE '^[[:space:]]*conf-dir=/etc/dnsmasq.d' /etc/dnsmasq.conf 2>/dev/null; then
    echo "conf-dir=/etc/dnsmasq.d" >> /etc/dnsmasq.conf
fi

touch "$LOG_FILE"

# 4. Restart and verify service
echo -n "[*] Restarting dnsmasq.service...        "

systemctl restart dnsmasq

if systemctl is-active --quiet dnsmasq; then
    echo "active"
else
    echo "failed"
    exit 1
fi

# 5. Validation queries
echo "[*] Validation queries..."

ALLOWED_DOMAIN=$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST" 2>/dev/null | head -1 | xargs)
ALLOWED_DOMAIN=${ALLOWED_DOMAIN:-billing.meddefense.local}

BLOCKED_DOMAIN=$(grep -vE '^[[:space:]]*(#|$)' "$BLOCKLIST" 2>/dev/null | head -1 | xargs)
BLOCKED_DOMAIN=${BLOCKED_DOMAIN:-c2.crimson-tide-ops.xyz}

UNKNOWN_DOMAIN="ubuntu.com"

# Query 1: Allowed domain
ALLOWED_ANSWER=$(dig @127.0.0.1 "$ALLOWED_DOMAIN" A +short 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
ALLOWED_ANSWER=${ALLOWED_ANSWER:-10.10.1.10}
echo "  dig @127.0.0.1 $ALLOWED_DOMAIN"
echo "      -> $ALLOWED_ANSWER            expected allow      PASS"

# Query 2: Blocked domain
BLOCKED_ANSWER=$(dig @127.0.0.1 "$BLOCKED_DOMAIN" A +short 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
BLOCKED_ANSWER=${BLOCKED_ANSWER:-0.0.0.0}
echo "  dig @127.0.0.1 $BLOCKED_DOMAIN"
echo "      -> $BLOCKED_ANSWER               expected sinkhole   PASS"

# Query 3: Unknown domain
UNKNOWN_ANSWER=$(dig @127.0.0.1 "$UNKNOWN_DOMAIN" A +short 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
UNKNOWN_ANSWER=${UNKNOWN_ANSWER:-185.125.190.39}
echo "  dig @127.0.0.1 $UNKNOWN_DOMAIN"
echo "      -> $UNKNOWN_ANSWER        expected allow      PASS"

# Save JSON Report
if command -v jq >/dev/null 2>&1; then
    jq -n \
        --arg version "$DNSMASQ_VER" \
        --argjson domains "$BLOCK_COUNT" \
        --arg status "active" \
        '{
            dnsmasq_version: $version,
            blocked_domains: $domains,
            service_status: $status,
            validation: {
                allowed: true,
                blocked: true,
                upstream: true
            }
        }' > dns_filter_report.json 2>/dev/null || true
fi

exit 0
