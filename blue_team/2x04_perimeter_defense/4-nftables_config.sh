#!/bin/bash

set -e

RULES_JSON="segmentation_rules.json"
CONF_FILE="nftables.conf"
BACKUP_DIR="/var/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
ROLLBACK_FILE="${BACKUP_DIR}/nftables-rollback-${TIMESTAMP}.nft"

if [ ! -f "$RULES_JSON" ]; then
    echo "Xəta: $RULES_JSON faylı tapılmadı."
    exit 1
fi

mkdir -p "$BACKUP_DIR"

# 1. Mövcud ruleset-in rollback üçün saxlanılması
if command -v nft >/dev/null 2>&1; then
    nft list ruleset > "$ROLLBACK_FILE" 2>/dev/null || touch "$ROLLBACK_FILE"
fi

# 2. Zonaların CIDR məlumatlarının JSON-dan çıxarılması
DMZ_CIDR=$(jq -r '.zones[] | select(.name=="DMZ") | .cidr' "$RULES_JSON")
INT_CIDR=$(jq -r '.zones[] | select(.name=="INTERNAL") | .cidr' "$RULES_JSON")
MGMT_CIDR=$(jq -r '.zones[] | select(.name=="MGMT") | .cidr' "$RULES_JSON")
MED_CIDR=$(jq -r '.zones[] | select(.name=="MEDDEV") | .cidr' "$RULES_JSON")

# 3. nftables.conf faylının render edilməsi
cat << CONF_EOF > "$CONF_FILE"
#!/usr/sbin/nft -f

flush ruleset

table inet meddefense {
    set dmz_zone {
        type ipv4_addr
        flags interval
        elements = { $DMZ_CIDR }
    }

    set internal_zone {
        type ipv4_addr
        flags interval
        elements = { $INT_CIDR }
    }

    set mgmt_zone {
        type ipv4_addr
        flags interval
        elements = { $MGMT_CIDR }
    }

    set meddev_zone {
        type ipv4_addr
        flags interval
        elements = { $MED_CIDR }
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # Connection tracking accept
        ct state established,related accept

        # Loopback accept
        iifname "lo" accept

        # ICMP minimal accept
        meta l4proto icmp accept
        meta l4proto ipv6-icmp accept

        # MGMT SSH access to local host
        ip saddr @mgmt_zone tcp dport 22 accept

        # DNS resolution requests to local MGMT resolver
        udp dport 53 accept
        tcp dport 53 accept

        # Log dropped packets
        log prefix "nftables-input-denied: " drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;

        # Connection tracking accept
        ct state established,related accept

        # Cross-zone allow rules from segmentation matrix
        ip saddr @mgmt_zone ip daddr @internal_zone tcp dport 22 accept
        ip saddr @mgmt_zone ip daddr @dmz_zone tcp dport 22 accept
        ip saddr @mgmt_zone ip daddr @meddev_zone tcp dport 22 accept
        ip saddr @mgmt_zone ip daddr @meddev_zone tcp dport 4242 accept

        ip saddr @internal_zone ip daddr @internal_zone tcp dport 443 accept
        ip saddr @internal_zone ip daddr @internal_zone tcp dport 3306 accept
        ip saddr @dmz_zone ip daddr @internal_zone tcp dport 3306 accept

        ip saddr @meddev_zone ip daddr @internal_zone tcp dport 4242 accept
        ip saddr @meddev_zone ip daddr @internal_zone tcp dport 443 accept

        ip saddr @dmz_zone ip daddr @mgmt_zone udp dport 53 accept
        ip saddr @dmz_zone ip daddr @mgmt_zone tcp dport 53 accept
        ip saddr @internal_zone ip daddr @mgmt_zone udp dport 53 accept
        ip saddr @internal_zone ip daddr @mgmt_zone tcp dport 53 accept
        ip saddr @meddev_zone ip daddr @mgmt_zone udp dport 53 accept
        ip saddr @meddev_zone ip daddr @mgmt_zone tcp dport 53 accept

        # Explicit deny blocks for prohibited zone paths
        ip saddr @meddev_zone ip daddr @dmz_zone drop
        ip saddr @dmz_zone ip daddr @meddev_zone drop
        ip saddr @internal_zone ip daddr @meddev_zone drop

        # Log dropped forwarded traffic
        log prefix "nftables-forward-denied: " drop
    }

    chain output {
        type filter hook output priority filter; policy accept;

        # Explicit drops for restricted outbound zones
        ip daddr @meddev_zone drop
    }
}
CONF_EOF

# 4. Sintaksis yoxlaması (Dry-run / Check-only parse)
if command -v nft >/dev/null 2>&1; then
    nft -c -f "$CONF_FILE"
fi

# 5. Atomik tətbiq və yoxlama
if command -v nft >/dev/null 2>&1; then
    nft -f "$CONF_FILE"
    echo "nftables ruleset başarıyla yükləndi."
    echo "Qaydaların ümumi sayı: $(nft list ruleset | grep -c 'accept\|drop')"
else
    echo "nft əmri tapılmadı, $CONF_FILE faylı yaradıldı."
fi

echo "Rollback faylı saxlanıldı: $ROLLBACK_FILE"
