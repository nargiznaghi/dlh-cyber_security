#!/bin/bash

# name: 6-log_source_map.sh
# purpose: Inventory active Linux log sources and their security relevance.
# author: Nargiz Naghiyeva

set -e
set -u
set -o pipefail

echo "[*] Discovering log sources..."

found=0
missing=0

printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" \
"Source" "Path" "Format" "Rotation" "Events/hr" "Relevance"

printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" \
"------" "----" "------" "--------" "---------" "---------"

# Get rotation information from logrotate config
get_rotation() {
    local file="$1"
    local result="unknown"
    local config

    config=$(grep -rl "$file" /etc/logrotate.conf /etc/logrotate.d 2>/dev/null | head -1 || true)

    if [ -n "$config" ]; then
        local period rotate
        period=$(grep -E "^[[:space:]]*(daily|weekly|monthly|yearly)" "$config" 2>/dev/null | head -1 | xargs || true)
        rotate=$(grep -E "^[[:space:]]*rotate[[:space:]]+[0-9]+" "$config" 2>/dev/null | head -1 | awk '{print $2}' || true)

        if [ -n "$period" ] && [ -n "$rotate" ]; then
            result="$period x$rotate"
        elif [ -n "$period" ]; then
            result="$period"
        fi
    fi

    echo "$result"
}

# Estimate events generated during current hour
get_events_hour() {
    local file="$1"
    local format="$2"
    local count

    if [ ! -s "$file" ]; then
        echo "0"
        return
    fi

    case "$format" in
        syslog)
            local pattern
            pattern=$(date "+%b %e %H:")
            count=$(grep -c "$pattern" "$file" 2>/dev/null || true)
            echo "$count"
            ;;

        combined)
            local pattern
            pattern=$(date "+%d/%b/%Y:%H:")
            count=$(grep -c "$pattern" "$file" 2>/dev/null || true)
            echo "$count"
            ;;

        audit)
            local lines
            lines=$(wc -l < "$file" 2>/dev/null || echo 0)
            echo $((lines / 24))
            ;;

        *)
            local lines
            lines=$(wc -l < "$file" 2>/dev/null || echo 0)
            echo $((lines / 24))
            ;;
    esac
}

check_log() {
    local name="$1"
    local path="$2"
    local format="$3"
    local relevance="$4"

    if [ -f "$path" ]; then
        local rotation events
        rotation=$(get_rotation "$path")
        events=$(get_events_hour "$path" "$format")

        printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" \
        "$name" "$path" "$format" "$rotation" "$events" "$relevance"

        found=$((found + 1))
    else
        missing=$((missing + 1))
    fi
}

# Expected security-relevant logs
check_log "auth.log" \
    "/var/log/auth.log" \
    "syslog" \
    "critical"

check_log "audit.log" \
    "/var/log/audit/audit.log" \
    "audit" \
    "critical"

check_log "syslog" \
    "/var/log/syslog" \
    "syslog" \
    "high"

check_log "kern.log" \
    "/var/log/kern.log" \
    "syslog" \
    "medium"

check_log "dpkg.log" \
    "/var/log/dpkg.log" \
    "custom" \
    "medium"

check_log "apache2 access" \
    "/var/log/apache2/access.log" \
    "combined" \
    "high"

check_log "apache2 error" \
    "/var/log/apache2/error.log" \
    "custom" \
    "high"

# Discover extra security-relevant logs if present
for extra in \
    /var/log/fail2ban.log \
    /var/log/ufw.log \
    /var/log/mysql/error.log
do
    if [ -f "$extra" ]; then
        name=$(basename "$extra")
        rotation=$(get_rotation "$extra")
        events=$(get_events_hour "$extra" "custom")

        printf "%-18s %-32s %-10s %-14s %-10s %-10s\n" \
        "$name" "$extra" "custom" "$rotation" "$events" "high"

        found=$((found + 1))
    fi
done

echo "Sources found: $found | Missing: $missing"

