#!/bin/bash
#
# Name:        12-change_log.sh
# Purpose:     Produce a canonical change log from apt history logs and prior
#              task artifacts, enriched with maintenance window and CVE data.
# Author:      Nargiz Naghiyeva
# Date:        August 18, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly APT_HISTORY_GLOB="/var/log/apt/history.log*"
readonly EXECUTION_LOG="${BASE_DIR}/patch_execution_log.json"
readonly VULN_INVENTORY="${BASE_DIR}/vulnerability_inventory.json"
readonly WINDOW_SCRIPT="${BASE_DIR}/11-maintenance_window.sh"
readonly OUTPUT_FILE="${BASE_DIR}/patch_change_log.json"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

log() {
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"
}

# 1. Parse APT History Logs
parse_apt_history() {
    local parsed_out="${TMP_DIR}/parsed_transactions.tsv"
    
    for hist_file in $APT_HISTORY_GLOB; do
        [[ ! -f "$hist_file" ]] && continue
        if [[ "$hist_file" == *.gz ]]; then
            zcat "$hist_file" 2>/dev/null || true
        else
            cat "$hist_file" 2>/dev/null || true
        fi
    done | awk '
    BEGIN {
        in_tx = 0; start_date = ""; cmd = ""; req = ""; up = ""; inst = ""; rm_pkg = "";
    }
    /^Start-Date:/ {
        if (in_tx == 1) {
            print start_date "\t" cmd "\t" req "\t" up "\t" inst "\t" rm_pkg
        }
        in_tx = 1
        start_date = substr($0, 13); gsub(/^[ \t]+|[ \t]+$/, "", start_date);
        cmd = ""; req = ""; up = ""; inst = ""; rm_pkg = "";
        next
    }
    /^Commandline:/ { cmd = substr($0, 13); gsub(/^[ \t]+|[ \t]+$/, "", cmd); next }
    /^Requested-By:/ { req = substr($0, 15); gsub(/^[ \t]+|[ \t]+$/, "", req); next }
    /^Upgrade:/ { up = substr($0, 10); gsub(/^[ \t]+|[ \t]+$/, "", up); next }
    /^Install:/ { inst = substr($0, 10); gsub(/^[ \t]+|[ \t]+$/, "", inst); next }
    /^Remove:/ { rm_pkg = substr($0, 9); gsub(/^[ \t]+|[ \t]+$/, "", rm_pkg); next }
    /^End-Date:/ {
        if (in_tx == 1) {
            print start_date "\t" cmd "\t" req "\t" up "\t" inst "\t" rm_pkg
        }
        in_tx = 0
        next
    }
    END {
        if (in_tx == 1) {
            print start_date "\t" cmd "\t" req "\t" up "\t" inst "\t" rm_pkg
        }
    }
    ' > "$parsed_out"
    
    echo "$parsed_out"
}

normalize_timestamp() {
    local raw="$1"
    local cleaned
    cleaned=$(echo "$raw" | tr '\016\040' ' ' | xargs)
    date -d "$cleaned" -Iseconds 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ"
}

to_epoch() {
    local iso_ts="$1"
    date -d "$iso_ts" '+%s' 2>/dev/null || echo 0
}

extract_user() {
    local requested_by="$1"
    if [[ -z "$requested_by" ]]; then
        echo "system"
        return
    fi
    local user
    user=$(echo "$requested_by" | sed 's/ (.*//' | xargs)
    [[ -z "$user" ]] && user="system"
    echo "$user"
}

extract_pkg_names() {
    local str="$1"
    [[ -z "$str" ]] && return
    echo "$str" | sed 's/), /\n/g' | sed 's/ (.*//' | sed 's/:.*//' | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//' | grep -v '^$' || true
}

get_window_decision() {
    local iso_ts="$1"
    if [[ -x "$WINDOW_SCRIPT" ]]; then
        local decision
        decision=$("$WINDOW_SCRIPT" --report --timestamp "$iso_ts" 2>/dev/null | jq -r '.decision // "outside"' 2>/dev/null || echo "outside")
        echo "$decision"
    else
        echo "outside"
    fi
}

get_linked_execution_log() {
    local event_epoch="$1"
    if [[ ! -f "$EXECUTION_LOG" ]]; then
        echo "null"
        return
    fi
    
    # 15-minute grouping / window matching (900 seconds)
    local exec_start
    exec_start=$(jq -r '.started_at // empty' "$EXECUTION_LOG" 2>/dev/null || true)
    if [[ -n "$exec_start" ]]; then
        local exec_epoch
        exec_epoch=$(to_epoch "$exec_start")
        local diff=$(( event_epoch - exec_epoch ))
        if [[ ${diff#-} -le 900 ]]; then
            echo "\"${EXECUTION_LOG}\""
            return
        fi
    fi
    echo "null"
}

get_resolved_cves() {
    local pkgs_file="$1"
    if [[ ! -f "$VULN_INVENTORY" ]]; then
        echo "[]"
        return
    fi

    local cves="[]"
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        local matched_cves
        matched_cves=$(jq --arg p "$pkg" '
            [.vulnerabilities[]? | select(.package == $p or .package_name == $p) | .cve_id // .id] | unique
        ' "$VULN_INVENTORY" 2>/dev/null || echo "[]")
        cves=$(jq -s '.[0] + .[1] | unique' <(echo "$cves") <(echo "$matched_cves"))
    done < "$pkgs_file"

    echo "$cves"
}

main() {
    log "Starting change log generation..."
    
    local raw_tsv
    raw_tsv=$(parse_apt_history)

    local events_json="[]"

    while IFS=$'\t' read -r start_date cmd req up inst rm_pkg; do
        [[ -z "$start_date" ]] && continue

        local iso_ts
        iso_ts=$(normalize_timestamp "$start_date")
        local event_epoch
        event_epoch=$(to_epoch "$iso_ts")

        local user
        user=$(extract_user "$req")

        local pkgs_tmp="${TMP_DIR}/pkgs.txt"
        > "$pkgs_tmp"

        local operation="upgrade"
        if [[ -n "$up" ]]; then
            operation="upgrade"
            extract_pkg_names "$up" >> "$pkgs_tmp"
        elif [[ -n "$inst" ]]; then
            operation="install"
            extract_pkg_names "$inst" >> "$pkgs_tmp"
        elif [[ -n "$rm_pkg" ]]; then
            operation="remove"
            extract_pkg_names "$rm_pkg" >> "$pkgs_tmp"
        fi

        local affected_packages="[]"
        if [[ -s "$pkgs_tmp" ]]; then
            affected_packages=$(jq -R '.' "$pkgs_tmp" | jq -s 'unique')
        fi

        local window_decision
        window_decision=$(get_window_decision "$iso_ts")

        local exec_log_link
        exec_log_link=$(get_linked_execution_log "$event_epoch")

        local resolved_cves
        resolved_cves=$(get_resolved_cves "$pkgs_tmp")

        local event_obj
        event_obj=$(jq -nc \
            --arg timestamp "$iso_ts" \
            --arg user "$user" \
            --arg operation "$operation" \
            --arg command "$cmd" \
            --argjson packages "$affected_packages" \
            --arg maintenance_window "$window_decision" \
            --argjson execution_log "$exec_log_link" \
            --argjson resolved_cves "$resolved_cves" \
            '{
                timestamp: $timestamp,
                user: $user,
                operation: $operation,
                command: $command,
                affected_packages: $packages,
                maintenance_window: $maintenance_window,
                execution_log: $execution_log,
                resolved_cves: $resolved_cves
            }')

        events_json=$(echo "$events_json" | jq --argjson ev "$event_obj" '. + [$ev]')
    done < "$raw_tsv"

    # Save canonical change log output
    jq -nc \
        --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson change_events "$events_json" \
        '{
            generated_at: $generated_at,
            total_events: ($change_events | length),
            change_events: $change_events
        }' > "$OUTPUT_FILE"

    log "Change log successfully written to $OUTPUT_FILE"
}

main "$@"
