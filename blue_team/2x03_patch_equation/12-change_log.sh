#!/bin/bash
#
# Name:        12-change_log.sh
# Purpose:     Produce a canonical change log from apt history logs and prior
#              task artifacts, enriched with maintenance window and CVE data
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

# Müvəqqəti faylların avtomatik təmizlənməsi
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

log() { echo "[*] $*"; }

# ============================================
# PARSE APT HISTORY LOGS
# ============================================
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
        start_date = substr($0, 13); gsub(/^[ \t]+/, "", start_date);
        cmd = ""; req = ""; up = ""; inst = ""; rm_pkg = "";
        next
    }
    /^Commandline:/ { cmd = substr($0, 13); gsub(/^[ \t]+/, "", cmd); next }
    /^Requested-By:/ { req = substr($0, 15); gsub(/^[ \t]+/, "", req); next }
    /^Upgrade:/ { up = substr($0, 10); gsub(/^[ \t]+/, "", up); next }
    /^Install:/ { inst = substr($0, 10); gsub(/^[ \t]+/, "", inst); next }
    /^Remove:/ { rm_pkg = substr($0, 9); gsub(/^[ \t]+/, "", rm_pkg); next }
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
    cleaned=$(echo "$raw" | sed 's/  */ /g' | xargs)
    date -d "$cleaned" -Iseconds 2>/dev/null || echo "$raw"
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
    user=$(echo "$requested_by" | sed 's/ (.*//' | sed 's/^[ \t]*//')
    [[ -z "$user" ]] && user="system"
    echo "$user"
}

count_packages_in_str() {
    local str="$1"
    if [[ -z "$str" ]]; then
        echo 0
        return
    fi
    echo "$str" | grep -oE '\([^)]*\)' | wc -l || echo 0
}

# Extract unique package names (stripped of architecture and version)
extract_pkg_names() {
    local str="$1"
    [[ -z "$str" ]] && return
    echo "$str" | sed 's/), /\n/g' | sed 's/(.*//' | sed 's/:.*//' | sed 's/^[ \t]*//;s/[ \t]*$//' | grep -v '^$' || true
}

# Call 11-maintenance_window.sh as required by prompt
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
    local start_epoch="$1"
    local end_epoch="$2"

    if [[ ! -f "$EXECUTION_LOG" ]]; then
        echo "null"
        return
    fi

    # Check if execution log overlaps with event (within 15 min / 900s)
    local matches
    matches=$(jq -r --argjson se "$start_epoch" --argjson ee "$end_epoch" '
        .entries[]? | select(
            (.timestamp // .executed_at // empty) as $ts |
            (($ts | fromdateiso8601?) // 0) as $e |
            ($e >= ($se - 900) and $e <= ($ee + 900))
        )
    ' "$EXECUTION_LOG" 2>/dev/null || echo "")

    if [[ -n "$matches" ]]; then
        jq -n --arg path "$EXECUTION_LOG" '$path'
    else
        echo "null"
    fi
}

get_cves_resolved() {
    local pkgs_file="$1"

    if [[ ! -f "$VULN_INVENTORY" ]] || [[ ! -s "$pkgs_file" ]]; then
        echo "[]"
        return
    fi

    local resolved_cves
    resolved_cves=$(jq -R -s --slurpfile inv "$VULN_INVENTORY" '
        split("\n") | map(select(length > 0)) as $pkgs |
        [$inv[0].packages[]? | select(.package as $p | $pkgs | index($p)) | .cves[]?] | unique
    ' "$pkgs_file" 2>/dev/null || echo "[]")

    echo "$resolved_cves"
}

# ============================================
# MAIN EXECUTION
# ============================================
main() {
    log "Parsing /var/log/apt/history.log*..."
    local parsed_file
    parsed_file=$(parse_apt_history)

    # Sort parsed transactions by date
    local sorted_file="${TMP_DIR}/sorted_transactions.tsv"
    sort -t$'\t' -k1,1 "$parsed_file" > "$sorted_file"

    local events_json_arr="${TMP_DIR}/events.json"
    echo "[]" > "$events_json_arr"

    local prev_epoch=0
    local cur_start=""
    local cur_end_epoch=0
    local cur_user=""
    local cur_pkg_count=0
    local cur_pkgs_file="${TMP_DIR}/cur_pkgs.txt"
    > "$cur_pkgs_file"

    process_event() {
        local start_ts="$1"
        local end_epoch_val="$2"
        local user_val="$3"
        local pkg_count_val="$4"
        local pkgs_file_val="$5"

        local start_epoch
        start_epoch=$(to_epoch "$start_ts")
        local end_ts
        end_ts=$(date -d "@$end_epoch_val" -Iseconds 2>/dev/null || echo "$start_ts")

        local window_decision
        window_decision=$(get_window_decision "$start_ts")

        local linked_log
        linked_log=$(get_linked_execution_log "$start_epoch" "$end_epoch_val")

        local cves
        cves=$(get_cves_resolved "$pkgs_file_val")

        local event_obj
        event_obj=$(jq -nc \
            --arg started "$start_ts" \
            --arg ended "$end_ts" \
            --arg user "$user_val" \
            --arg within_window "$window_decision" \
            --argjson packages "$pkg_count_val" \
            --argjson linked_log "$linked_log" \
            --argjson cves_resolved "$cves" \
            '{
                started: $started,
                ended: $ended,
                user: $user,
                within_window: $within_window,
                packages: $packages,
                linked_execution_log: $linked_log,
                cves_resolved: $cves_resolved
            }')

        local updated
        updated=$(jq --argjson new_evt "$event_obj" '. + [$new_evt]' "$events_json_arr")
        echo "$updated" > "$events_json_arr"
    }

    while IFS=$'\t' read -r start_date cmdline req_by upgrades installs removes; do
        [[ -z "$start_date" ]] && continue

        local iso_ts
        iso_ts=$(normalize_timestamp "$start_date")
        local epoch
        epoch=$(to_epoch "$iso_ts")
        [[ "$epoch" -eq 0 ]] && continue

        local tx_pkg_count=0
        tx_pkg_count=$(( $(count_packages_in_str "$upgrades") + $(count_packages_in_str "$installs") + $(count_packages_in_str "$removes") ))

        # 15 dəqiqəlik (900 saniyə) yaxınlıq üzrə qruplaşdırma
        if [[ $prev_epoch -gt 0 ]] && [[ $((epoch - prev_epoch)) -le 900 ]]; then
            cur_end_epoch="$epoch"
            cur_pkg_count=$((cur_pkg_count + tx_pkg_count))
            extract_pkg_names "$upgrades $installs" >> "$cur_pkgs_file"
        else
            if [[ $prev_epoch -gt 0 ]]; then
                sort -u "$cur_pkgs_file" -o "$cur_pkgs_file"
                process_event "$cur_start" "$cur_end_epoch" "$cur_user" "$cur_pkg_count" "$cur_pkgs_file"
            fi

            cur_start="$iso_ts"
            cur_end_epoch="$epoch"
            cur_user=$(extract_user "$req_by")
            cur_pkg_count=$tx_pkg_count
            > "$cur_pkgs_file"
            extract_pkg_names "$upgrades $installs" >> "$cur_pkgs_file"
        fi

        prev_epoch="$epoch"
    done < "$sorted_file"

    # Sonuncu event-i emal et
    if [[ $prev_epoch -gt 0 ]]; then
        sort -u "$cur_pkgs_file" -o "$cur_pkgs_file"
        process_event "$cur_start" "$cur_end_epoch" "$cur_user" "$cur_pkg_count" "$cur_pkgs_file"
    fi

    # Summary hesabla və patch_change_log.json faylına yaz
    jq '
        if length > 0 then
            {
                period_start: .[0].started,
                period_end: .[-1].ended,
                events: .,
                summary: {
                    total_events: length,
                    inside_window: ([.[] | select(.within_window == "inside" or .within_window == "inside_window")] | length),
                    outside_window: ([.[] | select(.within_window == "outside" or .within_window == "outside_window")] | length),
                    cves_resolved: ([.[].cves_resolved[]?] | unique | length)
                }
            }
        else
            {
                period_start: null,
                period_end: null,
                events: [],
                summary: {
                    total_events: 0,
                    inside_window: 0,
                    outside_window: 0,
                    cves_resolved: 0
                }
            }
        end
    ' "$events_json_arr" > "$OUTPUT_FILE"

    log "Canonical change log generated at: $OUTPUT_FILE"
}

main "$@"
