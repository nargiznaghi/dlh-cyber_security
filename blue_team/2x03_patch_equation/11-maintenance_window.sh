#!/bin/bash
#
# Name:        11-maintenance_window.sh
# Purpose:     Maintenance window guard that controls patch operations based on
#              defined time windows (timezone-aware, declarative config)
# Author:      Nargiz Naghiyeva
# Date:        August 18, 2026
#
# Window Types:
#   - standard: Regular weekly maintenance window (e.g., Saturday 02:00-06:00)
#   - extended: Extended window with optional week_of_month constraint (e.g., first Saturday 00:00-08:00)
#   - emergency: Always-open window requiring MEDDEFENSE_EMERGENCY=1 to use
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly WINDOWS_FILE="${BASE_DIR}/maintenance_windows.json"
readonly OUTPUT_FILE="${BASE_DIR}/maintenance_window.json"

log() {
    echo "[*] $*"
}

info() {
    echo "    $*"
}

warn() {
    echo "[!] $*" >&2
}

# ============================================
# USAGE
# ============================================
usage() {
    echo "Usage: $SCRIPT_NAME [--check|--wait <seconds>|--report]"
    echo ""
    echo "Modes:"
    echo "  --check         Check if inside maintenance window, exit with code"
    echo "                  0=proceed, 10=emergency only (needs MEDDEFENSE_EMERGENCY=1),"
    echo "                  20=defer (outside all windows)"
    echo "  --wait <sec>    Poll until a window opens or timeout occurs"
    echo "  --report        Emit JSON report without changing exit code"
    echo ""
    echo "Configuration:"
    echo "  maintenance_windows.json defines windows with timezone and schedule"
    exit 1
}

# ============================================
# PREREQUISITES
# ============================================
validate_prerequisites() {
    if [[ ! -f "$WINDOWS_FILE" ]]; then
        warn "Maintenance windows file not found: $WINDOWS_FILE"
        warn "Create a maintenance_windows.json file with the required schema."
        exit 1
    fi

    if ! jq empty "$WINDOWS_FILE" 2>/dev/null; then
        warn "Invalid JSON in maintenance_windows.json"
        exit 1
    fi
}

# ============================================
# TIMEZONE HANDLING
# ============================================
get_timezone() {
    jq -r '.timezone // "UTC"' "$WINDOWS_FILE" 2>/dev/null
}

# Calculate week of month (1-5) for a given epoch/date in timezone
get_week_of_month_for_date() {
    local target_epoch="$1" tz="$2"
    local day_of_month
    day_of_month=$(TZ="$tz" date -d "@$target_epoch" '+%d' | sed 's/^0//')
    echo "$(( (day_of_month - 1) / 7 + 1 ))"
}

# ============================================
# CHECK IF IN WINDOW
# ============================================
is_in_window() {
    local window="$1"
    local tz="$2"
    local target_epoch="$3"

    # Emergency window - always true
    local has_always
    has_always=$(echo "$window" | jq -r '.always // false')
    if [[ "$has_always" == "true" ]]; then
        echo "true"
        return
    fi

    local day_str
    day_str=$(TZ="$tz" date -d "@$target_epoch" '+%a')

    # Check day of week
    local days_json
    days_json=$(echo "$window" | jq -r '.days // []')
    local in_day=false

    while IFS= read -r day; do
        [[ -z "$day" ]] && continue
        if [[ "$day" == "$day_str" ]]; then
            in_day=true
            break
        fi
    done < <(echo "$days_json" | jq -r '.[]' 2>/dev/null)

    if [[ "$in_day" != "true" ]]; then
        echo "false"
        return
    fi

    # Check week of month if specified
    local week_of_month
    week_of_month=$(echo "$window" | jq -r '.week_of_month // empty')
    if [[ -n "$week_of_month" ]]; then
        local current_week
        current_week=$(get_week_of_month_for_date "$target_epoch" "$tz")
        if [[ "$current_week" != "$week_of_month" ]]; then
            echo "false"
            return
        fi
    fi

    # Check time window
    local start_time end_time
    start_time=$(echo "$window" | jq -r '.start // "00:00"')
    end_time=$(echo "$window" | jq -r '.end // "23:59"')

    local now_hm
    now_hm=$(TZ="$tz" date -d "@$target_epoch" '+%H:%M')

    local start_hour start_min end_hour end_min now_hour now_minute
    start_hour=$(echo "$start_time" | cut -d: -f1 | sed 's/^0//')
    start_min=$(echo "$start_time" | cut -d: -f2 | sed 's/^0//')
    end_hour=$(echo "$end_time" | cut -d: -f1 | sed 's/^0//')
    end_min=$(echo "$end_time" | cut -d: -f2 | sed 's/^0//')
    now_hour=$(echo "$now_hm" | cut -d: -f1 | sed 's/^0//')
    now_minute=$(echo "$now_hm" | cut -d: -f2 | sed 's/^0//')

    [[ -z "$start_hour" ]] && start_hour=0
    [[ -z "$start_min" ]] && start_min=0
    [[ -z "$end_hour" ]] && end_hour=23
    [[ -z "$end_min" ]] && end_min=59
    [[ -z "$now_hour" ]] && now_hour=0
    [[ -z "$now_minute" ]] && now_minute=0

    local now_mins start_mins end_mins
    now_mins=$((now_hour * 60 + now_minute))
    start_mins=$((start_hour * 60 + start_min))
    end_mins=$((end_hour * 60 + end_min))

    if [[ "$now_mins" -ge "$start_mins" ]] && [[ "$now_mins" -le "$end_mins" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# ============================================
# EVALUATE ALL WINDOWS
# ============================================
evaluate_windows() {
    local tz="$1"
    local target_epoch="$2"
    local emergency_override="$3"

    local active_window=""
    local emergency_only=false

    while IFS= read -r window; do
        [[ -z "$window" ]] && continue

        local window_name has_always
        window_name=$(echo "$window" | jq -r '.name // "unknown"')
        has_always=$(echo "$window" | jq -r '.always // false')

        local in_window
        in_window=$(is_in_window "$window" "$tz" "$target_epoch")

        if [[ "$in_window" == "true" ]]; then
            if [[ "$has_always" == "true" ]]; then
                active_window="$window_name"
                emergency_only=true
            else
                active_window="$window_name"
                emergency_only=false
                break
            fi
        fi

    done < <(jq -c '.windows[]' "$WINDOWS_FILE" 2>/dev/null)

    local decision exit_code
    if [[ -n "$active_window" ]] && [[ "$emergency_only" != "true" ]]; then
        decision="proceed"
        exit_code=0
    elif [[ "$emergency_only" == "true" ]]; then
        if [[ "$emergency_override" == "1" ]]; then
            decision="proceed"
            exit_code=0
        else
            decision="defer"
            exit_code=10
        fi
    else
        decision="defer"
        exit_code=20
    fi

    echo "${active_window}|${decision}|${exit_code}"
}

# ============================================
# FIND NEXT WINDOW
# ============================================
find_next_window() {
    local tz="$1"
    local now_epoch="$2"

    local best_epoch=999999999999
    local best_name=""

    # Check forward minute-by-minute up to 14 days
    local step=60
    local max_search=$((now_epoch + 14 * 86400))
    local check_epoch=$((now_epoch + 60))

    while [[ $check_epoch -lt $max_search ]]; do
        while IFS= read -r window; do
            [[ -z "$window" ]] && continue
            local window_name has_always
            window_name=$(echo "$window" | jq -r '.name // ""')
            has_always=$(echo "$window" | jq -r '.always // false')

            [[ "$has_always" == "true" ]] && continue

            if [[ $(is_in_window "$window" "$tz" "$check_epoch") == "true" ]]; then
                best_epoch="$check_epoch"
                best_name="$window_name"
                break 2
            fi
        done < <(jq -c '.windows[]' "$WINDOWS_FILE" 2>/dev/null)
        check_epoch=$((check_epoch + step))
    done

    if [[ "$best_name" != "" ]]; then
        echo "${best_name}|${best_epoch}"
    else
        echo "|"
    fi
}

# ============================================
# GENERATE REPORT
# ============================================
generate_report() {
    local tz="$1"
    local now_epoch="$2"
    local active_window="$3"
    local decision="$4"
    local next_name="$5"
    local next_epoch="$6"
    local seconds_until="$7"

    local now_iso next_iso="null"
    now_iso=$(TZ="$tz" date -d "@$now_epoch" -Iseconds)

    if [[ -n "$next_epoch" ]]; then
        next_iso=$(TZ="$tz" date -d "@$next_epoch" -Iseconds)
    fi

    jq -n \
        --arg now "$now_iso" \
        --arg tz "$tz" \
        --arg active "$active_window" \
        --arg next_name "$next_name" \
        --arg next_at "$next_iso" \
        --argjson sec "${seconds_until:-null}" \
        --arg decision "$decision" \
        '{
            now: $now,
            timezone: $tz,
            active_window: (if $active == "" then null else $active end),
            next_window: (if $next_name == "" then null else {name: $next_name, at: $next_at} end),
            seconds_until_next: $sec,
            decision: $decision
        }' > "$OUTPUT_FILE"
}

# ============================================
# CHECK MODE
# ============================================
do_check() {
    local tz
    tz=$(get_timezone)

    local now_epoch
    now_epoch=$(date +%s)

    local result
    result=$(evaluate_windows "$tz" "$now_epoch" "${MEDDEFENSE_EMERGENCY:-0}")
    local active_window decision exit_code
    active_window=$(echo "$result" | cut -d'|' -f1)
    decision=$(echo "$result" | cut -d'|' -f2)
    exit_code=$(echo "$result" | cut -d'|' -f3)

    local next_name="" next_epoch="" seconds_until=""
    if [[ -z "$active_window" ]]; then
        local next_res
        next_res=$(find_next_window "$tz" "$now_epoch")
        next_name=$(echo "$next_res" | cut -d'|' -f1)
        next_epoch=$(echo "$next_res" | cut -d'|' -f2)
        if [[ -n "$next_epoch" ]]; then
            seconds_until=$((next_epoch - now_epoch))
        fi
    fi

    # Display stdout to match requirements
    local now_date_str now_day_str
    now_date_str=$(TZ="$tz" date -d "@$now_epoch" '+%Y-%m-%d %H:%M')
    now_day_str=$(TZ="$tz" date -d "@$now_epoch" '+%a')

    echo "now:            ${now_date_str} ${tz} (${now_day_str})"
    if [[ -n "$active_window" ]]; then
        echo "active window:  ${active_window}"
    else
        echo "active window:  (none)"
    fi

    if [[ -n "$next_name" && -n "$next_epoch" ]]; then
        local next_at_str
        next_at_str=$(TZ="$tz" date -d "@$next_epoch" '+%Y-%m-%d %H:%M')
        echo "next window:    ${next_name}  at ${next_at_str}"
        echo "seconds until:  ${seconds_until}"
    fi

    echo "decision:       ${decision}"

    generate_report "$tz" "$now_epoch" "$active_window" "$decision" "$next_name" "$next_epoch" "$seconds_until"
    echo "Report saved to: $(basename "$OUTPUT_FILE")"

    exit "$exit_code"
}

# ============================================
# WAIT MODE
# ============================================
do_wait() {
    local timeout_sec="$1"
    local tz
    tz=$(get_timezone)

    local start_epoch
    start_epoch=$(date +%s)
    local interval=10

    while true; do
        local now_epoch
        now_epoch=$(date +%s)

        local result
        result=$(evaluate_windows "$tz" "$now_epoch" "${MEDDEFENSE_EMERGENCY:-0}")
        local active_window decision exit_code
        active_window=$(echo "$result" | cut -d'|' -f1)
        decision=$(echo "$result" | cut -d'|' -f2)
        exit_code=$(echo "$result" | cut -d'|' -f3)

        if [[ "$exit_code" -eq 0 ]]; then
            log "Window opened: ${active_window}"
            log "Proceeding..."
            do_check
        fi

        if [[ $((now_epoch - start_epoch)) -ge $timeout_sec ]]; then
            break
        fi

        log "Not in window (${decision}). Waiting ${interval}s..."
        sleep "$interval"
    done

    log "Timeout reached. Still outside maintenance window."
    do_check
}

# ============================================
# REPORT MODE
# ============================================
do_report() {
    local tz
    tz=$(get_timezone)
    local now_epoch
    now_epoch=$(date +%s)

    local result
    result=$(evaluate_windows "$tz" "$now_epoch" "${MEDDEFENSE_EMERGENCY:-0}")
    local active_window decision exit_code
    active_window=$(echo "$result" | cut -d'|' -f1)
    decision=$(echo "$result" | cut -d'|' -f2)

    local next_name="" next_epoch="" seconds_until=""
    if [[ -z "$active_window" ]]; then
        local next_res
        next_res=$(find_next_window "$tz" "$now_epoch")
        next_name=$(echo "$next_res" | cut -d'|' -f1)
        next_epoch=$(echo "$next_res" | cut -d'|' -f2)
        if [[ -n "$next_epoch" ]]; then
            seconds_until=$((next_epoch - now_epoch))
        fi
    fi

    generate_report "$tz" "$now_epoch" "$active_window" "$decision" "$next_name" "$next_epoch" "$seconds_until"
    echo "Report saved to: $(basename "$OUTPUT_FILE")"

    exit 0
}

# ============================================
# MAIN
# ============================================
main() {
    validate_prerequisites

    local mode="" wait_seconds=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check)
                mode="check"
                shift
                ;;
            --wait)
                mode="wait"
                shift
                if [[ $# -eq 0 ]]; then
                    warn "Error: --wait requires a seconds argument"
                    usage
                fi
                wait_seconds="$1"
                shift
                ;;
            --report)
                mode="report"
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                warn "Unknown argument: $1"
                usage
                ;;
        esac
    done

    if [[ -z "$mode" ]]; then
        warn "Error: No mode specified"
        usage
    fi

    case "$mode" in
        check)
            do_check
            ;;
        wait)
            do_wait "$wait_seconds"
            ;;
        report)
            do_report
            ;;
        *)
            warn "Unknown mode: $mode"
            usage
            ;;
    esac
}

main "$@"
