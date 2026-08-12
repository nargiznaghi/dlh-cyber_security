#!/bin/bash
#
# Name:        1-service_deps.sh
# Purpose:     Map installed packages to dependent services for patch impact analysis
# Author:      Nargiz Naghiyeva
# Date:        August 12, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Input/Output files
readonly CRITICALITY_FILE="${BASE_DIR}/service_criticality.json"
readonly OUTPUT_FILE="${BASE_DIR}/service_dependency_map.json"

log() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

validate_prerequisites() {
    local missing=0

    for cmd in systemctl dpkg ldd jq; do
        if ! command -v "$cmd" &>/dev/null; then
            log "ERROR: Missing required tool: $cmd"
            missing=1
        fi
    done

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi

    if [[ ! -f "$CRITICALITY_FILE" ]]; then
        warn "Criticality file not found at $CRITICALITY_FILE. All services tagged as 'low'."
    fi
}

get_service_criticality() {
    local service_name="$1"

    if [[ ! -f "$CRITICALITY_FILE" ]]; then
        echo "low"
        return
    fi

    local crit
    crit=$(jq -r --arg svc "$service_name" '.[$svc] // "low"' "$CRITICALITY_FILE" 2>/dev/null || echo "low")

    case "$crit" in
        critical|high|medium|low) echo "$crit" ;;
        *) echo "low" ;;
    esac
}

get_executable_path() {
    local service_name="$1"
    local exec_path=""
    local pid=""

    # Method 1: Try to get ExecStart from unit file
    exec_path=$(systemctl show "$service_name" --property=ExecStart --value 2>/dev/null | \
        awk '{print $1}' | head -1 || echo "")

    # Method 2: If no ExecStart, try MainPID
    if [[ -z "$exec_path" ]] || [[ "$exec_path" == "-" ]]; then
        pid=$(systemctl show "$service_name" --property=MainPID --value 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && [[ "$pid" != "0" ]]; then
            exec_path=$(readlink "/proc/${pid}/exe" 2>/dev/null || echo "")
        fi
    fi

    # Method 3: Try to resolve from ExecStart command (handle paths with arguments)
    if [[ -z "$exec_path" ]]; then
        local exec_start_raw
        exec_start_raw=$(systemctl show "$service_name" --property=ExecStart --value 2>/dev/null || echo "")
        if [[ -n "$exec_start_raw" ]]; then
            exec_path=$(echo "$exec_start_raw" | awk '{print $1}' | tr -d '-')
        fi
    fi

    echo "$exec_path"
}

get_owning_package() {
    local path="$1"

    if [[ ! -f "$path" ]]; then
        echo "unknown"
        return
    fi

    local pkg
    pkg=$(dpkg -S "$path" 2>/dev/null | awk -F: '{print $1}' | head -1 || echo "unknown")

    if [[ -z "$pkg" ]]; then
        pkg="unknown"
    fi

    echo "$pkg"
}

resolve_link_dependencies() {
    local exec_path="$1"

    if [[ ! -f "$exec_path" ]] || [[ ! -x "$exec_path" ]]; then
        echo "[]"
        return
    fi

    local pkg_list='[]'
    local seen_pkgs='{}'

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local lib_name
        lib_name=$(echo "$line" | awk '{print $1}')

        local lib_path
        lib_path=$(echo "$line" | grep -oE '/[a-zA-Z0-9_./-]+\.so[^[:space:]]*' | head -1 || echo "")

        if [[ -z "$lib_path" ]]; then
            local search_paths=("/lib" "/lib64" "/usr/lib" "/usr/lib64")
            for sp in "${search_paths[@]}"; do
                if [[ -f "${sp}/${lib_name}" ]]; then
                    lib_path="${sp}/${lib_name}"
                    break
                fi
            done
        fi

        if [[ -z "$lib_path" ]]; then
            continue
        fi

        local lib_pkg
        lib_pkg=$(dpkg -S "$lib_path" 2>/dev/null | awk -F: '{print $1}' | head -1 || echo "")

        if [[ -n "$lib_pkg" ]] && [[ "$lib_pkg" != "unknown" ]]; then
            local already_seen
            already_seen=$(echo "$seen_pkgs" | jq --arg pkg "$lib_pkg" '.[$pkg] // false')
            if [[ "$already_seen" != "true" ]]; then
                pkg_list=$(echo "$pkg_list" | jq ". + [\"$lib_pkg\"]")
                seen_pkgs=$(echo "$seen_pkgs" | jq ".[$lib_pkg] = true")
            fi
        fi
    done < <(ldd "$exec_path" 2>/dev/null || true)

    echo "$pkg_list"
}

build_service_dependency_map() {
    log "Building service dependency map..."

    local services_json='[]'
    local processed=0
    local failed=0

    local active_services
    active_services=$(systemctl list-units --type=service --state=active --no-pager \
        --no-legend 2>/dev/null | awk '{print $1}')

    local total_services
    total_services=$(echo "$active_services" | wc -w)
    log "Active services found: $total_services"

    while IFS= read -r service_name; do
        [[ -z "$service_name" ]] && continue

        processed=$((processed + 1))

        log "Processing service $processed/$total_services: $service_name..."

        local exec_path
        exec_path=$(get_executable_path "$service_name")

        if [[ -z "$exec_path" ]] || [[ "$exec_path" == "unknown" ]]; then
            warn "  Could not resolve executable for $service_name"
            failed=$((failed + 1))
            continue
        fi

        local owning_pkg
        owning_pkg=$(get_owning_package "$exec_path")

        local linked_pkgs
        linked_pkgs=$(resolve_link_dependencies "$exec_path")

        # Include owning package in linked_packages array and keep unique
        linked_pkgs=$(echo "$linked_pkgs" | jq ". + [\"$owning_pkg\"]" | jq 'unique')

        local criticality
        criticality=$(get_service_criticality "$service_name")

        local restart_required=false
        if [[ "$(echo "$linked_pkgs" | jq 'length')" -gt 0 ]]; then
            restart_required=true
        fi

        local service_entry
        service_entry=$(jq -n \
            --arg svc "$service_name" \
            --arg exec "$exec_path" \
            --arg owner "$owning_pkg" \
            --argjson linked "$linked_pkgs" \
            --arg crit "$criticality" \
            --argjson restart "$restart_required" \
            '{
                service: $svc,
                exec_path: $exec,
                owning_package: $owner,
                linked_packages: $linked,
                criticality: $crit,
                restart_required_on_patch: $restart
            }')

        services_json=$(echo "$services_json" | jq ". + [$service_entry]")

    done <<< "$active_services"

    jq -n \
        --argjson services "$services_json" \
        --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --argjson total "$total_services" \
        --argjson processed "$processed" \
        --argjson failed "$failed" \
        '{
            generated_at: $generated_at,
            total_active_services: $total,
            services_processed: $processed,
            services_failed: $failed,
            services: $services
        }' > "$OUTPUT_FILE"

    log "Services processed: $processed"
    log "Services failed: $failed"
    log "Dependency map saved to: $OUTPUT_FILE"

    if command -v needrestart &>/dev/null; then
        log "Cross-checking with needrestart -b..."
        needrestart -b 2>/dev/null | head -20 || warn "needrestart check failed"
    fi
}

main() {
    log "Starting service dependency mapping..."

    validate_prerequisites

    build_service_dependency_map

    log "Service dependency mapping complete."
}

main "$@"
