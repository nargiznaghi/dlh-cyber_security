#!/bin/bash
#
# Name:        9-rollback.sh
# Purpose:     Downgrade a package to its pre-patch version, hold it, and validate
#              affected services
# Author:      Nargiz Naghiyeva
# Date:        August 18, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly PRE_STATE_FILE="${BASE_DIR}/pre_patch_state.json"
readonly DEPS_MAP_FILE="${BASE_DIR}/service_dependency_map.json"
readonly PROBES_FILE="${BASE_DIR}/service_probes.json"

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
# CHECK ARGUMENTS
# ============================================
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <package-name>"
    exit 1
fi

readonly PACKAGE="$1"
readonly OUTPUT_FILE="${BASE_DIR}/rollback_${PACKAGE}.json"

# ============================================
# PREREQUISITE CHECKS
# ============================================
if [[ ! -f "$PRE_STATE_FILE" ]]; then
    warn "Pre-patch state file not found: $PRE_STATE_FILE"
    exit 1
fi

if [[ ! -f "$DEPS_MAP_FILE" ]]; then
    warn "Service dependency map not found: $DEPS_MAP_FILE"
    exit 1
fi

# ============================================
# LOAD TARGET VERSION FROM pre_patch_state.json
# ============================================
load_target_version() {
    local pkg="$1"
    local version

    # Primary lookup: packages[<name>] object/field
    version=$(jq -r --arg p "$pkg" '.packages[$p] // empty' "$PRE_STATE_FILE" 2>/dev/null || echo "")

    if [[ -z "$version" ]]; then
        # Fallback: packages.list array with package/version fields
        version=$(jq -r --arg p "$pkg" '.packages.list[]? | select(.package == $p) | .version // empty' "$PRE_STATE_FILE" 2>/dev/null || echo "")
    fi

    if [[ -z "$version" ]]; then
        # Fallback: without architecture suffix (e.g. zlib1g:amd64 -> zlib1g)
        local pkg_base="${pkg%%:*}"
        version=$(jq -r --arg p "$pkg_base" '.packages[$p] // (.packages.list[]? | select(.package == $p or (.package | split(":")[0]) == $p) | .version) // empty' "$PRE_STATE_FILE" 2>/dev/null || echo "")
    fi

    if [[ -z "$version" ]]; then
        # Fallback: flat array with package/version fields
        version=$(jq -r --arg p "$pkg" '.packages[]? | select(.package == $p or .name == $p) | .version // empty' "$PRE_STATE_FILE" 2>/dev/null || echo "")
    fi

    echo "$version"
}

# ============================================
# GET CURRENT INSTALLED VERSION
# ============================================
get_current_version() {
    local pkg="$1"
    dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo ""
}

# ============================================
# CHECK VERSION AVAILABILITY VIA apt-cache madison
# ============================================
check_version_available() {
    local pkg="$1"
    local target_ver="$2"

    local madison_output
    madison_output=$(apt-cache madison "$pkg" 2>/dev/null || true)

    if [[ -n "$madison_output" ]] && echo "$madison_output" | grep -qF "$target_ver"; then
        return 0
    fi

    # Check local package cache
    if ls /var/cache/apt/archives/${pkg}_*.deb >/dev/null 2>&1; then
        local cached_versions
        cached_versions=$(ls /var/cache/apt/archives/${pkg}_*.deb 2>/dev/null | \
            sed -E 's/.*'"${pkg}"'_([^_]+)_.*/\1/' || echo "")
        if echo "$cached_versions" | grep -qF "$target_ver"; then
            return 0
        fi
    fi

    # Prefix match attempt
    local target_prefix="${target_ver%%-[0-9]*}"
    if [[ -n "$madison_output" ]] && [[ -n "$target_prefix" ]] && echo "$madison_output" | grep -qF "$target_prefix"; then
        return 0
    fi

    return 1
}

# ============================================
# EXECUTE DOWNGRADE
# ============================================
execute_downgrade() {
    local pkg="$1"
    local target_ver="$2"

    local rc=1

    # Strategy 1: Direct install with --allow-downgrades
    set +e
    DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "${pkg}=${target_ver}" >/dev/null 2>&1
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        echo "OK"
        return
    fi

    # Strategy 2: Try with --allow-downgrades --fix-broken
    set +e
    DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades --fix-broken "${pkg}=${target_ver}" >/dev/null 2>&1
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        echo "OK"
        return
    fi

    # Strategy 3: Try unholding if held
    local held
    held=$(apt-mark showholds 2>/dev/null || true)

    if echo "$held" | grep -qw "$pkg"; then
        set +e
        DEBIAN_FRONTEND=noninteractive apt-mark unhold "$pkg" >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "${pkg}=${target_ver}" >/dev/null 2>&1
        rc=$?
        set -e

        if [[ $rc -eq 0 ]]; then
            echo "OK"
            return
        fi
    fi

    echo "FAILED"
}

# ============================================
# APPLY HOLD
# ============================================
apply_hold() {
    local pkg="$1"

    if apt-mark hold "$pkg" >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAILED"
    fi
}

# ============================================
# FIND AFFECTED SERVICES
# ============================================
find_affected_services() {
    local pkg="$1"

    if [[ ! -f "$DEPS_MAP_FILE" ]]; then
        echo ""
        return
    fi

    # Services whose linked_packages contains the package
    jq -r --arg p "$pkg" '
        [.services[]? | select(.linked_packages[]? | . == $p) | .service] | unique | .[]
    ' "$DEPS_MAP_FILE" 2>/dev/null || echo ""

    # Check owning_package field as fallback
    jq -r --arg p "$pkg" '
        [.services[]? | select(.owning_package == $p) | .service] | unique | .[]
    ' "$DEPS_MAP_FILE" 2>/dev/null || echo ""
}

# ============================================
# PORT LOOKUP FOR PROBES
# ============================================
get_expected_port_for_service() {
    local service="$1"

    case "$service" in
        *apache2*)      echo "80" ;;
        *ssh*)          echo "22" ;;
        *mysql*)        echo "3306" ;;
        *postgres*)     echo "5432" ;;
        *nginx*)        echo "80" ;;
        *redis*)        echo "6379" ;;
        *bind9*|*named*) echo "53" ;;
        *docker*)       echo "2375" ;;
        *)              echo "" ;;
    esac
}

# ============================================
# LIGHTWEIGHT LIVENESS PROBE
# ============================================
check_port_listening() {
    local port="$1"

    if command -v ss >/dev/null 2>&1; then
        ss -tulnp 2>/dev/null | grep -q ":${port} " && return 0
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulnp 2>/dev/null | grep -q ":${port} " && return 0
    fi

    return 1
}

run_liveness_probe() {
    local service="$1"
    local timeout_sec="${2:-10}"

    # Check probes file if present
    if [[ -f "$PROBES_FILE" ]]; then
        local probe_type probe_target
        probe_type=$(jq -r --arg s "$service" '.probes[]? | select(.service == $s) | .type // empty' "$PROBES_FILE" 2>/dev/null | head -1 || echo "")
        probe_target=$(jq -r --arg s "$service" '.probes[]? | select(.service == $s) | .target // empty' "$PROBES_FILE" 2>/dev/null | head -1 || echo "")

        if [[ -n "$probe_type" ]] && [[ -n "$probe_target" ]]; then
            case "$probe_type" in
                "http"|"https")
                    curl -sf --max-time "$timeout_sec" "$probe_target" >/dev/null 2>&1 && return 0
                    ;;
                "mysql")
                    local host="${probe_target%%:*}"
                    local port="${probe_target##*:}"
                    mysqladmin ping -h "$host" -P "$port" 2>/dev/null | grep -q "mysqld is alive" && return 0
                    check_port_listening "$port" && return 0
                    ;;
                "ssh")
                    timeout "$timeout_sec" bash -c "echo > /dev/tcp/127.0.0.1/22" 2>/dev/null && return 0
                    check_port_listening "22" && return 0
                    ;;
                "tcp_connect")
                    local host="${probe_target%%:*}"
                    local port="${probe_target##*:}"
                    timeout "$timeout_sec" bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null && return 0
                    check_port_listening "$port" && return 0
                    ;;
            esac
        fi
    fi

    # Fallback probes
    case "$service" in
        *apache2*|*nginx*)
            curl -sf --max-time "$timeout_sec" "http://localhost/" >/dev/null 2>&1 && return 0
            ;;
        *mysql*)
            mysqladmin ping -h "127.0.0.1" -P "3306" 2>/dev/null | grep -q "mysqld is alive" && return 0
            check_port_listening "3306" && return 0
            ;;
        *postgres*)
            pg_isready -h "127.0.0.1" -p "5432" >/dev/null 2>&1 && return 0
            check_port_listening "5432" && return 0
            ;;
        *ssh*)
            timeout "$timeout_sec" bash -c "echo > /dev/tcp/127.0.0.1/22" 2>/dev/null && return 0
            check_port_listening "22" && return 0
            ;;
        *redis*)
            redis-cli -h 127.0.0.1 -p 6379 ping >/dev/null 2>&1 && return 0
            check_port_listening "6379" && return 0
            ;;
        *bind9*|*named*)
            dig +short +time="$timeout_sec" @127.0.0.1 localhost A >/dev/null 2>&1 && return 0
            check_port_listening "53" && return 0
            ;;
    esac

    # Generic TCP port check
    local port
    port=$(get_expected_port_for_service "$service")
    if [[ -n "$port" ]] && check_port_listening "$port"; then
        return 0
    fi

    # Systemd status fallback
    local active_state
    active_state=$(systemctl show "$service" --property=ActiveState --value 2>/dev/null || echo "unknown")
    if [[ "$active_state" == "active" ]]; then
        return 0
    fi

    return 1
}

# ============================================
# RUN PROBES FOR AFFECTED SERVICES
# ============================================
run_affected_probes() {
    local pkg="$1"
    local results='[]'
    local all_pass=true

    local affected
    affected=$(find_affected_services "$pkg" | sort -u | grep -v '^$' || echo "")

    if [[ -z "$affected" ]]; then
        echo "$results"
        return 0
    fi

    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        [[ "$svc" == "(kernel-wide)" ]] && continue
        [[ "$svc" == "(system-wide)" ]] && continue

        local probe_result
        if run_liveness_probe "$svc" 10; then
            probe_result="PASS"
            info "$(printf '%-42s %s' "${svc} probe" "PASS")"
        else
            probe_result="FAIL"
            all_pass=false
            info "$(printf '%-42s %s' "${svc} probe" "FAIL")"
        fi

        local entry
        entry=$(jq -n --arg svc "$svc" --arg result "$probe_result" \
            '{service:$svc, probe:$result}')
        results=$(echo "$results" | jq ". + [$entry]")

    done <<< "$affected"

    if [[ "$all_pass" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

# ============================================
# MAIN
# ============================================
main() {
    local start_time
    start_time=$(date +%s)

    # STEP 1: Load target version
    local target_version
    target_version=$(load_target_version "$PACKAGE")

    if [[ -z "$target_version" ]]; then
        warn "Package '${PACKAGE}' not found in pre_patch_state.json"
        jq -n \
            --arg pkg "$PACKAGE" \
            --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            '{
                package: $pkg,
                error: "Package not found in pre_patch_state.json",
                timestamp: $ts,
                success: false
            }' > "$OUTPUT_FILE"
        exit 1
    fi

    log "Target version from pre_patch_state.json: ${target_version}"

    # STEP 2: Current version
    local current_version
    current_version=$(get_current_version "$PACKAGE")

    if [[ -z "$current_version" ]]; then
        warn "Package '${PACKAGE}' is not currently installed"
        exit 1
    fi

    # STEP 3: Version Availability
    local version_available=false
    if check_version_available "$PACKAGE" "$target_version"; then
        version_available=true
        log "Version available in cache or repository: yes"
    else
        log "Version available in cache or repository: no"
    fi

    # STEP 4: Downgrade Execution
    printf "[*] Downgrading %s... " "$PACKAGE"

    local downgrade_result
    downgrade_result=$(execute_downgrade "$PACKAGE" "$target_version")
    printf "%27s\n" "$downgrade_result"

    local downgrade_ok=false
    if [[ "$downgrade_result" == "OK" ]]; then
        downgrade_ok=true
    fi

    local post_version
    post_version=$(get_current_version "$PACKAGE")

    if [[ "$downgrade_ok" == "true" ]] && [[ "$post_version" != "$target_version" ]]; then
        warn "Installed version (${post_version}) does not match target (${target_version})"
        downgrade_ok=false
    fi

    # STEP 5: Apply Hold
    local hold_ok=false
    if [[ "$downgrade_ok" == "true" ]]; then
        printf "[*] apt-mark hold %s " "$PACKAGE"
        local hold_result
        hold_result=$(apply_hold "$PACKAGE")
        printf "%30s\n" "$hold_result"

        if [[ "$hold_result" == "OK" ]]; then
            hold_ok=true
        fi
    fi

    # STEP 6: Service Probes
    local probe_results='[]'
    local probes_ok=true

    if [[ "$downgrade_ok" == "true" ]] && [[ "$hold_ok" == "true" ]]; then
        log "Re-running probes for affected services..."
        probe_results=$(run_affected_probes "$PACKAGE") || probes_ok=false
    fi

    # STEP 7: Overall Success
    local overall_success=false
    if [[ "$downgrade_ok" == "true" ]] && [[ "$hold_ok" == "true" ]] && [[ "$probes_ok" == "true" ]]; then
        overall_success=true
    fi

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # STEP 8: Emit JSON Audit File
    jq -n \
        --arg pkg "$PACKAGE" \
        --arg current "$current_version" \
        --arg target "$target_version" \
        --arg post "$post_version" \
        --argjson version_avail "$version_available" \
        --argjson downgrade_ok "$downgrade_ok" \
        --argjson hold_ok "$hold_ok" \
        --argjson success "$overall_success" \
        --argjson duration "$duration" \
        --argjson probes "$probe_results" \
        '{
            package: $pkg,
            versions: {
                before_rollback: $current,
                target: $target,
                after_rollback: $post
            },
            version_available: $version_avail,
            downgrade_succeeded: $downgrade_ok,
            hold_applied: $hold_ok,
            service_probes: $probes,
            success: $success,
            duration_seconds: $duration,
            timestamp: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
        }' > "$OUTPUT_FILE"

    # STEP 9: Print Summary Output
    if [[ "$overall_success" == "true" ]]; then
        echo "ROLLBACK: success"
        echo "from ${current_version} to ${target_version}"
        exit 0
    else
        echo "ROLLBACK: failed"
        exit 1
    fi
}

main "$@"
