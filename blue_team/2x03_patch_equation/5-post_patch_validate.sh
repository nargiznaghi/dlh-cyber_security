#!/bin/bash
#
# Name:        5-post_patch_validate.sh
# Purpose:     Validate post-patch service state, listening ports, and liveness probes
# Author:      Nargiz Naghiyeva
# Date:        August 17, 2026
#

set -euo pipefail

readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly EXECUTION_LOG="${BASE_DIR}/patch_execution_log.json"
readonly DEPS_MAP_FILE="${BASE_DIR}/service_dependency_map.json"
readonly PRE_STATE_FILE="${BASE_DIR}/pre_patch_state.json"
readonly PROBES_FILE="${BASE_DIR}/service_probes.json"
readonly OUTPUT_FILE="${BASE_DIR}/post_patch_validation.json"

validate_prerequisites() {
    local missing=0

    if [[ ! -f "$PRE_STATE_FILE" && ! -f "$EXECUTION_LOG" ]]; then
        echo "ERROR: Neither pre_patch_state.json nor patch_execution_log.json found" >&2
        missing=1
    fi

    if [[ ! -f "$DEPS_MAP_FILE" ]]; then
        echo "ERROR: Service dependency map not found: $DEPS_MAP_FILE" >&2
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

get_current_service_state() {
    local service="$1"
    systemctl show "$service" --property=ActiveState --value 2>/dev/null || echo "unknown"
}

check_port_listening() {
    local port="$1"

    if command -v ss >/dev/null 2>&1; then
        ss -tulnp 2>/dev/null | grep -E -q ":${port}\b" && return 0
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulnp 2>/dev/null | grep -E -q ":${port}\b" && return 0
    fi

    return 1
}

get_expected_port_for_service() {
    local service="$1"

    case "$service" in
        *apache2*|*httpd*) echo "80" ;;
        *ssh*)             echo "22" ;;
        *mysql*|*mariadb*) echo "3306" ;;
        *postgres*)        echo "5432" ;;
        *nginx*)           echo "80" ;;
        *redis*)           echo "6379" ;;
        *bind9*|*named*)   echo "53" ;;
        *docker*)          echo "2375" ;;
        *)                 echo "" ;;
    esac
}

run_liveness_probe() {
    local service="$1"
    local probe_type="$2"
    local probe_target="$3"
    local timeout_sec="${4:-10}"

    case "$probe_type" in
        "http"|"https")
            curl -sf --max-time "$timeout_sec" "$probe_target" >/dev/null 2>&1
            ;;
        "mysql")
            local host="${probe_target%%:*}"
            local port="${probe_target##*:}"
            if [[ "$host" == "$port" ]]; then port="3306"; fi
            mysqladmin ping -h "$host" -P "$port" 2>/dev/null | grep -q "mysqld is alive" && return 0
            check_port_listening "$port" && return 0
            return 1
            ;;
        "ssh")
            ssh -o BatchMode=yes -o ConnectTimeout="$timeout_sec" "$probe_target" exit 0 >/dev/null 2>&1
            ;;
        "tcp_connect")
            local host="${probe_target%%:*}"
            local port="${probe_target##*:}"
            if [[ "$host" == "$port" ]]; then host="127.0.0.1"; fi
            timeout "$timeout_sec" bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null
            ;;
        "command")
            eval "$probe_target" >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

get_pre_patch_services() {
    if [[ -f "$PRE_STATE_FILE" ]]; then
        jq -r '.services[]?.service // empty' "$PRE_STATE_FILE" 2>/dev/null | sort -u
    else
        jq -r '.services[]?.service // empty' "$DEPS_MAP_FILE" 2>/dev/null | sort -u
    fi
}

get_pre_patch_service_state() {
    local service="$1"

    if [[ -f "$PRE_STATE_FILE" ]]; then
        local state
        state=$(jq -r --arg s "$service" '.services[]? | select(.service == $s) | .active_state // empty' "$PRE_STATE_FILE" 2>/dev/null || echo "")
        if [[ -n "$state" ]]; then
            echo "$state"
            return
        fi
    fi

    if [[ -f "$EXECUTION_LOG" ]]; then
        local log_state
        log_state=$(jq -r --arg s "$service" '[.entries[].pre.service_states[]? | select(.service == $s)] | .[0].active_state // "unknown"' "$EXECUTION_LOG" 2>/dev/null || echo "unknown")
        echo "$log_state"
        return
    fi

    echo "active"
}

perform_validation() {
    local service_check_pass=0 service_check_total=0
    local socket_check_pass=0 socket_check_total=0
    local probe_check_pass=0 probe_check_total=0

    declare -a details_array=()

    # 1. SERVICE STATE CHECKS
    while IFS= read -r svc; do
        [[ -z "$svc" || "$svc" == "(kernel-wide)" || "$svc" == "(system-wide)" ]] && continue

        local pre_state current_state status
        pre_state=$(get_pre_patch_service_state "$svc")
        current_state=$(get_current_service_state "$svc")

        service_check_total=$((service_check_total + 1))

        if [[ "$pre_state" == "active" && "$current_state" != "active" ]]; then
            status="regression"
        else
            status="pass"
            service_check_pass=$((service_check_pass + 1))
        fi

        local detail
        detail=$(jq -n \
            --arg svc "$svc" \
            --arg pre "$pre_state" \
            --arg cur "$current_state" \
            --arg status "$status" \
            '{check_type:"service_state",service:$svc,expected:$pre,actual:$cur,status:$status}')

        details_array+=("$detail")

    done < <(get_pre_patch_services)

    # 2. LISTENING SOCKET CHECKS
    local sockets_source='[]'
    if [[ -f "$PRE_STATE_FILE" ]]; then
        sockets_source=$(jq '.listening_ports // .listening // []' "$PRE_STATE_FILE" 2>/dev/null || echo '[]')
    fi

    local socket_count
    socket_count=$(echo "$sockets_source" | jq 'length' 2>/dev/null || echo 0)

    if [[ "$socket_count" -gt 0 ]]; then
        while IFS= read -r sock_entry; do
            [[ -z "$sock_entry" ]] && continue

            local port protocol status
            port=$(echo "$sock_entry" | jq -r '.port // .port_number')
            protocol=$(echo "$sock_entry" | jq -r '.protocol // "tcp"')

            [[ -z "$port" || "$port" == "null" ]] && continue

            socket_check_total=$((socket_check_total + 1))

            if check_port_listening "$port"; then
                status="pass"
                socket_check_pass=$((socket_check_pass + 1))
            else
                status="regression"
            fi

            local detail
            detail=$(jq -n \
                --arg port "$port" \
                --arg proto "$protocol" \
                --arg status "$status" \
                '{check_type:"listening_socket",port:$port,protocol:$proto,status:$status}')

            details_array+=("$detail")

        done < <(echo "$sockets_source" | jq -c '.[]')
    else
        while IFS= read -r svc; do
            [[ -z "$svc" ]] && continue

            local port
            port=$(get_expected_port_for_service "$svc")
            [[ -z "$port" ]] && continue

            socket_check_total=$((socket_check_total + 1))

            local status
            if check_port_listening "$port"; then
                status="pass"
                socket_check_pass=$((socket_check_pass + 1))
            else
                status="regression"
            fi

            local detail
            detail=$(jq -n \
                --arg svc "$svc" \
                --arg port "$port" \
                --arg status "$status" \
                '{check_type:"listening_socket",service:$svc,port:$port,protocol:"tcp",status:$status}')

            details_array+=("$detail")

        done < <(get_pre_patch_services)
    fi

    # 3. CRITICAL LIVENESS PROBES
    local critical_services_json
    critical_services_json=$(jq -c '[.services[]? | select(.criticality == "critical") | .service] | unique' "$DEPS_MAP_FILE" 2>/dev/null || echo '[]')

    local probes_json='[]'
    if [[ -f "$PROBES_FILE" ]]; then
        probes_json=$(jq -c --argjson critical "$critical_services_json" \
            '[.probes[]? | select(.service as $s | $critical | index($s))]' \
            "$PROBES_FILE" 2>/dev/null || echo '[]')
    fi

    local probe_count
    probe_count=$(echo "$probes_json" | jq 'length' 2>/dev/null || echo 0)

    if [[ "$probe_count" -gt 0 ]]; then
        while IFS= read -r probe_entry; do
            [[ -z "$probe_entry" ]] && continue

            local svc p_type p_target p_timeout status result_msg
            svc=$(echo "$probe_entry" | jq -r '.service')
            p_type=$(echo "$probe_entry" | jq -r '.type')
            p_target=$(echo "$probe_entry" | jq -r '.target')
            p_timeout=$(echo "$probe_entry" | jq -r '.timeout // 10')

            probe_check_total=$((probe_check_total + 1))

            if run_liveness_probe "$svc" "$p_type" "$p_target" "$p_timeout"; then
                status="pass"
                result_msg="Probe succeeded"
                probe_check_pass=$((probe_check_pass + 1))
            else
                status="probe_failed"
                result_msg="Probe failed"
            fi

            local detail
            detail=$(jq -n \
                --arg svc "$svc" \
                --arg type "$p_type" \
                --arg target "$p_target" \
                --arg status "$status" \
                --arg result "$result_msg" \
                '{check_type:"liveness_probe",service:$svc,probe_type:$type,target:$target,status:$status,result:$result}')

            details_array+=("$detail")

        done < <(echo "$probes_json" | jq -c '.[]')
    fi

    # BUILD FINAL REPORT
    local total_checks=$((service_check_total + socket_check_total + probe_check_total))
    local total_passed=$((service_check_pass + socket_check_pass + probe_check_pass))
    local total_failed=$((total_checks - total_passed))

    local hostname_val verdict
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    if [[ $total_failed -eq 0 ]]; then
        verdict="PASS"
    else
        verdict="FAIL"
    fi

    local details_json='[]'
    for detail in "${details_array[@]:-}"; do
        [[ -z "$detail" ]] && continue
        details_json=$(echo "$details_json" | jq ". + [$detail]")
    done

    jq -n \
        --arg host "$hostname_val" \
        --argjson total "$total_checks" \
        --argjson passed "$total_passed" \
        --argjson failed "$total_failed" \
        --arg verdict "$verdict" \
        --argjson svc_total "$service_check_total" \
        --argjson svc_pass "$service_check_pass" \
        --argjson sock_total "$socket_check_total" \
        --argjson sock_pass "$socket_check_pass" \
        --argjson probe_total "$probe_check_total" \
        --argjson probe_pass "$probe_check_pass" \
        --argjson details "$details_json" \
        '{
            hostname: $host,
            generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
            total_checks: $total,
            passed: $passed,
            failed: $failed,
            verdict: $verdict,
            summary: {
                service_state: {checked: $svc_total, passed: $svc_pass},
                listening_sockets: {checked: $sock_total, passed: $sock_pass},
                liveness_probes: {checked: $probe_total, passed: $probe_pass}
            },
            details: $details
        }' > "$OUTPUT_FILE"

    local svc_status="PASS"
    [[ "$service_check_pass" -lt "$service_check_total" ]] && svc_status="FAIL"

    local sock_status="PASS"
    [[ "$socket_check_pass" -lt "$socket_check_total" ]] && sock_status="FAIL"

    local probe_status="PASS"
    [[ "$probe_check_pass" -lt "$probe_check_total" ]] && probe_status="FAIL"

    printf 'Service state checks:     %d/%-4d %s\n' "$service_check_pass" "$service_check_total" "$svc_status"
    printf 'Listening socket checks:  %d/%-4d %s\n' "$socket_check_pass" "$socket_check_total" "$sock_status"
    printf 'Critical liveness probes: %d/%-4d %s\n' "$probe_check_pass" "$probe_check_total" "$probe_status"
    printf 'VERDICT: %s (%d/%d)\n' "$verdict" "$total_passed" "$total_checks"
    echo "Report saved to: post_patch_validation.json"

    if [[ $total_failed -gt 0 ]]; then
        return 1
    fi
    return 0
}

main() {
    validate_prerequisites

    if perform_validation; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
