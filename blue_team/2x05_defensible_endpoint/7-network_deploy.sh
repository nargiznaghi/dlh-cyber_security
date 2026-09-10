#!/bin/bash
#
# 7-network_deploy.sh - Hawthorne capstone, Task 7
#
# Deploys the network defense stack on hawthorne-app-01 and validates it. It
# wraps the 2x04 network pipeline rather than reimplementing it: artifacts are
# redirected into the capstone package, the Hawthorne segmentation contract is
# used instead of the main MedDefense topology, the firewall validation suite
# gates everything downstream, Suricata is replayed offline against the
# capstone PCAP set, and dnsmasq is configured as the local DNS filter.
#
# Usage:
#   sudo ./7-network_deploy.sh [-o CAPSTONE_ROOT] [-p PIPELINE] [-s SEG_FILE]
#                              [-P PCAP_DIR] [-R RULES_FILE] [-B BLOCKLIST]
#                              [-V VALIDATION_SUITE] [-a "ARGS"]
#                              [--skip-dns] [--skip-pipeline] [-h]
#

set -euo pipefail
set -o pipefail

readonly SCRIPT_NAME="7-network_deploy.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"
readonly RECORD_TYPE="network_deployment"

readonly ARTIFACTS_DIR_VALUE="capstone/network/"
readonly NETWORK_SUBDIR="capstone/network"
readonly LOG_RELPATH="capstone/network/network_deploy.log"
readonly SUMMARY_RELPATH="capstone/network/network_summary.json"
readonly RECORD_BASENAME="network_summary.json"
readonly TARGET_STATE_RELPATH="capstone/target_state.json"
readonly DNSMASQ_CONF="/etc/dnsmasq.d/meddefense-capstone.conf"
readonly BLOCK_BEGIN="# BEGIN meddefense-capstone managed block"
readonly BLOCK_END="# END meddefense-capstone managed block"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
PIPELINE="${NETWORK_PIPELINE:-/home/analyst/MedDefense_Lab/2x04/17-network_pipeline.sh}"
SEG_FILE="/home/analyst/MedDefense_Lab/capstone/segmentation_rules.json"
PCAP_DIR="/home/analyst/MedDefense_Lab/capstone/PCAPs/"
RULES_FILE="/home/analyst/MedDefense_Lab/capstone/meddefense.rules"
BLOCKLIST="/home/analyst/MedDefense_Lab/capstone/dns_blocklist.txt"
VALIDATION_SUITE="${FIREWALL_TEST_SUITE:-/home/analyst/MedDefense_Lab/2x04/5-firewall_test.sh}"
PIPELINE_ARGS=()
PIPELINE_ARGS_SET=0
SKIP_DNS=0
SKIP_PIPELINE=0
TMP_JSON=""
COLLECTION_ERRORS=()

PIPELINE_RC=0
EXTERNAL_SUITE_FAILED=0
FW_TOTAL=0
FW_PASSED=0
FW_FAILED=0
PCAP_COUNT=0
ALERT_COUNT=0
RULES_LOADED=0
RULES_NOT_FIRED=1
DNS_ACTIVE="false"
DNS_CHANGED="false"
DNS_DOMAINS=0

usage() {
    sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'
}

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

record_error() {
    COLLECTION_ERRORS+=("$1")
    log "WARN  $1"
}

cleanup() {
    if [[ -n "$TMP_JSON" && -f "$TMP_JSON" ]]; then
        rm -f "$TMP_JSON"
    fi
}
trap cleanup EXIT

json_escape() {
    local s
    s=$(printf '%s' "${1-}" | tr -d '\000-\010\013\014\016-\037')
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

jstr() {
    printf '"%s"' "$(json_escape "${1-}")"
}

jnum() {
    local v="${1-}"
    if [[ "$v" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
        printf '%s' "$v"
    else
        printf 'null'
    fi
}

emit() {
    printf '%s\n' "$*" >>"$TMP_JSON"
}

get_hostname() {
    if command -v hostname >/dev/null 2>&1; then
        hostname
    else
        uname -n
    fi
}

file_digest() {
    if [[ -r "$1" ]] && command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    fi
}

run_firewall_validation() {
    local out="$1" ruleset=""

    if [[ -n "$VALIDATION_SUITE" && -x "$VALIDATION_SUITE" ]]; then
        log "INFO  running the firewall validation suite: $VALIDATION_SUITE"
        set +e
        "$VALIDATION_SUITE" >>"$LOG_FILE" 2>&1
        local ext_rc=$?
        set -e
        if [[ "$ext_rc" -ne 0 ]]; then
            record_error "firewall validation suite ${VALIDATION_SUITE} exited ${ext_rc}"
            EXTERNAL_SUITE_FAILED=1
        fi
    elif [[ -n "$VALIDATION_SUITE" ]]; then
        log "INFO  ${VALIDATION_SUITE} not present; using built-in validation suite"
    fi

    ruleset=$(nft list ruleset 2>/dev/null || true)

    SEG_FILE="$SEG_FILE" NFT_RULESET="$ruleset" python3 - "$out" <<'PY'
import json, os, re, sys, datetime

out_path = sys.argv[1]
ruleset = os.environ.get("NFT_RULESET", "")
seg_path = os.environ["SEG_FILE"]

tests = []

def add(name, description, passed, detail=""):
    tests.append({
        "test": name,
        "description": description,
        "passed": bool(passed),
        "detail": detail,
    })

add("ruleset_loaded", "nftables ruleset is non-empty", bool(ruleset.strip()), "{0} bytes".format(len(ruleset)))

input_drop = re.search(r"hook\s+input\b[^\n]*policy\s+drop", ruleset)
add("input_default_deny", "input chain defaults to drop", bool(input_drop), input_drop.group(0).strip() if input_drop else "not found")

fwd_drop = re.search(r"hook\s+forward\b[^\n]*policy\s+drop", ruleset)
add("forward_default_deny", "forward chain defaults to drop", bool(fwd_drop), fwd_drop.group(0).strip() if fwd_drop else "not found")

add("loopback_allowed", "loopback traffic is permitted", bool(re.search(r'iif(name)?\s+"?lo"?', ruleset)), "")
add("established_allowed", "established/related traffic is permitted", bool(re.search(r"ct\s+state[^\n]*established", ruleset)), "")

try:
    with open(seg_path) as fh:
        seg = json.load(fh)
    add("segmentation_contract_readable", "Hawthorne segmentation contract parses", True, seg_path)
except Exception as exc:
    add("segmentation_contract_readable", "Hawthorne segmentation contract parses", False, str(exc))
    seg = None

if seg is not None:
    rules = seg.get("rules", []) if isinstance(seg, dict) else (seg if isinstance(seg, list) else [])
    add("segmentation_rules_present", "segmentation contract declares at least one rule", len(rules) > 0, "{0} rule(s)".format(len(rules)))

passed = sum(1 for t in tests if t["passed"])
failed = len(tests) - passed

doc = {
    "schema_version": "1.0",
    "record_type": "firewall_validation",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "segmentation_contract": seg_path,
    "tests_total": len(tests),
    "tests_passed": passed,
    "tests_failed": failed,
    "result": "pass" if failed == 0 else "fail",
    "tests": tests,
}

tmp = out_path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
os.replace(tmp, out_path)
print("{0} {1} {2}".format(len(tests), passed, failed))
PY
}

run_suricata_replay() {
    local pcap_dir="$1" work_dir="$2" pcap base rc
    local count=0

    mkdir -p "$work_dir"

    while IFS= read -r pcap; do
        [[ -z "$pcap" ]] && continue
        base=$(basename "$pcap")
        base="${base%.*}"
        mkdir -p "${work_dir}/${base}"
        log "INFO  replaying ${base}"
        {
            printf '===== SURICATA REPLAY %s =====\n' "$base"
        } >>"$LOG_FILE"
        set +e
        if [[ -r "$RULES_FILE" ]]; then
            suricata -r "$pcap" -l "${work_dir}/${base}" -S "$RULES_FILE" -k none >>"$LOG_FILE" 2>&1
        else
            suricata -r "$pcap" -l "${work_dir}/${base}" -k none >>"$LOG_FILE" 2>&1
        fi
        rc=$?
        set -e
        if [[ "$rc" -ne 0 ]]; then
            record_error "suricata replay of ${base} exited ${rc}"
        fi
        count=$((count + 1))
    done < <(find "$pcap_dir" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.pcapng' \) 2>/dev/null | LC_ALL=C sort)

    printf '%s' "$count"
}

parse_suricata_results() {
    SURICATA_WORK="$1" RULES_FILE="$RULES_FILE" PCAP_DIR="$PCAP_DIR" \
        python3 - "$2" "$3" <<'PY'
import json, os, re, sys, datetime

alerts_out, report_out = sys.argv[1], sys.argv[2]
work = os.environ["SURICATA_WORK"]
rules_path = os.environ["RULES_FILE"]
pcap_dir = os.environ["PCAP_DIR"]

alerts = []
for root, _dirs, files in os.walk(work):
    pcap_name = os.path.basename(root)
    for name in files:
        if name != "eve.json":
            continue
        with open(os.path.join(root, name)) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except ValueError:
                    continue
                if evt.get("event_type") != "alert":
                    continue
                alert = evt.get("alert", {})
                alerts.append({
                    "pcap": pcap_name,
                    "timestamp": evt.get("timestamp"),
                    "signature_id": alert.get("signature_id"),
                    "signature": alert.get("signature"),
                    "category": alert.get("category"),
                    "severity": alert.get("severity"),
                    "src_ip": evt.get("src_ip"),
                    "src_port": evt.get("src_port"),
                    "dest_ip": evt.get("dest_ip"),
                    "dest_port": evt.get("dest_port"),
                    "proto": evt.get("proto"),
                })

alerts.sort(key=lambda a: (a["pcap"], str(a["timestamp"] or "")))
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

with open(alerts_out + ".tmp", "w") as fh:
    json.dump({
        "schema_version": "1.0",
        "record_type": "suricata_alerts",
        "generated_at": now,
        "mode": "offline_replay",
        "pcap_dir": pcap_dir,
        "alert_count": len(alerts),
        "alerts": alerts,
    }, fh, indent=2)
    fh.write("\n")
os.replace(alerts_out + ".tmp", alerts_out)

rules = []
sid_re = re.compile(r"\bsid\s*:\s*(\d+)")
msg_re = re.compile(r'\bmsg\s*:\s*"([^"]*)"')
try:
    with open(rules_path) as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = sid_re.search(stripped)
            if m:
                msg = msg_re.search(stripped)
                rules.append({"sid": int(m.group(1)), "msg": msg.group(1) if msg else None})
except FileNotFoundError:
    pass

fired_sids = set(a["signature_id"] for a in alerts if a.get("signature_id"))
not_fired = [r for r in rules if r["sid"] not in fired_sids]

with open(report_out + ".tmp", "w") as fh:
    json.dump({
        "schema_version": "1.0",
        "record_type": "rule_validation",
        "generated_at": now,
        "rules_file": rules_path,
        "rules_loaded": len(rules),
        "rules_fired": len(rules) - len(not_fired),
        "rules_not_fired_count": len(not_fired),
        "all_rules_fired": len(not_fired) == 0 and len(rules) > 0,
        "rules": rules,
    }, fh, indent=2)
    fh.write("\n")
os.replace(report_out + ".tmp", report_out)
cp_rule = os.path.join(os.path.dirname(report_out), "rule_validation.json")
os.system(f"cp -f {report_out} {cp_rule}")

print("{0} {1} {2}".format(len(alerts), len(rules), len(not_fired)))
PY
}

write_managed_block() {
    local file="$1" body="$2"
    MD_BLOCK_BODY="$body" MD_BEGIN="$BLOCK_BEGIN" MD_END="$BLOCK_END" \
        python3 - "$file" <<'PY'
import os, re, sys

path = sys.argv[1]
begin = os.environ["MD_BEGIN"]
end = os.environ["MD_END"]
body = os.environ["MD_BLOCK_BODY"]

try:
    with open(path) as fh:
        text = fh.read()
except FileNotFoundError:
    text = ""

new_block = "{0}\n{1}\n{2}\n".format(begin, body, end)
pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end) + r"\n?", re.S)

if pattern.search(text):
    updated = pattern.sub(new_block, text)
else:
    prefix = (text.rstrip("\n") + "\n\n") if text.strip() else ""
    updated = prefix + new_block

if updated == text:
    print("unchanged")
else:
    tmp = path + ".meddefense.tmp"
    with open(tmp, "w") as fh:
        fh.write(updated)
    os.replace(tmp, path)
    print("changed")
PY
}

configure_dns_filter() {
    local out="$1" body domains result active="false"

    domains=$(grep -vE '^\s*(#|$)' "$BLOCKLIST" 2>/dev/null | awk '{print $NF}' | LC_ALL=C sort -u || true)
    DNS_DOMAINS=$(printf '%s\n' "$domains" | grep -c . || true)

    if [[ "$DNS_DOMAINS" -eq 0 ]]; then
        record_error "DNS blocklist ${BLOCKLIST} yielded no domains"
    fi

    body=""
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        body+="address=/${domain}/0.0.0.0"$'\n'
    done <<<"$domains"
    body="${body%$'\n'}"

    mkdir -p "$(dirname "$DNSMASQ_CONF")"
    result=$(write_managed_block "$DNSMASQ_CONF" "$body")
    if [[ "$result" == "changed" ]]; then
        DNS_CHANGED="true"
        log "INFO  wrote ${DNS_DOMAINS} blocked domain(s) to ${DNSMASQ_CONF}"
    fi

    if command -v dnsmasq >/dev/null 2>&1; then
        if ! dnsmasq --test >>"$LOG_FILE" 2>&1; then
            record_error "dnsmasq configuration failed syntax test"
        elif [[ "$DNS_CHANGED" == "true" ]]; then
            systemctl restart dnsmasq >>"$LOG_FILE" 2>&1 || record_error "dnsmasq restart failed"
        fi
        systemctl enable dnsmasq >>"$LOG_FILE" 2>&1 || true
        if systemctl is-active --quiet dnsmasq 2>/dev/null; then
            active="true"
        fi
    else
        record_error "dnsmasq is not installed"
    fi

    DNS_ACTIVE="$active"

    DNS_ACTIVE="$active" DNS_CHANGED="$DNS_CHANGED" DNS_DOMAINS="$DNS_DOMAINS" \
        DNS_CONF="$DNSMASQ_CONF" DNS_BLOCKLIST="$BLOCKLIST" python3 - "$out" <<'PY'
import json, os, sys, datetime

out_path = sys.argv[1]
doc = {
    "schema_version": "1.0",
    "record_type": "dns_filter_status",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "provider": "dnsmasq",
    "active": os.environ["DNS_ACTIVE"] == "true",
    "config_path": os.environ["DNS_CONF"],
    "blocklist_path": os.environ["DNS_BLOCKLIST"],
    "blocked_domain_count": int(os.environ["DNS_DOMAINS"]),
    "config_changed": os.environ["DNS_CHANGED"] == "true",
}
tmp = out_path + ".tmp"
with open(tmp, "w") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
os.replace(tmp, out_path)
PY
}

write_summary() {
    local out="$1" overall_result="$2"
    TMP_JSON=$(mktemp)

    emit "{"
    emit "  \"schema_version\": \"$SCHEMA_VERSION\","
    emit "  \"record_type\": \"$RECORD_TYPE\","
    emit "  \"generated_at\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
    emit "  \"result\": \"$overall_result\","
    emit "  \"pipeline_exit_code\": $PIPELINE_RC,"
    emit "  \"firewall_tests_total\": $FW_TOTAL,"
    emit "  \"firewall_tests_passed\": $FW_PASSED,"
    emit "  \"firewall_tests_failed\": $FW_FAILED,"
    emit "  \"pcaps_replayed\": $PCAP_COUNT,"
    emit "  \"alerts_generated\": $ALERT_COUNT,"
    emit "  \"custom_rules_loaded\": $RULES_LOADED,"
    emit "  \"custom_rules_not_fired\": $RULES_NOT_FIRED,"
    emit "  \"dns_filter_active\": $DNS_ACTIVE,"
    emit "  \"dns_blocked_domains\": $DNS_DOMAINS,"
    emit "  \"errors\": ["
    local first=1
    for err in "${COLLECTION_ERRORS[@]+"${COLLECTION_ERRORS[@]}"}"; do
        [[ $first -eq 0 ]] && emit ","
        emit "    $(jstr "$err")"
        first=0
    done
    emit ""
    emit "  ]"
    emit "}"

    mv "$TMP_JSON" "$out"
    TMP_JSON=""
}

main() {
    local arg hn net_dir out_file target_state dep root_abs
    local fw_out alerts_out report_out dns_out suricata_work
    local fw_result parse_result result="pass"

    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -o) CAPSTONE_ROOT="$2"; shift 2 ;;
            -p) PIPELINE="$2"; shift 2 ;;
            -s) SEG_FILE="$2"; shift 2 ;;
            -P) PCAP_DIR="$2"; shift 2 ;;
            -R) RULES_FILE="$2"; shift 2 ;;
            -B) BLOCKLIST="$2"; shift 2 ;;
            -V) VALIDATION_SUITE="$2"; shift 2 ;;
            -a) read -r -a PIPELINE_ARGS <<<"$2"; PIPELINE_ARGS_SET=1; shift 2 ;;
            --skip-dns) SKIP_DNS=1; shift ;;
            --skip-pipeline) SKIP_PIPELINE=1; shift ;;
            -h | --help) usage; exit 0 ;;
            *) log "ERROR unknown argument: $arg"; exit 2 ;;
        esac
    done

    if [[ "$(id -u)" -ne 0 ]]; then
        log "ERROR network deployment must run as root; re-run with sudo"
        exit 2
    fi

    for dep in nft suricata python3 find awk date sha256sum; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "ERROR missing required dependency: $dep"
            exit 2
        fi
    done

    target_state="${CAPSTONE_ROOT}/${TARGET_STATE_RELPATH}"
    if [[ ! -f "$target_state" ]]; then
        log "FATAL target state contract is missing: $target_state"
        exit 2
    fi

    if [[ "$PIPELINE_ARGS_SET" -eq 0 ]]; then
        PIPELINE_ARGS=("$SEG_FILE")
    fi

    hn=$(get_hostname)
    root_abs=$(cd "$CAPSTONE_ROOT" && pwd)
    net_dir="${root_abs}/${NETWORK_SUBDIR}"
    mkdir -p "$net_dir"
    
    LOG_FILE="${root_abs}/${LOG_RELPATH}"
    out_file="${net_dir}/${RECORD_BASENAME}"
    fw_out="${net_dir}/firewall_validation.json"
    alerts_out="${net_dir}/suricata_alerts.json"
    report_out="${net_dir}/suricata_rule_report.json"
    dns_out="${net_dir}/dns_filter_status.json"
    suricata_work="${net_dir}/suricata"

    : >"$LOG_FILE"
    cp -f "$SEG_FILE" "${net_dir}/segmentation_rules.json"

    # 1. Pipeline execution
    if [[ "$SKIP_PIPELINE" -eq 0 ]]; then
        log "INFO  invoking pipeline"
        set +e
        (
            cd "$root_abs" || exit 2
            export CAPSTONE_ARTIFACTS_DIR="$ARTIFACTS_DIR_VALUE"
            export CAPSTONE_SEGMENTATION_FILE="$SEG_FILE"
            export SEGMENTATION_RULES="$SEG_FILE"
            export CAPSTONE_PCAP_DIR="$PCAP_DIR"
            "$PIPELINE" "${PIPELINE_ARGS[@]+"${PIPELINE_ARGS[@]}"}"
        ) >>"$LOG_FILE" 2>&1
        PIPELINE_RC=$?
        set -e
        if [[ "$PIPELINE_RC" -ne 0 ]]; then
            record_error "network pipeline exited ${PIPELINE_RC}"
            result="fail"
        fi
    fi

    # 2. Firewall Validation
    log "INFO  running firewall validation"
    fw_result=$(run_firewall_validation "$fw_out")
    FW_TOTAL=$(printf '%s' "$fw_result" | awk '{print $1}')
    FW_PASSED=$(printf '%s' "$fw_result" | awk '{print $2}')
    FW_FAILED=$(printf '%s' "$fw_result" | awk '{print $3}')

    if [[ "$FW_FAILED" -ne 0 || "$EXTERNAL_SUITE_FAILED" -ne 0 ]]; then
        record_error "firewall validation failed"
        write_summary "$out_file" "fail"
        exit 1
    fi

    # 3. Suricata Replay
    log "INFO  replaying capstone PCAP set"
    PCAP_COUNT=$(run_suricata_replay "$PCAP_DIR" "$suricata_work")
    parse_result=$(parse_suricata_results "$suricata_work" "$alerts_out" "$report_out")

    ALERT_COUNT=$(printf '%s' "$parse_result" | awk '{print $1}')
    RULES_LOADED=$(printf '%s' "$parse_result" | awk '{print $2}')
    RULES_NOT_FIRED=$(printf '%s' "$parse_result" | awk '{print $3}')

    if [[ "$RULES_NOT_FIRED" -ne 0 ]]; then
        record_error "${RULES_NOT_FIRED} custom rule(s) did not fire against PCAP set"
        result="fail"
    fi

    # 4. DNS Filter Config
    if [[ "$SKIP_DNS" -eq 0 ]]; then
        log "INFO  configuring DNS filter"
        configure_dns_filter "$dns_out"
    fi

    # Summary and Exit
    write_summary "$out_file" "$result"
    
    if [[ "$result" == "fail" ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
