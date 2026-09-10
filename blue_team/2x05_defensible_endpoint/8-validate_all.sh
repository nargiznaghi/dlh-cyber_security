#!/bin/bash
#
# 8-validate_all.sh - Hawthorne capstone, Task 8
#
# End-to-End Validation Suite for Hawthorne Defensible Endpoint & Network Stack.
# Reads capstone/target_state.json, walks every control, executes the dispatch
# check, records evidence, and produces a final machine-readable report.
#
# Usage:
#   ./8-validate_all.sh [-c CAPSTONE_ROOT] [-t TARGET_STATE] [-o REPORT_FILE] [-h]
#

set -euo pipefail
set -o pipefail

readonly SCRIPT_NAME="8-validate_all.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCHEMA_VERSION="1.0"
readonly RECORD_TYPE="capstone_validation_report"

CAPSTONE_ROOT="${CAPSTONE_ROOT:-.}"
TARGET_STATE=""
REPORT_FILE=""

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -c CAPSTONE_ROOT  Path to capstone root directory (default: .)
  -t TARGET_STATE   Path to target_state.json (default: <CAPSTONE_ROOT>/capstone/target_state.json)
  -o REPORT_FILE    Path to output validation_report.json (default: <CAPSTONE_ROOT>/capstone/validation_report.json)
  -h, --help        Show this help message
EOF
}

log() {
    printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

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

main() {
    local arg root_abs

    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -c) CAPSTONE_ROOT="$2"; shift 2 ;;
            -t) TARGET_STATE="$2"; shift 2 ;;
            -o) REPORT_FILE="$2"; shift 2 ;;
            -h | --help) usage; exit 0 ;;
            *) log "ERROR unknown argument: $arg"; exit 2 ;;
        esac
    done

    root_abs=$(cd "$CAPSTONE_ROOT" && pwd)
    
    if [[ -z "$TARGET_STATE" ]]; then
        TARGET_STATE="${root_abs}/capstone/target_state.json"
    fi

    if [[ -z "$REPORT_FILE" ]]; then
        REPORT_FILE="${root_abs}/capstone/validation_report.json"
    fi

    if [[ ! -f "$TARGET_STATE" ]]; then
        log "FATAL target_state.json not found at ${TARGET_STATE}"
        exit 2
    fi

    for dep in python3 jq; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log "ERROR missing required dependency: $dep"
            exit 2
        fi
    done

    log "INFO  Starting End-to-End Capstone Validation"
    log "INFO  Target State Contract: $TARGET_STATE"

    # Execute Python validator engine
    python3 - "$root_abs" "$TARGET_STATE" "$REPORT_FILE" <<'PY'
import json, os, sys, subprocess, datetime, re

root_abs = sys.argv[1]
target_state_path = sys.argv[2]
report_out_path = sys.argv[3]

with open(target_state_path, "r") as fh:
    target_data = json.load(fh)

controls = target_data.get("controls", [])
results = []

total_count = len(controls)
pass_count = 0
fail_count = 0
error_count = 0

family_stats = {}

def resolve_path(p):
    if not p:
        return p
    if os.path.isabs(p):
        return p
    return os.path.join(root_abs, p)

for ctrl in controls:
    cid = ctrl.get("id", "UNKNOWN")
    family = ctrl.get("family", "General")
    description = ctrl.get("description", "")
    check_type = ctrl.get("check_type", "")
    check_target = ctrl.get("check_target", "")
    expected = ctrl.get("expected_value", None)

    if family not in family_stats:
        family_stats[family] = {"total": 0, "pass": 0, "fail": 0, "error": 0}
    
    family_stats[family]["total"] += 1

    verdict = "error"
    evidence = ""

    try:
        if check_type == "file_exists":
            target_path = resolve_path(check_target)
            if os.path.exists(target_path):
                verdict = "pass"
                evidence = f"File exists at {check_target}"
            else:
                verdict = "fail"
                evidence = f"File missing at {check_target}"

        elif check_type in ("json_field_equals", "json_field_gte"):
            target_path = resolve_path(check_target)
            if not os.path.exists(target_path):
                verdict = "fail"
                evidence = f"JSON artifact missing: {check_target}"
            else:
                field_path = ctrl.get("json_field", "")
                with open(target_path, "r") as jfh:
                    jdata = json.load(jfh)
                
                # Navigate nested JSON field (e.g., "status.active" or "tests_failed")
                cur = jdata
                parts = field_path.split(".") if field_path else []
                found = True
                for p in parts:
                    if isinstance(cur, dict) and p in cur:
                        cur = cur[p]
                    else:
                        found = False
                        break
                
                if not found:
                    verdict = "fail"
                    evidence = f"Field '{field_path}' not found in {check_target}"
                else:
                    if check_type == "json_field_equals":
                        if cur == expected:
                            verdict = "pass"
                            evidence = f"Field '{field_path}' == {cur} (matches expected)"
                        else:
                            verdict = "fail"
                            evidence = f"Field '{field_path}' == {cur} (expected: {expected})"
                    elif check_type == "json_field_gte":
                        try:
                            val_num = float(cur)
                            exp_num = float(expected)
                            if val_num >= exp_num:
                                verdict = "pass"
                                evidence = f"Field '{field_path}' == {val_num} >= {exp_num}"
                            else:
                                verdict = "fail"
                                evidence = f"Field '{field_path}' == {val_num} < {exp_num}"
                        except (ValueError, TypeError):
                            verdict = "error"
                            evidence = f"Non-numeric field comparison for '{field_path}': got {cur}"

        elif check_type == "command_exit_zero":
            proc = subprocess.run(check_target, shell=True, cwd=root_abs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if proc.returncode == 0:
                verdict = "pass"
                evidence = f"Command exited 0: '{check_target}'"
            else:
                verdict = "fail"
                evidence = f"Command exited {proc.returncode}: '{check_target}'"

        elif check_type == "grep_match":
            target_path = resolve_path(check_target)
            if not os.path.exists(target_path):
                verdict = "fail"
                evidence = f"Target file missing for grep: {check_target}"
            else:
                pattern = str(expected)
                regex = re.compile(pattern)
                matched = False
                with open(target_path, "r") as gfh:
                    for line in gfh:
                        if regex.search(line):
                            matched = True
                            break
                if matched:
                    verdict = "pass"
                    evidence = f"Pattern '{pattern}' matched in {check_target}"
                else:
                    verdict = "fail"
                    evidence = f"Pattern '{pattern}' not found in {check_target}"
        else:
            verdict = "error"
            evidence = f"Unknown check_type: '{check_type}'"

    except Exception as exc:
        verdict = "error"
        evidence = f"Exception during check execution: {str(exc)}"

    if verdict == "pass":
        pass_count += 1
        family_stats[family]["pass"] += 1
    elif verdict == "fail":
        fail_count += 1
        family_stats[family]["fail"] += 1
    else:
        error_count += 1
        family_stats[family]["error"] += 1

    results.append({
        "id": cid,
        "family": family,
        "description": description,
        "check_type": check_type,
        "verdict": verdict,
        "evidence": evidence
    })

pass_pct = round((pass_count / total_count * 100), 2) if total_count > 0 else 0.0
overall_status = "READY" if (fail_count == 0 and error_count == 0) else "NOT_READY"

report_doc = {
    "schema_version": "1.0",
    "record_type": "capstone_validation_report",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "status": overall_status,
    "summary": {
        "total_controls": total_count,
        "passed": pass_count,
        "failed": fail_count,
        "errors": error_count,
        "pass_percentage": pass_pct
    },
    "family_summary": family_stats,
    "controls": results
}

os.makedirs(os.path.dirname(report_out_path), exist_ok=True)
tmp_out = report_out_path + ".tmp"
with open(tmp_out, "w") as rfh:
    json.dump(report_doc, rfh, indent=2)
    rfh.write("\n")
os.replace(tmp_out, report_out_path)

# Print Summary Table to stdout
print("\n" + "="*70)
print(f" HAWTHORNE CAPSTONE END-TO-END VALIDATION REPORT")
print("="*70)
print(f"{'CONTROL FAMILY':<30} | {'TOTAL':<7} | {'PASS':<6} | {'FAIL':<6} | {'ERR':<5}")
print("-" * 70)

for fam, st in sorted(family_stats.items()):
    print(f"{fam:<30} | {st['total']:<7} | {st['pass']:<6} | {st['fail']:<6} | {st['error']:<5}")

print("-" * 70)
print(f"{'TOTALS':<30} | {total_count:<7} | {pass_count:<6} | {fail_count:<6} | {error_count:<5}")
print("="*70)
print(f"Overall Pass Percentage: {pass_pct}%")
print(f"Environment Status    : {overall_status}")
print(f"Full Report Saved To  : {report_out_path}")
print("="*70 + "\n")

if fail_count > 0 or error_count > 0:
    print("FAILED / ERROR CONTROLS:")
    for r in results:
        if r["verdict"] in ("fail", "error"):
            print(f"  [{r['verdict'].upper()}] {r['id']} ({r['family']}): {r['evidence']}")
    print("")
    sys.exit(1)

sys.exit(0)
PY

}

main "$@"

