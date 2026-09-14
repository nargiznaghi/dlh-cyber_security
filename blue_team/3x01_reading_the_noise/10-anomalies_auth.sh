#!/bin/bash
#
# 10-anomalies_auth.sh - Task 10: Authentication Anomalies Detection for 3x01
#

set -euo pipefail

SUMMARY_FILE="${SUMMARY_FILE:-$(pwd)/baseline_summary.json}"
LABELED_EVENTS="${LABELED_EVENTS:-$(pwd)/labeled_events.json}"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/anomalies_auth.json}"

for f in "$SUMMARY_FILE" "$LABELED_EVENTS"; do
    if [ ! -f "$f" ]; then
        echo "Error: Required file not found at $f" >&2
        exit 1
    fi
done

python3 - "$SUMMARY_FILE" "$LABELED_EVENTS" "$OUTPUT_FILE" <<'PYTHON_EOF'
import sys
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict

summary_file = sys.argv[1]
labeled_file = sys.argv[2]
output_file = sys.argv[3]

with open(summary_file, "r", encoding="utf-8") as f:
    summary = json.load(f)

auth_baseline = summary.get("auth", {})
eval_window = summary.get("evaluation_window", {})
thresholds = summary.get("thresholds", {})

eval_start_str = eval_window.get("start")
eval_end_str = eval_window.get("end")

if not eval_start_str or not eval_end_str:
    sys.stderr.write("Error: Evaluation window bounds missing in baseline summary.\n")
    sys.exit(1)

eval_start = datetime.fromisoformat(eval_start_str)
eval_end = datetime.fromisoformat(eval_end_str)

known_accounts = set(auth_baseline.get("known_accounts", []))
max_failures_1h_base = auth_baseline.get("max_failures_1h_window", 5)
failure_multiplier = thresholds.get("failure_rate_multiplier", {}).get("value", 3.0)
allowed_burst_limit = int(max_failures_1h_base * failure_multiplier)

# Per-user historical business hours pattern check from baseline per_user
# If user had logins in baseline, check if they EVER logged in offhours (06:00 to 17:59 UTC is business)
# Let's extract per-user business-hour-only behavior if tracked, or assume offhours login is anomalous 
# if user only logged in during business hours in baseline.
# For simplicity, we track baseline user login hours from labeled file during baseline window.
b_window = summary.get("baseline_window", {})
b_start = datetime.fromisoformat(b_window.get("start"))
b_end = datetime.fromisoformat(b_window.get("end"))

user_has_offhours_in_baseline = set()
host_priv_esc_baseline = defaultdict(int)

# Re-scan baseline dataset or extract from per_user / records if needed
# Let's read labeled file to build precise baseline user time profiles and host priv-esc counts
with open(labeled_file, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
            ts_str = rec.get("timestamp")
            if not ts_str:
                continue
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            if b_start <= dt < b_end:
                label = rec.get("canonical_label")
                user = rec.get("username") or rec.get("user") or rec.get("account")
                host = rec.get("hostname") or rec.get("host") or "unknown"
                
                if label == "login_success" and user:
                    hour = dt.hour
                    if not (6 <= hour < 18):
                        user_has_offhours_in_baseline.add(str(user))
                
                if label == "privilege_escalation":
                    host_priv_esc_baseline[host] += 1
        except Exception:
            continue

anomalies = []
eval_records = []

# Collect evaluation window records
with open(labeled_file, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
            ts_str = rec.get("timestamp")
            if not ts_str:
                continue
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            if eval_start <= dt <= eval_end:
                eval_records.append((dt, rec))
        except Exception:
            continue

# 1. unknown_account check
unknown_account_count = 0
for dt, rec in eval_records:
    label = rec.get("canonical_label")
    if label in {"login_success", "login_failure"}:
        user = rec.get("username") or rec.get("user") or rec.get("account")
        if user and str(user) not in known_accounts:
            unknown_account_count += 1
            anomalies.append({
                "timestamp": dt.isoformat(),
                "host": rec.get("hostname") or rec.get("host") or "unknown",
                "user": str(user),
                "src_ip": rec.get("src_ip") or "unknown",
                "anomaly_type": "unknown_account",
                "baseline_value": 0,
                "observed_value": str(user),
                "severity": "HIGH",
                "event_refs": [rec.get("event_id") or rec.get("id") or "eval_event"]
            })

# 2. failure_rate_burst check (sliding 1-hour window per src_ip in evaluation window)
failure_burst_count = 0
src_failures_eval = defaultdict(list)
for dt, rec in eval_records:
    if rec.get("canonical_label") == "login_failure":
        src_ip = rec.get("src_ip")
        if src_ip and src_ip != "unknown":
            src_failures_eval[src_ip].append((dt, rec))

for src_ip, fails in src_failures_eval.items():
    fails.sort(key=lambda x: x[0])
    for i in range(len(fails)):
        w_start = fails[i][0]
        w_end = w_start + timedelta(hours=1)
        window_fails = [f for f in fails if w_start <= f[0] < w_end]
        if len(window_fails) > allowed_burst_limit:
            # Report anomaly for the peak or each event exceeding
            failure_burst_count += len(window_fails)
            sample_rec = window_fails[0][1]
            anomalies.append({
                "timestamp": w_start.isoformat(),
                "host": sample_rec.get("hostname") or sample_rec.get("host") or "unknown",
                "user": sample_rec.get("username") or sample_rec.get("user") or "multiple",
                "src_ip": src_ip,
                "anomaly_type": "failure_rate_burst",
                "baseline_value": max_failures_1h_base,
                "observed_value": len(window_fails),
                "severity": "CRITICAL",
                "event_refs": [r.get("event_id") or "burst_event" for _, r in window_fails[:5]]
            })
            # Skip ahead to avoid duplicate reporting of the same burst window
            break

# 3. offhours_login check
offhours_login_count = 0
for dt, rec in eval_records:
    if rec.get("canonical_label") == "login_success":
        user = rec.get("username") or rec.get("user") or rec.get("account")
        hour = dt.hour
        # Offhours: 18:00 to 05:59
        if user and not (6 <= hour < 18):
            # If user existed in baseline but NEVER logged in off-hours during baseline
            if str(user) in known_accounts and str(user) not in user_has_offhours_in_baseline:
                offhours_login_count += 1
                anomalies.append({
                    "timestamp": dt.isoformat(),
                    "host": rec.get("hostname") or rec.get("host") or "unknown",
                    "user": str(user),
                    "src_ip": rec.get("src_ip") or "unknown",
                    "anomaly_type": "offhours_login",
                    "baseline_value": "business_hours_only",
                    "observed_value": f"hour_{hour}",
                    "severity": "MEDIUM",
                    "event_refs": [rec.get("event_id") or "offhours_event"]
                })

# 4. privilege_escalation_surge check (> 0 events on a host where baseline has zero)
priv_surge_count = 0
eval_host_priv_esc = defaultdict(list)
for dt, rec in eval_records:
    if rec.get("canonical_label") == "privilege_escalation":
        host = rec.get("hostname") or rec.get("host") or "unknown"
        eval_host_priv_esc[host].append((dt, rec))

for host, events in eval_host_priv_esc.items():
    baseline_count = host_priv_esc_baseline.get(host, 0)
    if baseline_count == 0 and len(events) > 0:
        priv_surge_count += len(events)
        sample_dt, sample_rec = events[0]
        anomalies.append({
            "timestamp": sample_dt.isoformat(),
            "host": host,
            "user": sample_rec.get("username") or sample_rec.get("user") or "unknown",
            "src_ip": sample_rec.get("src_ip") or "unknown",
            "anomaly_type": "privilege_escalation_surge",
            "baseline_value": 0,
            "observed_value": len(events),
            "severity": "HIGH",
            "event_refs": [r.get("event_id") or "priv_event" for _, r in events]
        })

output_doc = {
    "evaluation_window": {
        "start": eval_start.isoformat(),
        "end": eval_end.isoformat()
    },
    "total_anomalies": len(anomalies),
    "anomalies": anomalies
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(output_doc, f, indent=2, ensure_ascii=False)

print(f"evaluation window  : {eval_start.isoformat()} -> {eval_end.isoformat()}")
print(f"unknown_account           : {unknown_account_count}")
print(f"failure_rate_burst        : {failure_burst_count}")
print(f"offhours_login            : {offhours_login_count}")
print(f"privilege_escalation_surge: {priv_surge_count}")
print(f"total anomalies           : {len(anomalies)}")
print(f"{output_file} written")

PYTHON_EOF
