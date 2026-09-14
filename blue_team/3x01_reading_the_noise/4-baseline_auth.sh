#!/bin/bash
#
# 4-baseline_auth.sh - Task 4: Authentication Baseline for 3x01
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
LABELED_EVENTS="${LABELED_EVENTS:-$(pwd)/labeled_events.json}"
BASELINE_AUTH_OUT="${BASELINE_AUTH_OUT:-$(pwd)/baseline_auth.json}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

if [ ! -f "$LABELED_EVENTS" ]; then
    echo "Error: Labeled events file not found at $LABELED_EVENTS" >&2
    exit 1
fi

python3 - "$LABELED_EVENTS" "$BASELINE_AUTH_OUT" "$BASELINE_DAYS" <<'PYTHON_EOF'
import sys
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict

labeled_file = sys.argv[1]
output_file = sys.argv[2]
baseline_days_arg = float(sys.argv[3])

records = []
timestamps = []

with open(labeled_file, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
            records.append(rec)
            ts_str = rec.get("timestamp")
            if ts_str:
                if ts_str.endswith("Z"):
                    ts_str = ts_str[:-1] + "+00:00"
                dt = datetime.fromisoformat(ts_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                timestamps.append(dt)
        except Exception:
            continue

if not timestamps:
    print("Error: No timestamps found in dataset.")
    sys.exit(1)

min_dt = min(timestamps)
max_dt = max(timestamps)

# Dynamic window calculation
baseline_start = min_dt
baseline_end = min_dt + timedelta(days=baseline_days_arg)
if baseline_end > max_dt:
    baseline_end = max_dt

per_host = defaultdict(lambda: {"login_success": 0, "login_failure": 0, "logout": 0, "account_lockout": 0, "privilege_escalation": 0})
per_user = defaultdict(lambda: {"success": 0, "failure": 0})
known_accounts = set()

business_hours_success = 0
business_hours_failure = 0
business_hours_hours = 0

offhours_success = 0
offhours_failure = 0
offhours_hours = 0

# For tracking max failures in 1h window per src_ip
ip_failures = defaultdict(list)

auth_labels = {"login_success", "login_failure", "logout", "account_lockout", "privilege_escalation"}

for rec in records:
    label = rec.get("canonical_label")
    if label not in auth_labels:
        continue

    ts_str = rec.get("timestamp")
    if not ts_str:
        continue
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    rec_dt = datetime.fromisoformat(ts_str)
    if rec_dt.tzinfo is None:
        rec_dt = rec_dt.replace(tzinfo=timezone.utc)

    if rec_dt < baseline_start or rec_dt >= baseline_end:
        continue

    host = rec.get("hostname") or rec.get("host") or "unknown"
    user = rec.get("username") or rec.get("user") or rec.get("account")
    src_ip = rec.get("src_ip") or "unknown"

    if user:
        known_accounts.add(str(user))

    # Per host counts
    if label in per_host[host]:
        per_host[host][label] += 1

    # Per user counts
    if user:
        if label == "login_success":
            per_user[user]["success"] += 1
        elif label == "login_failure":
            per_user[user]["failure"] += 1

    # Business hours vs Off hours (06:00 to 17:59 UTC)
    hour = rec_dt.hour
    if 6 <= hour < 18:
        if label == "login_success":
            business_hours_success += 1
        elif label == "login_failure":
            business_hours_failure += 1
    else:
        if label == "login_success":
            offhours_success += 1
        elif label == "login_failure":
            offhours_failure += 1

    # Single src_ip failure tracking
    if label == "login_failure" and src_ip != "unknown":
        ip_failures[src_ip].append(rec_dt)

# Compute hourly averages
total_baseline_hours = (baseline_end - baseline_start).total_seconds() / 3600.0
# Approximate splitting 12h business / 12h off-hours per day
total_days = total_baseline_hours / 24.0
biz_hours_total = total_days * 12.0
off_hours_total = total_days * 12.0

biz_success_avg = round(business_hours_success / biz_hours_total, 2) if biz_hours_total > 0 else 0
biz_failure_avg = round(business_hours_failure / biz_hours_total, 2) if biz_hours_total > 0 else 0

off_success_avg = round(offhours_success / off_hours_total, 2) if off_hours_total > 0 else 0
off_failure_avg = round(offhours_failure / off_hours_total, 2) if off_hours_total > 0 else 0

# Sliding 1-hour window for max src_ip failures
max_failures_1h = 0
for ip, fail_times in ip_failures.items():
    fail_times.sort()
    for i in range(len(fail_times)):
        window_start = fail_times[i]
        window_end = window_start + timedelta(hours=1)
        count = sum(1 for t in fail_times if window_start <= t < window_end)
        if count > max_failures_1h:
            max_failures_1h = count

baseline_output = {
    "window": {
        "start": baseline_start.isoformat(),
        "end": baseline_end.isoformat()
    },
    "per_host": dict(per_host),
    "per_user": dict(per_user),
    "known_accounts": sorted(list(known_accounts)),
    "business_hours_avg": {
        "success_per_hour": biz_success_avg,
        "failure_per_hour": biz_failure_avg
    },
    "offhours_avg": {
        "success_per_hour": off_success_avg,
        "failure_per_hour": off_failure_avg
    },
    "max_failures_1h_window": max_failures_1h
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(baseline_output, f, indent=2, ensure_ascii=False)

print(f"baseline window : {baseline_start.isoformat()} -> {baseline_end.isoformat()}")
print(f"hosts           : {len(per_host)}")
print(f"known accounts  : {len(known_accounts)}")
print(f"business hours  : {biz_success_avg} success/h  |  {biz_failure_avg} failure/h")
print(f"off hours       : {off_success_avg} success/h  |  {off_failure_avg} failure/h")
print(f"max 1h src_ip failures : {max_failures_1h}")
print(f"{output_file} written")

PYTHON_EOF
