#!/bin/bash
#
# 9-baseline_summary.sh - Task 9: Cross-Source Baseline Summary for 3x01
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
LABELED_EVENTS="${LABELED_EVENTS:-$(pwd)/labeled_events.json}"

AUTH_FILE="${AUTH_FILE:-$(pwd)/baseline_auth.json}"
PROCESS_FILE="${PROCESS_FILE:-$(pwd)/baseline_process.json}"
NETWORK_FILE="${NETWORK_FILE:-$(pwd)/baseline_network.json}"
FILE_FILE="${FILE_FILE:-$(pwd)/baseline_file.json}"
TEMPORAL_FILE="${TEMPORAL_FILE:-$(pwd)/temporal_profile.json}"

SUMMARY_OUT="${SUMMARY_OUT:-$(pwd)/baseline_summary.json}"

# Əvvəlki baseline fayllarının mövcudluğunu yoxla
for f in "$AUTH_FILE" "$PROCESS_FILE" "$NETWORK_FILE" "$FILE_FILE" "$TEMPORAL_FILE" "$LABELED_EVENTS"; do
    if [ ! -f "$f" ]; then
        echo "Error: Required baseline component file not found at $f" >&2
        exit 1
    fi
done

python3 - "$LABELED_EVENTS" "$AUTH_FILE" "$PROCESS_FILE" "$NETWORK_FILE" "$FILE_FILE" "$TEMPORAL_FILE" "$SUMMARY_OUT" <<'PYTHON_EOF'
import sys
import json
from datetime import datetime, timezone

labeled_file = sys.argv[1]
auth_file = sys.argv[2]
process_file = sys.argv[3]
network_file = sys.argv[4]
file_file = sys.argv[5]
temporal_file = sys.argv[6]
output_file = sys.argv[7]

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

auth_data = load_json(auth_file)
process_data = load_json(process_file)
network_data = load_json(network_file)
file_data = load_json(file_file)
temporal_data = load_json(temporal_file)

# Dataset üzrə ümumi min və max zaman damğalarını (evaluation window üçün) hesablayırıq
timestamps = []
with open(labeled_file, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
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
    sys.stderr.write("Error: Could not extract timestamps from dataset.\n")
    sys.exit(1)

min_dt = min(timestamps)
max_dt = max(timestamps)

# Baseline window
b_start_str = auth_data.get("window", {}).get("start")
b_end_str = auth_data.get("window", {}).get("end")

if b_start_str and b_end_str:
    b_start = datetime.fromisoformat(b_start_str)
    b_end = datetime.fromisoformat(b_end_str)
else:
    b_start = min_dt
    b_end = max_dt

b_duration_days = round((b_end - b_start).total_seconds() / 86400.0, 2)

# Evaluation Window (Day 8: baseline sonundan dataset sonuna qədər)
e_start = b_end
e_end = max_dt
e_duration_hours = round((e_end - e_start).total_seconds() / 3600.0, 2)

# Host Inventarı (bütün baselinelərdən toplanmış unikal hostlar)
host_inventory = set()
for sub_doc in [auth_data, process_data, network_data, file_data]:
    if "per_host" in sub_doc:
        host_inventory.update(sub_doc["per_host"].keys())

# Dynamic Anomaly Thresholds
thresholds = {
    "failure_rate_multiplier": {
        "value": 3.0,
        "comment": "Flags authentication failure spikes exceeding 3x the baseline average rate for a specific host/user."
    },
    "unknown_process_penalty": {
        "value": 5,
        "comment": "Assigns a score penalty of 5 to any executed process name that was not observed during the baseline window."
    },
    "unknown_port_penalty": {
        "value": 4,
        "comment": "Assigns a score penalty of 4 for outbound/inbound connections to destination ports outside baseline allowed list."
    },
    "max_failures_1h_threshold": {
        "value": max(10, auth_data.get("max_failures_1h_window", 0) * 2),
        "comment": "Threshold for brute-force attempt detection, set to 2x the maximum 1-hour failure burst seen in baseline."
    },
    "offhours_activity_threshold": {
        "value": 2.5,
        "comment": "Multiplier for off-hours event density anomaly detection relative to off-hours baseline hourly averages."
    }
}

summary_doc = {
    "version": "1.0",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "baseline_window": {
        "start": b_start.isoformat(),
        "end": b_end.isoformat(),
        "duration_days": b_duration_days
    },
    "evaluation_window": {
        "start": e_start.isoformat(),
        "end": e_end.isoformat(),
        "duration_hours": e_duration_hours
    },
    "host_inventory": sorted(list(host_inventory)),
    "auth": auth_data,
    "process": process_data,
    "network": network_data,
    "file": file_data,
    "temporal": temporal_data,
    "thresholds": thresholds
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(summary_doc, f, indent=2, ensure_ascii=False)

print("version           : 1.0")
print(f"baseline window   : {b_start.isoformat()} -> {b_end.isoformat()}  ({b_duration_days} days)")
print(f"evaluation window : {e_start.isoformat()} -> {e_end.isoformat()}  ({e_duration_hours}h)")
print(f"hosts             : {len(host_inventory)}")
print("sections included : auth, process, network, file, temporal, thresholds")
print(f"{output_file} written")

PYTHON_EOF
