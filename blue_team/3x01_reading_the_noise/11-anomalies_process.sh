#!/bin/bash
#
# 11-anomalies_process.sh - Task 11: Process Execution Anomalies Detection for 3x01
#

set -euo pipefail

SUMMARY_FILE="${SUMMARY_FILE:-$(pwd)/baseline_summary.json}"
LABELED_EVENTS="${LABELED_EVENTS:-$(pwd)/labeled_events.json}"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/anomalies_process.json}"

for f in "$SUMMARY_FILE" "$LABELED_EVENTS"; do
    if [ ! -f "$f" ]; then
        echo "Error: Required file not found at $f" >&2
        exit 1
    fi
done

python3 - "$SUMMARY_FILE" "$LABELED_EVENTS" "$OUTPUT_FILE" <<'PYTHON_EOF'
import sys
import json
from datetime import datetime, timezone
from collections import defaultdict, Counter

summary_file = sys.argv[1]
labeled_file = sys.argv[2]
output_file = sys.argv[3]

# Severity Assignment Rubric
SEVERITY_RUBRIC = {
    "high_risk_process": "CRITICAL",
    "unknown_process_for_host": "HIGH",
    "unknown_parent_child": "MEDIUM",
    "rare_process_spike": "HIGH"
}

# High-risk tooling watchlist
HIGH_RISK_WATCHLIST = {
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
    "nc", "nmap", "wget", "curl", "python3", "bash"
}

with open(summary_file, "r", encoding="utf-8") as f:
    summary = json.load(f)

proc_baseline = summary.get("process", {})
eval_window = summary.get("evaluation_window", {})

eval_start = datetime.fromisoformat(eval_window["start"])
eval_end = datetime.fromisoformat(eval_window["end"])

per_host_base = proc_baseline.get("per_host", {})
parent_child_base = proc_baseline.get("parent_child_pairs", {})
rare_procs_base = {item["process_name"]: item["total_executions"] for item in proc_baseline.get("rare_processes", [])}

# Normalize host process sets from baseline
host_expected_procs = {}
for host, procs in per_host_base.items():
    host_expected_procs[host] = set(procs.keys())

host_expected_pairs = {}
for host, pairs in parent_child_base.items():
    host_expected_pairs[host] = set(pairs)

# Read evaluation window records
eval_records = []
process_labels = {"process_start", "child_process_spawn"}

with open(labeled_file, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
            label = rec.get("canonical_label")
            cat = rec.get("event_category")
            if label not in process_labels and cat != "process":
                continue

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

anomalies = []

count_unknown_proc = 0
count_unknown_pair = 0
count_rare_spike = 0
count_high_risk = 0

# Track process execution counts per host during evaluation window for spike detection
eval_host_proc_counts = defaultdict(Counter)
eval_host_proc_events = defaultdict(lambda: defaultdict(list))

for dt, rec in eval_records:
    host = rec.get("hostname") or rec.get("host") or "unknown"
    proc_name = rec.get("process_name") or rec.get("image") or rec.get("process") or "unknown"
    parent_proc = rec.get("parent_process_name") or rec.get("parent_image") or rec.get("parent_process") or "unknown"
    user = rec.get("username") or rec.get("user") or rec.get("account") or "unknown"

    if proc_name != "unknown" and ("\\" in proc_name or "/" in proc_name):
        proc_name = proc_name.replace("\\", "/").split("/")[-1]

    if parent_proc != "unknown" and ("\\" in parent_proc or "/" in parent_proc):
        parent_proc = parent_proc.replace("\\", "/").split("/")[-1]

    eval_host_proc_counts[host][proc_name] += 1
    eval_host_proc_events[host][proc_name].append((dt, rec, parent_proc, user))

    expected_procs = host_expected_procs.get(host, set())
    
    # 1. high_risk_process check (Watchlist tool running on a host where it did not run in baseline)
    if proc_name.lower() in HIGH_RISK_WATCHLIST and proc_name not in expected_procs:
        count_high_risk += 1
        anomalies.append({
            "timestamp": dt.isoformat(),
            "host": host,
            "user": user,
            "process_name": proc_name,
            "parent_process_name": parent_proc,
            "anomaly_type": "high_risk_process",
            "severity": SEVERITY_RUBRIC["high_risk_process"],
            "event_refs": [rec.get("event_id") or rec.get("id") or "eval_event"]
        })
    # 2. unknown_process_for_host check
    elif proc_name not in expected_procs:
        count_unknown_proc += 1
        anomalies.append({
            "timestamp": dt.isoformat(),
            "host": host,
            "user": user,
            "process_name": proc_name,
            "parent_process_name": parent_proc,
            "anomaly_type": "unknown_process_for_host",
            "severity": SEVERITY_RUBRIC["unknown_process_for_host"],
            "event_refs": [rec.get("event_id") or rec.get("id") or "eval_event"]
        })

    # 3. unknown_parent_child check
    if parent_proc != "unknown" and proc_name != "unknown":
        pair_str = f"{parent_proc} -> {proc_name}"
        expected_pairs = host_expected_pairs.get(host, set())
        if pair_str not in expected_pairs:
            count_unknown_pair += 1
            anomalies.append({
                "timestamp": dt.isoformat(),
                "host": host,
                "user": user,
                "process_name": proc_name,
                "parent_process_name": parent_proc,
                "anomaly_type": "unknown_parent_child",
                "severity": SEVERITY_RUBRIC["unknown_parent_child"],
                "event_refs": [rec.get("event_id") or rec.get("id") or "eval_event"]
            })

# 4. rare_process_spike check (< 5 total runs in baseline, > 10 runs in eval window on single host)
for host, procs in eval_host_proc_counts.items():
    for proc_name, eval_count in procs.items():
        base_count = rare_procs_base.get(proc_name)
        if base_count is not None and base_count < 5 and eval_count > 10:
            count_rare_spike += 1
            sample_events = eval_host_proc_events[host][proc_name]
            first_dt, first_rec, sample_parent, sample_user = sample_events[0]
            anomalies.append({
                "timestamp": first_dt.isoformat(),
                "host": host,
                "user": sample_user,
                "process_name": proc_name,
                "parent_process_name": sample_parent,
                "anomaly_type": "rare_process_spike",
                "severity": SEVERITY_RUBRIC["rare_process_spike"],
                "event_refs": [r.get("event_id") or "spike_event" for _, r, _, _ in sample_events[:5]]
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

print(f"evaluation window : {eval_start.isoformat()} -> {eval_end.isoformat()}")
print(f"unknown_process_for_host : {count_unknown_proc}")
print(f"unknown_parent_child     : {count_unknown_pair}")
print(f"rare_process_spike       : {count_rare_spike}")
print(f"high_risk_process        : {count_high_risk}")
print(f"total anomalies          : {len(anomalies)}")
print(f"{output_file} written")

PYTHON_EOF
