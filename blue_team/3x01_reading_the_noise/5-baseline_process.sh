#!/bin/bash
#
# 5-baseline_process.sh - Task 5: Process Execution Baseline for 3x01
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
LABELED_EVENTS="${LABELED_EVENTS:-$(pwd)/labeled_events.json}"
BASELINE_PROCESS_OUT="${BASELINE_PROCESS_OUT:-$(pwd)/baseline_process.json}"
BASELINE_DAYS="${BASELINE_DAYS:-7}"

if [ ! -f "$LABELED_EVENTS" ]; then
    echo "Error: Labeled events file not found at $LABELED_EVENTS" >&2
    exit 1
fi

python3 - "$LABELED_EVENTS" "$BASELINE_PROCESS_OUT" "$BASELINE_DAYS" <<'PYTHON_EOF'
import sys
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter

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

baseline_start = min_dt
baseline_end = min_dt + timedelta(days=baseline_days_arg)
if baseline_end > max_dt:
    baseline_end = max_dt

process_labels = {"process_start", "child_process_spawn", "process_stop"}

# Data structures for baseline computation
# host -> process_name -> {count, first_seen, last_seen, users}
per_host_data = defaultdict(lambda: defaultdict(lambda: {
    "count": 0,
    "first_seen": None,
    "last_seen": None,
    "users": set()
}))

global_process_counts = Counter()
process_hosts_map = defaultdict(set)
parent_child_pairs_per_host = defaultdict(set)

for rec in records:
    label = rec.get("canonical_label")
    cat = rec.get("event_category")
    
    # Process start / execution events
    if label not in process_labels and cat != "process":
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
    proc_name = rec.get("process_name") or rec.get("image") or rec.get("process") or "unknown"
    user = rec.get("username") or rec.get("user") or rec.get("account")
    parent_proc = rec.get("parent_process_name") or rec.get("parent_image") or rec.get("parent_process")

    # Clean up process path if full path is given (keep filename or standardized path)
    if proc_name != "unknown" and ("\\" in proc_name or "/" in proc_name):
        proc_name = proc_name.replace("\\", "/").split("/")[-1]

    pdata = per_host_data[host][proc_name]
    pdata["count"] += 1
    
    if pdata["first_seen"] is None or rec_dt < pdata["first_seen"]:
        pdata["first_seen"] = rec_dt
    if pdata["last_seen"] is None or rec_dt > pdata["last_seen"]:
        pdata["last_seen"] = rec_dt

    if user:
        pdata["users"].add(str(user))

    global_process_counts[proc_name] += 1
    process_hosts_map[proc_name].add(host)

    if parent_proc and proc_name != "unknown":
        if "\\" in parent_proc or "/" in parent_proc:
            parent_proc = parent_proc.replace("\\", "/").split("/")[-1]
        parent_child_pairs_per_host[host].add(f"{parent_proc} -> {proc_name}")

# Format per_host dictionary for JSON output
per_host_output = {}
for h, procs in per_host_data.items():
    per_host_output[h] = {}
    for p_name, p_info in procs.items():
        per_host_output[h][p_name] = {
            "execution_count": p_info["count"],
            "first_seen": p_info["first_seen"].isoformat() if p_info["first_seen"] else None,
            "last_seen": p_info["last_seen"].isoformat() if p_info["last_seen"] else None,
            "executing_users": sorted(list(p_info["users"]))
        }

# Global top 50 processes
global_top = [{"process_name": p, "execution_count": c} for p, c in global_process_counts.most_common(50)]

# Rare processes: run on only 1 host or total execution count < 5
rare_processes = []
for p_name, count in global_process_counts.items():
    hosts_count = len(process_hosts_map[p_name])
    if hosts_count == 1 or count < 5:
        rare_processes.append({
            "process_name": p_name,
            "total_executions": count,
            "host_count": hosts_count,
            "hosts": sorted(list(process_hosts_map[p_name]))
        })

# Parent-child pairs formatted
parent_child_output = {h: sorted(list(pairs)) for h, pairs in parent_child_pairs_per_host.items()}

total_parent_child_pairs = sum(len(pairs) for pairs in parent_child_pairs_per_host.values())

top_proc_name = global_top[0]["process_name"] if global_top else "N/A"
top_proc_count = global_top[0]["execution_count"] if global_top else 0

baseline_output = {
    "window": {
        "start": baseline_start.isoformat(),
        "end": baseline_end.isoformat()
    },
    "per_host": per_host_output,
    "global_top": global_top,
    "rare_processes": rare_processes,
    "parent_child_pairs": parent_child_output
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(baseline_output, f, indent=2, ensure_ascii=False)

print(f"baseline window : {baseline_start.isoformat()} -> {baseline_end.isoformat()}")
print(f"processes indexed by host: {len(per_host_output)} hosts")
print(f"global top process    : {top_proc_name} ({top_proc_count} executions)")
print(f"rare processes        : {len(rare_processes)}")
print(f"parent->child pairs   : {total_parent_child_pairs}")
print(f"{output_file} written")

PYTHON_EOF
