#!/bin/bash
#
# 0-source_inventory.sh - Task 0: Evidence Pack Inventory
#
# Generates source_inventory.json for all files inside the evidence pack 
# and outputs a human-readable summary to stdout.
#

set -euo pipefail

# Read paths from variables with fallback defaults
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/source_inventory.json}"
EVIDENCE_YEAR="${EVIDENCE_YEAR:-2026}"

if [ ! -d "$EVIDENCE_PACK" ]; then
    echo "Error: Evidence pack directory not found at $EVIDENCE_PACK" >&2
    exit 1
fi

python3 - "$EVIDENCE_PACK" "$OUTPUT_FILE" "$EVIDENCE_YEAR" <<'PYTHON'
import os
import sys
import json
import csv
import re
import hashlib
from datetime import datetime, timezone

root_dir = sys.argv[1]
output_file = sys.argv[2]
evidence_year = int(sys.argv[3])

categories = ["windows", "linux", "network"]

def calculate_sha256(file_path):
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

def to_iso_utc(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_timestamp(value):
    if value is None:
        return None
    val_str = str(value).strip()
    if not val_str:
        return None

    # Epoch timestamp
    try:
        if re.fullmatch(r"\d+(?:\.\d+)?", val_str):
            ts = float(val_str)
            if ts > 1e11:
                ts /= 1000.0
            return to_iso_utc(datetime.fromtimestamp(ts, tz=timezone.utc))
    except (ValueError, OverflowError):
        pass

    # ISO 8601 parsing
    try:
        text = val_str
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
        dt = datetime.fromisoformat(text)
        return to_iso_utc(dt)
    except ValueError:
        pass

    # Standard date formats
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(val_str, fmt)
            return to_iso_utc(dt.replace(tzinfo=timezone.utc))
        except ValueError:
            pass

    # Syslog format: "Oct 12 04:15:20"
    try:
        dt = datetime.strptime(f"{evidence_year} {val_str}", "%Y %b %d %H:%M:%S")
        return to_iso_utc(dt.replace(tzinfo=timezone.utc))
    except ValueError:
        pass

    return None

def read_json_data(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()
    if not content:
        return []
    
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Fallback to NDJSON
    records = []
    for line in content.splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records

def inspect_windows(path):
    records = read_json_data(path)
    times = []
    ts_keys = ["timestamp_raw", "TimeCreated", "@timestamp", "timestamp", "EventTime", "SystemTime"]
    
    for r in records:
        if not isinstance(r, dict):
            continue
        for k in ts_keys:
            val = r.get(k)
            if val is not None:
                if isinstance(val, dict) and "#attributes" in val:
                    val = val["#attributes"].get("SystemTime")
                ts = parse_timestamp(val)
                if ts:
                    times.append(ts)
                    break

    return {
        "record_count": len(records),
        "first_event_time": min(times) if times else None,
        "last_event_time": max(times) if times else None
    }

def inspect_linux(path):
    line_count = 0
    times = []
    
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_count += 1
            line_str = line.strip()
            if not line_str:
                continue

            # Audit log format
            audit_match = re.search(r'msg=audit\(([\d.]+):\d+\)', line_str)
            if audit_match:
                ts = parse_timestamp(audit_match.group(1))
                if ts:
                    times.append(ts)
                continue

            # Syslog format
            syslog_match = re.match(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line_str)
            if syslog_match:
                ts = parse_timestamp(syslog_match.group(1))
                if ts:
                    times.append(ts)
                continue

            # ISO format in text
            iso_match = re.search(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b', line_str)
            if iso_match:
                ts = parse_timestamp(iso_match.group(0))
                if ts:
                    times.append(ts)

    return {
        "line_count": line_count,
        "first_event_time": min(times) if times else None,
        "last_event_time": max(times) if times else None
    }

def inspect_csv(path):
    record_count = 0
    times = []
    
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            record_count += 1
            for col in ["timestamp", "time", "Date", "EventTime", "datetime"]:
                if col in row and row[col]:
                    ts = parse_timestamp(row[col])
                    if ts:
                        times.append(ts)
                        break

    return {
        "record_count": record_count,
        "first_event_time": min(times) if times else None,
        "last_event_time": max(times) if times else None
    }

def inspect_network_json(path):
    records = read_json_data(path)
    first_times = []
    last_times = []

    for r in records:
        if not isinstance(r, dict):
            continue
        
        if "timestamp" in r:
            ts = parse_timestamp(r.get("timestamp"))
            if ts:
                first_times.append(ts)
                last_times.append(ts)
        elif "start_time" in r or "start" in r:
            s_ts = parse_timestamp(r.get("start_time") or r.get("start"))
            e_ts = parse_timestamp(r.get("end_time") or r.get("end"))
            if s_ts:
                first_times.append(s_ts)
            if e_ts:
                last_times.append(e_ts)
            elif s_ts:
                last_times.append(s_ts)

    return {
        "record_count": len(records),
        "first_event_time": min(first_times) if first_times else None,
        "last_event_time": max(last_times) if last_times else None
    }

inventory = []
summary = {
    "windows": {"files": 0, "bytes": 0},
    "linux": {"files": 0, "bytes": 0},
    "network": {"files": 0, "bytes": 0}
}

for category in categories:
    cat_dir = os.path.join(root_dir, category)
    if not os.path.isdir(cat_dir):
        continue

    for current_root, _, filenames in os.walk(cat_dir):
        for filename in sorted(filenames):
            if filename.startswith("."):
                continue
            
            full_path = os.path.join(current_root, filename)
            rel_path = os.path.relpath(full_path, root_dir)
            size = os.path.getsize(full_path)

            if category == "windows":
                source_type = "windows_json"
                details = inspect_windows(full_path)
            elif category == "linux":
                source_type = "linux_text"
                details = inspect_linux(full_path)
            elif filename.lower().endswith(".csv"):
                source_type = "network_csv"
                details = inspect_csv(full_path)
            else:
                source_type = "network_json"
                details = inspect_network_json(full_path)

            entry = {
                "path": rel_path,
                "source_type": source_type,
                "size_bytes": size,
                "sha256": calculate_sha256(full_path)
            }
            entry.update(details)
            inventory.append(entry)

            summary[category]["files"] += 1
            summary[category]["bytes"] += size

inventory.sort(key=lambda x: x["path"])

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(inventory, f, indent=2)
    f.write("\n")

# Summary stdout formatting
tot_files = sum(summary[c]["files"] for c in categories)
tot_bytes = sum(summary[c]["bytes"] for c in categories)

for cat in categories:
    f_cnt = summary[cat]["files"]
    b_cnt = summary[cat]["bytes"]
    mb_val = b_cnt / (1024 * 1024)
    print(f"{cat:<8}: {f_cnt} files  |  {mb_val:4.1f} MB")

tot_mb = tot_bytes / (1024 * 1024)
print(f"{'total':<8}: {tot_files} files  |  {tot_mb:4.1f} MB")
print(f"manifest written to {os.path.basename(output_file)}")

PYTHON
