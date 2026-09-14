#!/bin/bash
#
# 5-normalize.sh - Task 5: Normalization Script
#

set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"

WINDOWS_FILE="$WORKDIR/windows_events.json"
LINUX_FILE="$WORKDIR/linux_events.json"
SCHEMA_FILE="$WORKDIR/event_schema.json"

NORMALIZED_FILE="$WORKDIR/normalized_events.json"
QUARANTINE_FILE="$WORKDIR/quarantine.json"

for file in "$WINDOWS_FILE" "$LINUX_FILE" "$SCHEMA_FILE"
do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing file: $file" >&2
        exit 1
    fi
done

python3 - \
    "$WINDOWS_FILE" \
    "$LINUX_FILE" \
    "$SCHEMA_FILE" \
    "$NORMALIZED_FILE" \
    "$QUARANTINE_FILE" <<'PYTHON_EOF'

import json
import os
import sys
from datetime import datetime, timezone

windows_file = sys.argv[1]
linux_file = sys.argv[2]
schema_file = sys.argv[3]
normalized_file = sys.argv[4]
quarantine_file = sys.argv[5]

with open(schema_file, "r", encoding="utf-8") as f:
    schema = json.load(f)

schema_fields = schema["fields"]
field_names = [field["name"] for field in schema_fields]
required_fields = [field["name"] for field in schema_fields if field.get("required", False)]

DEFAULT_YEAR = int(os.environ.get("NORMALIZE_YEAR", 2026))

def normalize_timestamp(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None

    # Epoch timestamp
    try:
        if value.replace(".", "", 1).isdigit():
            ts = float(value)
            dt = datetime.fromtimestamp(ts, timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError):
        pass

    # ISO 8601
    try:
        iso_val = value
        if iso_val.endswith("Z"):
            iso_val = iso_val[:-1] + "+00:00"
        dt = datetime.fromisoformat(iso_val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Linux Syslog (Mar 18 10:22:11)
    try:
        dt = datetime.strptime(f"{DEFAULT_YEAR} {value}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None

def windows_category(record):
    if record.get("event_category"):
        return record["event_category"]
    event_id = str(record.get("event_id", ""))
    channel = str(record.get("channel", "")).lower()
    provider = str(record.get("provider", "")).lower()

    if event_id in {"4624", "4625", "4648"}:
        return "authentication"
    if event_id in {"4720", "4726", "4732"}:
        return "account"
    if event_id == "4688" or event_id == "1":
        return "process"
    if event_id == "3":
        return "network"
    if "powershell" in channel or "powershell" in provider:
        return "powershell"
    return "windows_event"

def linux_category(record):
    if record.get("event_category"):
        return record["event_category"]
    if record.get("audit_type"):
        return "audit"
    program = str(record.get("program") or "").lower()
    if program in {"sshd", "sudo", "su"}:
        return "authentication"
    return "linux_event"

def build_schema_record(values):
    normalized = {name: None for name in field_names}
    for key, value in values.items():
        if key in normalized:
            normalized[key] = value
    return normalized

def normalize_windows(record):
    event_data = record.get("event_data") or {}
    values = {
        "timestamp": normalize_timestamp(record.get("timestamp_raw")),
        "hostname": record.get("hostname"),
        "source_type": "windows_json",
        "source_origin": record.get("source_origin"),
        "event_category": windows_category(record),
        "event_id": record.get("event_id"),
        "severity": record.get("severity") or "informational",
        "user": record.get("user") or event_data.get("TargetUserName") or event_data.get("SubjectUserName"),
        "process_name": record.get("process_name") or event_data.get("Image") or event_data.get("NewProcessName"),
        "process_id": record.get("process_id") or event_data.get("ProcessId") or event_data.get("NewProcessId"),
        "src_ip": record.get("src_ip") or event_data.get("IpAddress") or event_data.get("SourceIp"),
        "src_port": record.get("src_port") or event_data.get("IpPort") or event_data.get("SourcePort"),
        "dst_ip": record.get("dst_ip") or event_data.get("DestinationIp"),
        "dst_port": record.get("dst_port") or event_data.get("DestinationPort"),
        "protocol": record.get("protocol") or event_data.get("Protocol"),
        "raw_message": record.get("raw_message") or json.dumps(record, ensure_ascii=False)
    }
    return build_schema_record(values)

def normalize_linux(record):
    parsed = record.get("parsed_fields") or {}
    values = {
        "timestamp": normalize_timestamp(record.get("timestamp_raw")),
        "hostname": record.get("hostname"),
        "source_type": "linux_text",
        "source_origin": record.get("source_origin"),
        "event_category": linux_category(record),
        "event_id": record.get("audit_type"),
        "severity": record.get("severity") or "informational",
        "user": record.get("user"),
        "process_name": record.get("program"),
        "process_id": record.get("pid"),
        "src_ip": parsed.get("src_ip") or parsed.get("src") or parsed.get("rhost") or parsed.get("addr"),
        "src_port": parsed.get("src_port") or parsed.get("sport"),
        "dst_ip": parsed.get("dst_ip") or parsed.get("dst"),
        "dst_port": parsed.get("dst_port") or parsed.get("dport"),
        "protocol": parsed.get("proto") or parsed.get("protocol"),
        "raw_message": record.get("raw_message") or json.dumps(record, ensure_ascii=False)
    }
    return build_schema_record(values)

def quarantine_reason(record):
    if record.get("timestamp") is None:
        return "unparseable timestamp"
    for field in required_fields:
        if record.get(field) is None:
            return f"missing required field: {field}"
    return None

def process_file(filepath, source_type, normalizer, normalized_output, quarantine_output):
    norm_cnt = 0
    quar_cnt = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                original = json.loads(line)
            except json.JSONDecodeError:
                bad = {
                    "source_type": source_type,
                    "raw_message": line,
                    "quarantine_reason": f"invalid JSON at line {idx}"
                }
                quarantine_output.write(json.dumps(bad, ensure_ascii=False) + "\n")
                quar_cnt += 1
                continue

            normalized = normalizer(original)
            reason = quarantine_reason(normalized)

            if reason:
                bad = dict(original)
                bad["quarantine_reason"] = reason
                quarantine_output.write(json.dumps(bad, ensure_ascii=False) + "\n")
                quar_cnt += 1
            else:
                normalized_output.write(json.dumps(normalized, ensure_ascii=False) + "\n")
                norm_cnt += 1
    return norm_cnt, quar_cnt

with open(normalized_file, "w", encoding="utf-8") as norm_out, open(quarantine_file, "w", encoding="utf-8") as quar_out:
    w_norm, w_quar = process_file(windows_file, "windows_json", normalize_windows, norm_out, quar_out)
    l_norm, l_quar = process_file(linux_file, "linux_text", normalize_linux, norm_out, quar_out)

tot_norm = w_norm + l_norm
tot_quar = w_quar + l_quar

print(f"windows_json     : normalized {w_norm:>8d}    quarantined {w_quar:>2d}")
print(f"linux_text       : normalized {l_norm:>8d}    quarantined {l_quar:>2d}")
print(f"total            : normalized {tot_norm:>8d}    quarantined {tot_quar:>2d}")
print("normalized_events.json written")
print("quarantine.json  written")

PYTHON_EOF
