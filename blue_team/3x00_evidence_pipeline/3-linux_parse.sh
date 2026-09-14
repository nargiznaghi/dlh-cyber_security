#!/bin/bash
#
# 3-linux_parse.sh - Task 3: Linux Log Parsing
#

set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
LINUX_DIR="$EVIDENCE_PACK/linux"
STUDENT_FILE="$EVIDENCE_PACK/student_telemetry/linux_events.json"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/linux_events.json}"

python3 - "$LINUX_DIR" "$STUDENT_FILE" "$OUTPUT_FILE" <<'PYTHON'
import json
import os
import re
import sys

linux_dir = sys.argv[1]
student_file = sys.argv[2]
output_file = sys.argv[3]

SYSLOG_RE = re.compile(
    r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+'
    r'([^\s:\[]+)'
    r'(?:\[(\d+)\])?:\s*(.*)$'
)

def extract_key_values(text):
    fields = {}
    for match in re.finditer(r'([A-Za-z0-9_.-]+)=("[^"]*"|\S+)', text):
        key = match.group(1)
        val = match.group(2).strip('"')
        fields[key] = val
    return fields

def extract_user(message):
    patterns = [
        r'for invalid user\s+([A-Za-z0-9_.-]+)',
        r'for user\s+([A-Za-z0-9_.-]+)',
        r'for\s+([A-Za-z0-9_.-]+)',
        r'user[ =]([A-Za-z0-9_.-]+)'
    ]
    for pattern in patterns:
        m = re.search(pattern, message, re.IGNORECASE)
        if m:
            return m.group(1)
    return None

def parse_syslog_file(filepath, out_f):
    lines_count = 0
    records_count = 0
    if not os.path.exists(filepath):
        return lines_count, records_count

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            lines_count += 1
            line = raw_line.rstrip("\n")
            if not line:
                continue

            match = SYSLOG_RE.match(line)
            if match:
                timestamp, hostname, program, pid, message = match.groups()
                rec = {
                    "timestamp_raw": timestamp,
                    "hostname": hostname,
                    "program": program,
                    "pid": int(pid) if pid else None,
                    "user": extract_user(message),
                    "raw_message": line,
                    "parsed_fields": extract_key_values(message),
                    "source_origin": "evidence_pack"
                }
            else:
                rec = {
                    "timestamp_raw": None,
                    "hostname": None,
                    "program": None,
                    "pid": None,
                    "user": None,
                    "raw_message": line,
                    "parsed_fields": extract_key_values(line),
                    "source_origin": "evidence_pack"
                }
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            records_count += 1

    return lines_count, records_count

def parse_audit_file(filepath, out_f):
    lines_count = 0
    if not os.path.exists(filepath):
        return lines_count, 0

    groups = {}
    group_order = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            lines_count += 1
            line = raw_line.rstrip("\n")
            if not line:
                continue

            audit_match = re.search(r'msg=audit\(([\d.]+):(\d+)\)', line)
            if audit_match:
                ts = audit_match.group(1)
                event_id = audit_match.group(2)
                group_key = f"{ts}:{event_id}"
            else:
                group_key = f"line_{lines_count}"
                ts = None

            if group_key not in groups:
                groups[group_key] = {
                    "timestamp_raw": ts,
                    "lines": [],
                    "fields": {}
                }
                group_order.append(group_key)

            groups[group_key]["lines"].append(line)
            kv = extract_key_values(line)
            groups[group_key]["fields"].update(kv)

    records_count = len(group_order)
    for g_key in group_order:
        g_data = groups[g_key]
        fields = g_data["fields"]

        audit_type_match = re.search(r'\btype=([A-Za-z0-9_]+)', g_data["lines"][0])
        audit_type = audit_type_match.group(1) if audit_type_match else None

        pid = fields.get("pid")
        if pid is not None:
            try:
                pid = int(pid)
            except ValueError:
                pass

        user = fields.get("acct") or fields.get("user") or fields.get("auid") or fields.get("uid")

        rec = {
            "timestamp_raw": g_data["timestamp_raw"],
            "hostname": fields.get("node"),
            "audit_type": audit_type,
            "pid": pid,
            "user": user,
            "raw_message": "\n".join(g_data["lines"]),
            "parsed_fields": fields,
            "source_origin": "evidence_pack"
        }
        out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    return lines_count, records_count

def append_student_telemetry(filepath, out_f):
    if not os.path.exists(filepath):
        return 0
    
    records = []
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read().strip()
        try:
            data = json.loads(content)
            if isinstance(data, list):
                records = [x for x in data if isinstance(x, dict)]
            elif isinstance(data, dict):
                records = [data]
        except json.JSONDecodeError:
            for line in content.splitlines():
                if line.strip():
                    try:
                        r = json.loads(line)
                        if isinstance(r, dict):
                            records.append(r)
                    except json.JSONDecodeError:
                        pass

    for record in records:
        record["source_origin"] = "student_telemetry"
        if "timestamp_raw" not in record:
            record["timestamp_raw"] = record.get("timestamp")
        if "hostname" not in record:
            record["hostname"] = None
        if "program" not in record and "audit_type" not in record:
            record["program"] = record.get("source_type")
        if "pid" not in record:
            record["pid"] = None
        if "user" not in record:
            record["user"] = None
        if "raw_message" not in record:
            record["raw_message"] = json.dumps(record, ensure_ascii=False)
        if "parsed_fields" not in record:
            record["parsed_fields"] = {}

        out_f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return len(records)

auth_file = os.path.join(linux_dir, "auth.log")
audit_file = os.path.join(linux_dir, "audit.log")
syslog_file = os.path.join(linux_dir, "syslog")

with open(output_file, "w", encoding="utf-8") as out_f:
    auth_lines, auth_recs = parse_syslog_file(auth_file, out_f)
    audit_lines, audit_recs = parse_audit_file(audit_file, out_f)
    syslog_lines, syslog_recs = parse_syslog_file(syslog_file, out_f)
    student_recs = append_student_telemetry(student_file, out_f)

print(f"parsing auth.log      ... {auth_lines:>5} lines  -> {auth_recs:>5} records")
print(f"parsing audit.log     ... {audit_lines:>5} lines  -> {audit_recs:>5} records (grouped)")
print(f"parsing syslog        ... {syslog_lines:>5} lines  -> {syslog_recs:>5} records")
print(f"appending student telemetry ... {student_recs:>4} records")
print("linux_events.json: written")

PYTHON
