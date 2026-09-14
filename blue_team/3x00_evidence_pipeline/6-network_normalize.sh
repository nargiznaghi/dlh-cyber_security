#!/bin/bash
#
# 6-network_normalize.sh - Task 6: Network Artifact Normalization
#

set -euo pipefail

EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
NETWORK_DIR="$EVIDENCE_PACK/network"
SCHEMA_FILE="${SCHEMA_FILE:-$(pwd)/event_schema.json}"
NORMALIZED_FILE="${NORMALIZED_FILE:-$(pwd)/normalized_events.json}"
OUTPUT_NETWORK="${OUTPUT_NETWORK:-$(pwd)/network_events.json}"

if [ ! -d "$NETWORK_DIR" ]; then
    echo "Error: Network directory not found at $NETWORK_DIR" >&2
    exit 1
fi

python3 - "$NETWORK_DIR" "$SCHEMA_FILE" "$NORMALIZED_FILE" "$OUTPUT_NETWORK" <<'PYTHON'
import os
import sys
import csv
import json
from datetime import datetime, timezone

network_dir = sys.argv[1]
schema_file = sys.argv[2]
normalized_file = sys.argv[3]
output_network = sys.argv[4]

with open(schema_file, "r", encoding="utf-8") as f:
    schema = json.load(f)

field_names = [field["name"] for field in schema.get("fields", [])]

def build_schema_record(values):
    record = {name: None for name in field_names}
    for k, v in values.items():
        if k in record:
            record[k] = v
    return record

def parse_iso8601(ts_str):
    if not ts_str:
        return None
    try:
        ts_str = str(ts_str).strip()
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None

def parse_epoch(ts_val):
    try:
        dt = datetime.fromtimestamp(float(ts_val), timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None

def parse_ampm(ts_str):
    if not ts_str:
        return None
    try:
        dt = datetime.strptime(ts_str.strip(), "%m/%d/%Y %I:%M:%S %p")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None

network_records = []

# 1. Parse Firewall CSV
fw_file = os.path.join(network_dir, "firewall.csv")
fw_count = 0
if os.path.exists(fw_file):
    with open(fw_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = parse_epoch(row.get("timestamp"))
            action = row.get("action", "").upper()
            
            rec_val = {
                "timestamp": ts,
                "hostname": row.get("interface") or "firewall",
                "source_type": "firewall",
                "source_origin": "evidence_pack",
                "event_category": "network",
                "event_id": row.get("rule_id"),
                "severity": "informational",
                "user": None,
                "process_name": None,
                "process_id": None,
                "src_ip": row.get("src_ip"),
                "src_port": int(row["src_port"]) if row.get("src_port") and row["src_port"].isdigit() else None,
                "dst_ip": row.get("dst_ip"),
                "dst_port": int(row["dst_port"]) if row.get("dst_port") and row["dst_port"].isdigit() else None,
                "protocol": row.get("protocol"),
                "action": action,
                "raw_message": json.dumps(row, ensure_ascii=False)
            }
            network_records.append(build_schema_record(rec_val))
            fw_count += 1

# 2. Parse Suricata EVE JSON
suricata_file = os.path.join(network_dir, "suricata_eve.json")
suricata_count = 0
if os.path.exists(suricata_file):
    with open(suricata_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                ts = parse_iso8601(data.get("timestamp"))
                alert = data.get("alert") or {}
                
                sev = "medium"
                if alert.get("severity") == 1:
                    sev = "high"
                elif alert.get("severity") == 2:
                    sev = "medium"
                elif alert.get("severity") == 3:
                    sev = "low"

                rec_val = {
                    "timestamp": ts,
                    "hostname": data.get("host") or "suricata",
                    "source_type": "suricata",
                    "source_origin": "evidence_pack",
                    "event_category": "network_alert",
                    "event_id": str(alert.get("signature_id")) if alert.get("signature_id") else None,
                    "severity": sev,
                    "user": None,
                    "process_name": None,
                    "process_id": None,
                    "src_ip": data.get("src_ip"),
                    "src_port": data.get("src_port"),
                    "dst_ip": data.get("dest_ip") or data.get("dst_ip"),
                    "dst_port": data.get("dest_port") or data.get("dst_port"),
                    "protocol": data.get("proto"),
                    "signature": alert.get("signature"),
                    "raw_message": line
                }
                network_records.append(build_schema_record(rec_val))
                suricata_count += 1
            except json.JSONDecodeError:
                continue

# 3. Parse PCAP Summary JSON
pcap_file = os.path.join(network_dir, "pcap_summary.json")
pcap_count = 0
if os.path.exists(pcap_file):
    with open(pcap_file, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                ts = parse_ampm(data.get("start_time"))
                
                rec_val = {
                    "timestamp": ts,
                    "hostname": data.get("hostname") or "pcap_sensor",
                    "source_type": "pcap_summary",
                    "source_origin": "evidence_pack",
                    "event_category": "network_flow",
                    "event_id": None,
                    "severity": "informational",
                    "user": None,
                    "process_name": None,
                    "process_id": None,
                    "src_ip": data.get("src_ip"),
                    "src_port": data.get("src_port"),
                    "dst_ip": data.get("dst_ip"),
                    "dst_port": data.get("dst_port"),
                    "protocol": data.get("protocol") or data.get("proto"),
                    "raw_message": line
                }
                network_records.append(build_schema_record(rec_val))
                pcap_count += 1
            except json.JSONDecodeError:
                continue

# Print per-file record counts
print(f"firewall.csv        : {fw_count:>6d} records normalized")
print(f"suricata_eve.json   : {suricata_count:>6d} records normalized")
print(f"pcap_summary.json   : {pcap_count:>6d} records normalized")

# Write standalone network_events.json
with open(output_network, "w", encoding="utf-8") as out_net:
    for rec in network_records:
        out_net.write(json.dumps(rec, ensure_ascii=False) + "\n")

# Append to normalized_events.json
with open(normalized_file, "a", encoding="utf-8") as out_norm:
    for rec in network_records:
        out_norm.write(json.dumps(rec, ensure_ascii=False) + "\n")

print("appended to normalized_events.json")
print("network_events.json written")

PYTHON
