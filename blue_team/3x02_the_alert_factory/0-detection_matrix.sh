#!/bin/bash
#
# 0-detection_matrix.sh - Task 0: Detection Type Analysis for 3x02
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/detection_matrix.json}"

ENRICHED_EVENTS="$HANDOFF_DIR/data/enriched_events.json"
EVENT_SCHEMA="$HANDOFF_DIR/schema/event_schema.json"
BASELINE_SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"

for f in "$ENRICHED_EVENTS" "$BASELINE_SUMMARY"; do
    if [ ! -f "$f" ]; then
        echo "Error: Required input file missing at $f" >&2
        exit 1
    fi
done

python3 - "$ENRICHED_EVENTS" "$BASELINE_SUMMARY" "$OUTPUT_FILE" <<'PYTHON_EOF'
import sys
import json
import os
from collections import defaultdict

enriched_file = sys.argv[1]
baseline_file = sys.argv[2]
output_file = sys.argv[3]

with open(enriched_file, "r", encoding="utf-8") as f:
    events = json.load(f)

with open(baseline_file, "r", encoding="utf-8") as f:
    baseline_summary = json.load(f)

# Qruplaşdırma: source_type üzrə
source_events = defaultdict(list)
for ev in events:
    stype = ev.get("source_type", "unknown")
    source_events[stype].append(ev)

# ATT&CK Tactic xəritələnməsi mənbə növləri üçün
TACTIC_MAP = {
    "windows_json": ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0008"],
    "linux_text": ["TA0001", "TA0002", "TA0003", "TA0004", "TA0006", "TA0008"],
    "suricata_alert": ["TA0011", "TA0010"],
    "firewall": ["TA0011", "TA0010"],
    "pcap_flow": ["TA0011", "TA0010"]
}

DETECTION_TYPES_MAP = {
    "windows_json": ["signature", "anomaly", "behavioral", "correlation"],
    "linux_text": ["signature", "anomaly", "behavioral", "correlation"],
    "suricata_alert": ["signature", "correlation"],
    "firewall": ["anomaly", "correlation"],
    "pcap_flow": ["anomaly", "behavioral"]
}

RATIONALE_MAP = {
    "windows_json": "Rich event IDs, process trees, and auth logs enable signature, behavioral, anomaly, and correlation analytics.",
    "linux_text": "Auditd and auth syslog streams provide detailed execution and auth metrics for full spectrum detection.",
    "suricata_alert": "Pre-matched signatures and alert triggers suitable for direct signature filtering and correlation.",
    "firewall": "Network connection metadata ideal for volume/destination anomaly detection and correlation.",
    "pcap_flow": "Flow metrics permit behavioral pattern tracking and traffic volume anomaly detection."
}

matrix_results = []

for stype, ev_list in source_events.items():
    total_count = len(ev_list)
    field_presence = defaultdict(int)
    field_values = defaultdict(set)

    for ev in ev_list:
        for k, v in ev.items():
            field_presence[k] += 1
            if v is not None and not isinstance(v, (dict, list)):
                field_values[k].add(str(v))

    stable_fields = [
        k for k, count in field_presence.items() 
        if (count / total_count) >= 0.95 and not k.startswith("_")
    ]
    stable_fields.sort()

    high_card_fields = [
        k for k, val_set in field_values.items()
        if (len(val_set) > 0.5 * total_count) and not k.startswith("_")
    ]
    high_card_fields.sort()

    supp_types = DETECTION_TYPES_MAP.get(stype, ["signature", "anomaly"])
    tactics = TACTIC_MAP.get(stype, ["TA0001", "TA0002"])
    rationale = RATIONALE_MAP.get(stype, "Sufficient structured attributes available for analytical processing.")

    entry = {
        "source_type": stype,
        "record_count": total_count,
        "stable_fields": stable_fields,
        "high_cardinality_fields": high_card_fields,
        "supported_detection_types": supp_types,
        "rationale": rationale,
        "recommended_attack_tactics": tactics
    }
    matrix_results.append(entry)

# Çıxış strukturunun saxlanması
with open(output_file, "w", encoding="utf-8") as f:
    json.dump({"sources": matrix_results}, f, indent=2, ensure_ascii=False)

# Konsol çıxışı
for item in matrix_results:
    stype = item["source_type"]
    dtypes = item["supported_detection_types"]
    num_types = len(dtypes)
    dtypes_str = " ".join(dtypes)
    print(f"{stype:<16} {num_types} types  [{dtypes_str}]")

print(f"{len(matrix_results)} source types analyzed")
print(f"{os.path.basename(output_file)} written")

PYTHON_EOF
