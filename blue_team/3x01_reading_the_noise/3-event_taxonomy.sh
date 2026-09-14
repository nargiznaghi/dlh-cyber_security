#!/bin/bash
#
# 3-event_taxonomy.sh - Task 3: Event Type Taxonomy for 3x01
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ENRICHED_EVENTS="$HANDOFF_DIR/data/enriched_events.json"

TAXONOMY_FILE="${TAXONOMY_FILE:-$(pwd)/event_taxonomy.json}"
LABELED_FILE="${LABELED_FILE:-$(pwd)/labeled_events.json}"

if [ ! -f "$ENRICHED_EVENTS" ]; then
    echo "Error: Dataset not found at $ENRICHED_EVENTS" >&2
    exit 1
fi

python3 - "$ENRICHED_EVENTS" "$TAXONOMY_FILE" "$LABELED_FILE" <<'PYTHON_EOF'
import sys
import json
from collections import Counter

enriched_file = sys.argv[1]
taxonomy_file = sys.argv[2]
labeled_file = sys.argv[3]

# Kanonik Taksonomiya Qaydaları (Rule definitions)
rules = [
    # Authentication & Accounts
    {
        "label": "login_success",
        "source_type": "windows_json",
        "match": {"event_id": "4624"}
    },
    {
        "label": "login_failure",
        "source_type": "windows_json",
        "match": {"event_id": "4625"}
    },
    {
        "label": "logout",
        "source_type": "windows_json",
        "match": {"event_id": "4634"}
    },
    {
        "label": "account_lockout",
        "source_type": "windows_json",
        "match": {"event_id": "4740"}
    },
    {
        "label": "privilege_escalation",
        "source_type": "windows_json",
        "match": {"event_id": "4672"}
    },
    {
        "label": "login_success",
        "source_type": "linux_text",
        "match": {"event_category": "authentication"}
    },

    # Process Management
    {
        "label": "process_start",
        "source_type": "windows_json",
        "match": {"event_id": "4688"}
    },
    {
        "label": "process_start",
        "source_type": "windows_json",
        "match": {"event_id": "1"}
    },
    {
        "label": "process_stop",
        "source_type": "windows_json",
        "match": {"event_id": "5"}
    },
    {
        "label": "child_process_spawn",
        "source_type": "windows_json",
        "match": {"event_category": "process"}
    },

    # File System Access
    {
        "label": "file_read_sensitive",
        "source_type": "windows_json",
        "match": {"event_id": "4663"}
    },
    {
        "label": "file_write_sensitive",
        "source_type": "windows_json",
        "match": {"event_id": "11"}
    },
    {
        "label": "file_permission_change",
        "source_type": "windows_json",
        "match": {"event_id": "4670"}
    },

    # Network Telemetry
    {
        "label": "network_blocked",
        "source_type": "firewall",
        "match": {"action": "BLOCK"}
    },
    {
        "label": "network_connection_outbound",
        "source_type": "firewall",
        "match": {"action": "ALLOW"}
    },
    {
        "label": "network_alert",
        "source_type": "suricata",
        "match": {"event_category": "network_alert"}
    },
    {
        "label": "network_connection_inbound",
        "source_type": "pcap_summary",
        "match": {"event_category": "network_flow"}
    }
]

# 1. Taksonomiya qaydalarını event_taxonomy.json faylına yaz
taxonomy_data = {
    "taxonomy_name": "MedDefense Event Type Taxonomy",
    "version": "1.0",
    "total_rules": len(rules),
    "rules": rules
}

with open(taxonomy_file, "w", encoding="utf-8") as f:
    json.dump(taxonomy_data, f, indent=2, ensure_ascii=False)

def classify_event(record):
    source = record.get("source_type")
    
    # Qaydalar üzrə match yoxlanışı
    for rule in rules:
        if rule["source_type"] == source:
            matched = True
            for field, expected_val in rule["match"].items():
                rec_val = record.get(field)
                if rec_val is None or str(rec_val).lower() != str(expected_val).lower():
                    matched = False
                    break
            if matched:
                return rule["label"]

    # Fallback / General Heuristics
    category = record.get("event_category")
    if category == "authentication":
        return "login_success"
    elif category == "process":
        return "process_start"
    elif category == "network_alert":
        return "network_alert"
    elif category == "network":
        if record.get("action") == "BLOCK":
            return "network_blocked"
        return "network_connection_outbound"
    elif category == "network_flow":
        return "network_connection_inbound"
        
    return "unlabeled"

labeled_count = 0
unlabeled_count = 0
label_dist = Counter()

with open(enriched_file, "r", encoding="utf-8", errors="replace") as in_f, \
     open(labeled_file, "w", encoding="utf-8") as out_f:
    
    for line in in_f:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
            label = classify_event(rec)
            rec["canonical_label"] = label
            
            if label != "unlabeled":
                labeled_count += 1
            else:
                unlabeled_count += 1
                
            label_dist[label] += 1
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except json.JSONDecodeError:
            continue

print(f"taxonomy rules         : {len(rules)}")
print(f"records labeled        : {labeled_count}")
print(f"records unlabeled      : {unlabeled_count}")
print("canonical label distribution (top 10):")
for label, count in label_dist.most_common(10):
    print(f"  {label:<25} {count}")

print("event_taxonomy.json written")
print("labeled_events.json written")

PYTHON_EOF
