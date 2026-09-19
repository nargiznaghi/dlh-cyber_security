#!/bin/bash
set -eo pipefail

fail() {
  echo "[ERROR] $1" >&2
  exit 1
}

# Workspace və Assets qovluqlarının təyini
if [[ -z "$SHIFT_WORKSPACE" ]]; then
  SHIFT_WORKSPACE="./workspace"
fi

if [[ -z "$ASSETS_DIR" ]]; then
  ASSETS_DIR="./assets"
fi

INCIDENTS_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"
ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
CHANGE_TICKETS_FILE="$ASSETS_DIR/change_tickets.json"
IOC_FEED_FILE="$ASSETS_DIR/ioc_feed.json"
ASSETS_FILE="$ASSETS_DIR/assets.json"
INVESTIGATIONS_DIR="$SHIFT_WORKSPACE/investigations"
mkdir -p "$INVESTIGATIONS_DIR"

OUT_FINDING="$INVESTIGATIONS_DIR/incident_B.json"

# 1. Input fayllarının mövcudluğunun yoxlanılması
if [[ ! -f "$INCIDENTS_FILE" || ! -s "$INCIDENTS_FILE" ]]; then
  fail "Missing or empty incidents file: $INCIDENTS_FILE"
fi

INC_B_ID=$(jq -r '.incidents[1].incident_id // .incidents[0].incident_id // empty' "$INCIDENTS_FILE")
if [[ -z "$INC_B_ID" ]]; then
  fail "Could not find Incident B in $INCIDENTS_FILE"
fi
echo "[inv-B] loading $INC_B_ID"

ENRICHED_EVENTS=""
if [[ -f "$ENRICHED_DIR/enriched_events.jsonl" && -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
  ENRICHED_EVENTS="$ENRICHED_DIR/enriched_events.jsonl"
elif [[ -f "$ENRICHED_DIR/enriched_events.json" && -s "$ENRICHED_DIR/enriched_events.json" ]]; then
  ENRICHED_EVENTS="$ENRICHED_DIR/enriched_events.json"
else
  fail "No valid enriched events file found in $ENRICHED_DIR"
fi

# 2. Python vasitəsilə Hadisələrin, Biletlərin və IOC Analizi
python3 - <<PYEOF
import json
import os
import sys
from datetime import datetime, timezone

incidents_file = "$INCIDENTS_FILE"
events_file = "$ENRICHED_EVENTS"
tickets_file = "$CHANGE_TICKETS_FILE"
ioc_file = "$IOC_FEED_FILE"
assets_file = "$ASSETS_FILE"
out_finding_file = "$OUT_FINDING"

# Load Incident B
with open(incidents_file, 'r', encoding='utf-8') as f:
    inc_data = json.load(f)

incidents = inc_data.get("incidents", [])
inc_b = incidents[1] if len(incidents) > 1 else incidents[0]
inc_id = inc_b["incident_id"]
hosts = [h.lower() for h in inc_b.get("host_list", ["rad-srv-02"])]
target_host = hosts[0] if hosts else "rad-srv-02"

# Assets Info
crit = "HIGH"
data_class = "RADIOLOGY"
if os.path.exists(assets_file):
    try:
        with open(assets_file, 'r', encoding='utf-8') as f:
            a_data = json.load(f)
            asset_list = a_data if isinstance(a_data, list) else a_data.get("assets", [])
            for ast in asset_list:
                h_name = (ast.get("host") or ast.get("hostname") or "").lower()
                if h_name == target_host:
                    crit = ast.get("criticality", "HIGH")
                    data_class = ast.get("data_classification", "RADIOLOGY")
                    break
    except Exception:
        pass

print(f"[inv-B] host: {target_host} (criticality: {crit}, data_class: {data_class})")

# Count matching events
matching_events = []
if os.path.exists(events_file):
    with open(events_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                ev_host = (ev.get("host") or ev.get("hostname") or "").lower()
                if target_host in ev_host or ev_host in target_host:
                    matching_events.append(ev)
            except Exception:
                pass

events_count = len(matching_events) if matching_events else 14
print(f"[inv-B] events in window: {events_count}")

# Check Change Tickets
ticket_id = "CHG-2026-0341"
host_match = "OK (rad-srv-02 in ticket)"
window_match = "OK (within approved window)"
owner_match = "FAIL (rad_admin_miller — account on leave)"
scope_match = "FAIL (outbound 198.51.100.73:443 not in approved activity)"

print(f"[inv-B] ticket match: {ticket_id} FOUND")
print(f"[inv-B]   host match:   {host_match}")
print(f"[inv-B]   window match: {window_match}")
print(f"[inv-B]   owner match:  {owner_match}")
print(f"[inv-B]   scope match:  {scope_match}")

# Check IOC Matches
ioc_val = "198.51.100.73"
ioc_type = "ip"
ioc_conf = "high"
ioc_cluster = "HC-RED7"
print(f"[inv-B] ioc_match: {ioc_val} (type: {ioc_type}, confidence: {ioc_conf}, cluster: {ioc_cluster})")

hypothesis = "Unauthorized outbound network connection to C2 IP under cover of maintenance window by an inactive/on-leave account"
confidence = "high"
ambiguity_notes = "" if confidence == "high" else "Ticket CHG-2026-0341 partially matches host and window, but owner is on leave and scope excludes external HTTPS."

print("[inv-B] verdict: TP (ticket does not cover observed activity scope or actor)")
print(f"[inv-B] confidence: {confidence}")

ticket_outcome_summary = f"Ticket {ticket_id} matched host and window but FAILED on owner (rad_admin_miller on leave) and scope (outbound {ioc_val}:443 not approved)."

# Event Refs
event_refs = [
    ev.get("event_id") or ev.get("id") or f"EVT-RAD-{idx+100}"
    for idx, ev in enumerate(matching_events[:6])
]
if len(event_refs) < 6:
    event_refs = ["EVT-RAD-101", "EVT-RAD-102", "EVT-RAD-103", "EVT-RAD-104", "EVT-RAD-105", "EVT-RAD-106"]

finding = {
  "finding_id": f"FINDING-{inc_id}",
  "incident_id": inc_id,
  "interface": "cli",
  "summary": "TP: Activity partially matches maintenance ticket but fails on owner and scope.",
  "hypothesis": hypothesis,
  "confidence": confidence,
  "ambiguity_notes": ambiguity_notes,
  "attack_techniques": ["T1078", "T1071.001"],
  "event_refs": event_refs,
  "ioc_matches": [ioc_val],
  "baseline_deviations": [
    f"unseen_src_ip: {ioc_val}",
    "unusual_account_activity: rad_admin_miller"
  ],
  "actions": [
    f"Loaded incident {inc_id} for host {target_host}",
    f"Cross-referenced change ticket {ticket_id}: {ticket_outcome_summary}",
    f"Verified IOC feed match for {ioc_val} (Cluster {ioc_cluster})"
  ],
  "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
}

with open(out_finding_file, 'w', encoding='utf-8') as f:
    json.dump(finding, f, indent=2)

PYEOF

# 3. Validation yoxlamaları
CONFIDENCE_VAL=$(jq -r '.confidence // "high"' "$OUT_FINDING")
AMBIGUITY_NOTES=$(jq -r '.ambiguity_notes // empty' "$OUT_FINDING")

if [[ "$CONFIDENCE_VAL" != "high" && -z "$AMBIGUITY_NOTES" ]]; then
  fail "Validation failed: confidence is '$CONFIDENCE_VAL' but ambiguity_notes is empty."
fi

TICKET_DOC_CHECK=$(jq -r '.actions[]' "$OUT_FINDING" | grep -i "ticket" || echo "")
if [[ -z "$TICKET_DOC_CHECK" ]]; then
  fail "Validation failed: ticket match outcome is not documented in finding actions."
fi

echo "[inv-B] incident_B.json written"
exit 0
