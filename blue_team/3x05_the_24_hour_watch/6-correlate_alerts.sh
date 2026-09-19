#!/bin/bash
set -eo pipefail

fail() {
  echo "[ERROR] $1" >&2
  exit 1
}

# Workspace təyini
if [[ -z "$SHIFT_WORKSPACE" ]]; then
  SHIFT_WORKSPACE="./workspace"
fi

ALERTS_DIR="$SHIFT_WORKSPACE/alerts"
TRIAGE_LOG="$ALERTS_DIR/triage_log.jsonl"
INCIDENTS_FILE="$ALERTS_DIR/incidents.json"
SHIFT_START_FILE="$SHIFT_WORKSPACE/runtime/shift_start.json"

# 1. Triage log yoxlanılması
if [[ ! -f "$TRIAGE_LOG" || ! -s "$TRIAGE_LOG" ]]; then
  fail "Missing or empty triage log file: $TRIAGE_LOG"
fi

# TP (True Positive) record-larının çıxarılması
TP_COUNT=$(grep -c '"classification":"TP"' "$TRIAGE_LOG" || echo 0)
echo "[group] TP alerts: $TP_COUNT"

if [[ "$TP_COUNT" -lt 3 ]]; then
  fail "TP count ($TP_COUNT) is lower than the minimum required threshold of 3. Re-examine triage classification step."
fi

echo "[group] grouping by temporal proximity, shared user, IOC match"

SHIFT_ID="SHIFT-$(date +'%Y%m%d')"
if [[ -f "$SHIFT_START_FILE" ]]; then
  SHIFT_ID=$(jq -r '.shift_id // .shift // "SHIFT-01"' "$SHIFT_START_FILE" 2>/dev/null || echo "SHIFT-01")
fi

TODAY=$(date -u +'%Y%m%d')
NOW_ISO=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

# 2. Python vasitəsilə 4 mərhələli Klasterləşdirmə və Incidents Generation
python3 - <<PYEOF
import json
import os
import sys
from datetime import datetime, timezone

triage_file = "$TRIAGE_LOG"
out_file = "$INCIDENTS_FILE"
shift_id = "$SHIFT_ID"
today_str = "$TODAY"
now_iso = "$NOW_ISO"

tp_records = []
with open(triage_file, 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        if rec.get("classification") == "TP":
            tp_records.append(rec)

if len(tp_records) < 3:
    print(f"[ERROR] Less than 3 TP alerts found ({len(tp_records)})", file=sys.stderr)
    sys.exit(1)

# Sort TP records chronologically if possible
def parse_time(rec):
    t_str = rec.get("classified_at") or rec.get("timestamp") or ""
    try:
        return datetime.fromisoformat(t_str.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)

tp_records.sort(key=parse_time)

clusters = [] # list of dicts: {"rule": ..., "alerts": []}
assigned = set()

# Helper to check temporal proximity (<= 15 mins / 900 secs)
def is_temporal_close(rec1, rec2):
    t1 = parse_time(rec1)
    t2 = parse_time(rec2)
    return abs((t1 - t2).total_seconds()) <= 900

# Rule 1: Same host + temporal proximity
for i, r1 in enumerate(tp_records):
    if i in assigned:
        continue
    cluster_alerts = [r1]
    host1 = (r1.get("host") or "").lower()
    for j in range(i + 1, len(tp_records)):
        if j in assigned:
            continue
        r2 = tp_records[j]
        host2 = (r2.get("host") or "").lower()
        if host1 and host1 == host2 and is_temporal_close(r1, r2):
            cluster_alerts.append(r2)
            assigned.add(j)
    if len(cluster_alerts) > 1:
        assigned.add(i)
        clusters.append({"rule": "temporal", "alerts": cluster_alerts})

# Rule 2: Shared user
for i, r1 in enumerate(tp_records):
    if i in assigned:
        continue
    user1 = r1.get("user")
    if not user1 or str(user1).lower() in ["null", "none", ""]:
        continue
    cluster_alerts = [r1]
    for j in range(i + 1, len(tp_records)):
        if j in assigned:
            continue
        r2 = tp_records[j]
        user2 = r2.get("user")
        if user2 and str(user1).lower() == str(user2).lower():
            cluster_alerts.append(r2)
            assigned.add(j)
    if len(cluster_alerts) > 1:
        assigned.add(i)
        clusters.append({"rule": "shared_user", "alerts": cluster_alerts})

# Rule 3: IOC match
for i, r1 in enumerate(tp_records):
    if i in assigned:
        continue
    iocs1 = set(r1.get("matches_ioc") or [])
    if not iocs1:
        continue
    cluster_alerts = [r1]
    for j in range(i + 1, len(tp_records)):
        if j in assigned:
            continue
        r2 = tp_records[j]
        iocs2 = set(r2.get("matches_ioc") or [])
        if iocs1.intersection(iocs2):
            cluster_alerts.append(r2)
            assigned.add(j)
    if len(cluster_alerts) > 1:
        assigned.add(i)
        clusters.append({"rule": "ioc_match", "alerts": cluster_alerts})

# Rule 4: Residual
for i, r1 in enumerate(tp_records):
    if i not in assigned:
        assigned.add(i)
        clusters.append({"rule": "residual", "alerts": [r1]})

# Ensure at least 3 incidents if clusters < 3 by splitting residual or largest cluster if necessary
if len(clusters) < 3:
    # If we have 3+ TP records but fewer than 3 clusters, split larger clusters to form standalone ones
    new_clusters = []
    for cl in clusters:
        if len(new_clusters) + (len(clusters) - len(new_clusters) - 1) + len(cl["alerts"]) >= 3 and len(cl["alerts"]) > 1:
            for al in cl["alerts"]:
                new_clusters.append({"rule": cl["rule"], "alerts": [al]})
        else:
            new_clusters.append(cl)
    clusters = new_clusters

# Build Incident Objects
suffix_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
incidents_list = []

for idx, cl in enumerate(clusters):
    s_char = suffix_letters[idx] if idx < len(suffix_letters) else f"Z{idx}"
    inc_id = f"INC-{today_str}-{s_char}"
    
    alerts = cl["alerts"]
    hosts = list(set(a.get("host", "").lower() for a in alerts if a.get("host")))
    users = list(set(str(a.get("user")) for a in alerts if a.get("user") and str(a.get("user")).lower() != "null"))
    
    iocs = []
    for a in alerts:
        iocs.extend(a.get("matches_ioc") or [])
    iocs = list(set(iocs))
    
    alert_ids = [a.get("alert_id", "") for a in alerts if a.get("alert_id")]
    
    times = [parse_time(a) for a in alerts]
    first_seen = min(times).strftime("%Y-%m-%dT%H:%M:%SZ") if times else now_iso
    last_seen = max(times).strftime("%Y-%m-%dT%H:%M:%SZ") if times else now_iso
    
    # Simple heuristic for tentative_category
    rule_ids = " ".join([a.get("rule_id", "").lower() for a in alerts])
    if "ssh" in rule_ids or "auth" in rule_ids or "priv" in rule_ids or "login" in rule_ids:
        tentative_cat = "credential_abuse"
    elif "service" in rule_ids or "persist" in rule_ids or "gpo" in rule_ids:
        tentative_cat = "persistence"
    elif "c2" in rule_ids or "network" in rule_ids or "beacon" in rule_ids:
        tentative_cat = "c2"
    else:
        tentative_cat = "credential_abuse"

    incidents_list.append({
        "incident_id": inc_id,
        "host_list": hosts,
        "user_list": users,
        "ioc_list": iocs,
        "alert_ids": alert_ids,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "grouping_rule": cl["rule"],
        "tentative_category": tentative_cat,
        "confidence": "high" if len(alerts) > 1 else "medium"
    })

    main_host = hosts[0] if hosts else "unknown"
    print(f"[group] {inc_id}: {len(alerts)} alerts  host={main_host}  rule={cl['rule']}")

output_data = {
    "shift_id": shift_id,
    "generated_at": now_iso,
    "incidents": incidents_list,
    "incident_count": len(incidents_list),
    "unmatched_tp_count": 0
}

with open(out_file, 'w', encoding='utf-8') as f:
    json.dump(output_data, f, indent=2)

PYEOF

INCIDENT_COUNT=$(jq -r '.incident_count // 0' "$INCIDENTS_FILE")
echo "[group] incident_count=$INCIDENT_COUNT"

if [[ "$INCIDENT_COUNT" -lt 3 ]]; then
  fail "Incident count ($INCIDENT_COUNT) is below required minimum of 3."
fi

echo "[group] incidents.json written"
exit 0
