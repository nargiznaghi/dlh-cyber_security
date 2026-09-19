#!/bin/bash

set -euo pipefail

# --------------------------------------------------
# Helper
# --------------------------------------------------

fail() {
    echo "[resp] ERROR: $1" >&2
    exit 1
}

# --------------------------------------------------
# Required environment variables
# --------------------------------------------------

for var in SHIFT_WORKSPACE ASSETS_DIR
do
    if [[ -z "${!var:-}" ]]; then
        fail "$var is not set"
    fi
done

CAMPAIGN="$SHIFT_WORKSPACE/campaign/campaign_assessment.json"
INCIDENTS="$SHIFT_WORKSPACE/alerts/incidents.json"
IOC_FEED="$ASSETS_DIR/ioc_feed.json"
ASSETS="$ASSETS_DIR/assets.json"

CONTAINMENT="$SHIFT_WORKSPACE/response/containment.json"
IOC_PACKAGE="$SHIFT_WORKSPACE/response/ioc_package.json"

# --------------------------------------------------
# Find enriched events
# --------------------------------------------------

if [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.jsonl" ]]; then
    EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.jsonl"
elif [[ -s "$SHIFT_WORKSPACE/enriched/enriched_events.json" ]]; then
    EVENTS="$SHIFT_WORKSPACE/enriched/enriched_events.json"
else
    fail "enriched events file is missing"
fi

# --------------------------------------------------
# Check required base files
# --------------------------------------------------

for file in "$CAMPAIGN" "$INCIDENTS" "$IOC_FEED"
do
    if [[ ! -s "$file" ]]; then
        fail "missing or empty file: $file"
    fi
done

mkdir -p "$SHIFT_WORKSPACE/response"

echo "[resp] loading campaign_assessment and incidents"

# --------------------------------------------------
# Build containment + IOC package
# --------------------------------------------------

python3 - \
    "$CAMPAIGN" \
    "$INCIDENTS" \
    "$IOC_FEED" \
    "$ASSETS" \
    "$EVENTS" \
    "$SHIFT_WORKSPACE/investigations" \
    "$CONTAINMENT" \
    "$IOC_PACKAGE" <<'PY'

import json
import re
import sys
import os
import glob
from datetime import datetime, timezone

campaign_path = sys.argv[1]
incidents_path = sys.argv[2]
feed_path = sys.argv[3]
assets_path = sys.argv[4]
events_path = sys.argv[5]
investigations_dir = sys.argv[6]
containment_path = sys.argv[7]
package_path = sys.argv[8]

def load_json(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def clean(value):
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def event_id(event):
    return clean(
        event.get("event_ref")
        or event.get("event_id")
        or event.get("id")
        or event.get("event_uid")
        or (event.get("event", {}).get("id") if isinstance(event.get("event"), dict) else "")
    )

def event_time(event):
    return clean(
        event.get("timestamp")
        or event.get("@timestamp")
        or event.get("event_time")
        or event.get("time")
    )

def add_candidate(result, ioc_type, value):
    value = clean(value)
    if not value:
        return
    result.add((ioc_type, value))

def extract_candidates(event):
    result = set()

    add_candidate(result, "ip", event.get("src_ip"))
    add_candidate(result, "ip", event.get("dst_ip"))

    for key in ("source", "destination", "src", "dst"):
        obj = event.get(key)
        if isinstance(obj, dict):
            add_candidate(result, "ip", obj.get("ip"))

    for value in (event.get("domain"), event.get("dns_name"), event.get("destination_domain")):
        add_candidate(result, "domain", value)

    dns = event.get("dns")
    if isinstance(dns, dict):
        question = dns.get("question")
        if isinstance(question, dict):
            add_candidate(result, "domain", question.get("name"))

    destination = event.get("destination")
    if isinstance(destination, dict):
        add_candidate(result, "domain", destination.get("domain"))

    for value in (event.get("username"), event.get("account")):
        add_candidate(result, "account", value)

    user = event.get("user")
    if isinstance(user, str):
        add_candidate(result, "account", user)
    elif isinstance(user, dict):
        add_candidate(result, "account", user.get("name"))

    add_candidate(result, "service_name", event.get("service_name"))
    service = event.get("service")
    if isinstance(service, dict):
        add_candidate(result, "service_name", service.get("name"))

    winlog = event.get("winlog")
    if isinstance(winlog, dict):
        event_data = winlog.get("event_data")
        if isinstance(event_data, dict):
            add_candidate(result, "service_name", event_data.get("ServiceName"))

    for key in ("hash", "sha256", "md5", "sha1"):
        add_candidate(result, "hash", event.get(key))

    file_obj = event.get("file")
    if isinstance(file_obj, dict):
        hash_obj = file_obj.get("hash")
        if isinstance(hash_obj, dict):
            for value in hash_obj.values():
                add_candidate(result, "hash", value)

    for value in (event.get("dst_port"), event.get("destination_port")):
        if value is not None:
            add_candidate(result, "port", str(value))

    if isinstance(destination, dict) and destination.get("port") is not None:
        add_candidate(result, "port", str(destination.get("port")))

    return result

def defang(ioc_type, value):
    value = clean(value)
    if ioc_type in ("ip", "domain"):
        value = value.replace("http://", "http[://]").replace("https://", "https[://]")
        value = value.replace(".", "[.]")
    return value

# Load base data
campaign = load_json(campaign_path)
incidents_data = load_json(incidents_path)
feed_data = load_json(feed_path)

valid_incident_ids = set()
incidents_list = incidents_data.get("incidents", [])
for inc in incidents_list:
    iid = clean(inc.get("incident_id"))
    if iid:
        valid_incident_ids.add(iid)

shift_id = clean(incidents_data.get("shift_id")) or "unknown"

# Dynamic investigation finding files loading
findings = []
for fpath in glob.glob(os.path.join(investigations_dir, "*.json")):
    fdata = load_json(fpath)
    if fdata:
        findings.append(fdata)

# Read enriched events
events = []
if events_path.endswith(".jsonl"):
    with open(events_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
else:
    data = load_json(events_path)
    events = data if isinstance(data, list) else [data]

events_by_id = {event_id(e): e for e in events if event_id(e)}

feed_lookup = {}
for item in feed_data.get("iocs", []):
    val = clean(item.get("value") or item.get("indicator") or item.get("ioc"))
    if val:
        feed_lookup[val] = {
            "type": clean(item.get("type") or "unknown"),
            "confidence": clean(item.get("confidence") or "medium").lower()
        }

package_iocs = []
package_keys = set()
new_discovered = 0

for finding in findings:
    finding_text = json.dumps(finding, ensure_ascii=False)
    
    # Try to map finding to incident
    inc_id = clean(finding.get("incident_id"))
    if not inc_id or inc_id not in valid_incident_ids:
        # fallback match
        for v_id in valid_incident_ids:
            if v_id in finding_text:
                inc_id = v_id
                break
    if not inc_id and valid_incident_ids:
        inc_id = list(valid_incident_ids)[0]

    references = [clean(ref) for ref in finding.get("event_refs", []) if clean(ref)]

    for ref in references:
        if ref not in events_by_id:
            continue
        event = events_by_id[ref]
        candidates = extract_candidates(event)

        for ioc_type, value in candidates:
            in_feed = value in feed_lookup
            explicitly_relevant = value in finding_text

            if not (in_feed or explicitly_relevant):
                continue

            key = (inc_id, ioc_type, value)

            backing = []
            times = []
            for check_ref in references:
                event2 = events_by_id.get(check_ref)
                if event2 and (ioc_type, value) in extract_candidates(event2):
                    backing.append(check_ref)
                    ts = event_time(event2)
                    if ts:
                        times.append(ts)

            if not backing or key in package_keys:
                continue

            package_keys.add(key)
            source = "ioc_feed" if in_feed else "shift_discovered"
            if source == "shift_discovered":
                new_discovered += 1

            confidence = feed_lookup[value]["confidence"] if in_feed else clean(finding.get("confidence") or "medium").lower()
            if confidence not in ("low", "medium", "high"):
                confidence = "medium"

            package_iocs.append({
                "type": ioc_type,
                "value": defang(ioc_type, value),
                "first_seen": min(times) if times else "",
                "last_seen": max(times) if times else "",
                "incident_id": inc_id,
                "source": source,
                "confidence": confidence,
                "_event_refs": backing
            })

# Validate backing
for ioc in package_iocs:
    if not ioc["_event_refs"]:
        raise SystemExit(f"[resp] ERROR: IOC {ioc['value']} has no event backing")

# Build containment actions
actions = []
action_keys = set()

def add_action(priority, action_str, target_type, target_value, incident_id, impact, approval):
    if incident_id not in valid_incident_ids:
        raise SystemExit(f"[resp] ERROR: action references invalid incident {incident_id}")

    key = (priority, target_type, target_value, incident_id)
    if key in action_keys:
        return
    action_keys.add(key)

    actions.append({
        "priority": priority,
        "action": clean(action_str)[:160],
        "target_type": target_type,
        "target_value": target_value,
        "incident_id": incident_id,
        "operational_impact": clean(impact)[:160],
        "requires_approval_from": approval
    })

# Immediate: IP actions
for ioc in package_iocs:
    if ioc["type"] == "ip":
        add_action("immediate", f"Block confirmed malicious IP {ioc['value']} at the perimeter firewall.", "ip", ioc["value"], ioc["incident_id"], "Connections to this destination will be blocked.", "SOC Lead")

# Actions per incident
for inc in incidents_list:
    iid = clean(inc.get("incident_id"))
    for host in inc.get("host_list", []):
        host = clean(host)
        if host:
            add_action("immediate", f"Isolate {host} from the network while preserving security telemetry.", "host", host, iid, "Host network access will be interrupted during containment.", "SOC Lead")
            add_action("medium_term", f"Deploy or tighten Sysmon detection coverage on {host}.", "host", host, iid, "Additional telemetry may increase endpoint log volume.", "Security Architecture")

    for user in inc.get("user_list", []):
        user = clean(user)
        if user:
            add_action("short_term", f"Reset credentials and review active sessions for account {user}.", "user", user, iid, "User sessions may be terminated and credentials must be redistributed.", "System Owner")

for ioc in package_iocs:
    if ioc["type"] == "service_name":
        add_action("short_term", f"Audit service accounts and services matching {ioc['value']}.", "service", ioc["value"], ioc["incident_id"], "Service review may require temporary restart or credential rotation.", "System Owner")

# Sort and limit actions to 12
priority_order = {"immediate": 0, "short_term": 1, "medium_term": 2}
actions.sort(key=lambda x: (priority_order[x["priority"]], x["incident_id"], x["target_type"], x["target_value"]))
actions = actions[:12]

for idx, act in enumerate(actions, start=1):
    act["action_id"] = f"ACT-{idx:03d}"

final_actions = []
for act in actions:
    final_actions.append({
        "action_id": act["action_id"],
        "priority": act["priority"],
        "action": act["action"],
        "target_type": act["target_type"],
        "target_value": act["target_value"],
        "incident_id": act["incident_id"],
        "operational_impact": act["operational_impact"],
        "requires_approval_from": act["requires_approval_from"]
    })

containment = {
    "shift_id": shift_id,
    "generated_at": now(),
    "actions": final_actions
}

with open(containment_path, "w", encoding="utf-8") as f:
    json.dump(containment, f, indent=2)
    f.write("\n")

final_iocs = []
for ioc in package_iocs:
    final_iocs.append({
        "type": ioc["type"],
        "value": ioc["value"],
        "first_seen": ioc["first_seen"],
        "last_seen": ioc["last_seen"],
        "incident_id": ioc["incident_id"],
        "source": ioc["source"],
        "confidence": ioc["confidence"]
    })

cluster = clean(campaign.get("cluster_id"))
if not cluster:
    cluster = "unknown"

ioc_package = {
    "shift_id": shift_id,
    "tlp": "AMBER",
    "cluster_id": cluster,
    "generated_at": now(),
    "iocs": final_iocs
}

with open(package_path, "w", encoding="utf-8") as f:
    json.dump(ioc_package, f, indent=2)
    f.write("\n")

# Summary output matching expected pattern
p_counts = {"immediate": 0, "short_term": 0, "medium_term": 0}
for act in final_actions:
    p_counts[act["priority"]] += 1

t_counts = {"ip": 0, "domain": 0, "hash": 0, "account": 0, "service_name": 0}
for ioc in final_iocs:
    if ioc["type"] in t_counts:
        t_counts[ioc["type"]] += 1

print(f"[resp] actions: immediate={p_counts['immediate']} short_term={p_counts['short_term']} medium_term={p_counts['medium_term']} total={len(final_actions)}")
print(f"[resp] IOCs: ip={t_counts['ip']} domain={t_counts['domain']} hash={t_counts['hash']} account={t_counts['account']} service={t_counts['service_name']} total={len(final_iocs)}")
print(f"[resp] newly discovered (not in feed): {new_discovered}")
print("[resp] all IOCs traced to events: OK")
print("[resp] containment.json written")
print("[resp] ioc_package.json written")
PY
