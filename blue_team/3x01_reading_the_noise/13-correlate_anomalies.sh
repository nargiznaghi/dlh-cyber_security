#!/bin/bash
#
# 13-correlate_anomalies.sh - Task 13: Cross-Source Anomaly Correlation for 3x01
#

set -euo pipefail

AUTH_ANOM="${AUTH_ANOM:-$(pwd)/anomalies_auth.json}"
PROC_ANOM="${PROC_ANOM:-$(pwd)/anomalies_process.json}"
NET_ANOM="${NET_ANOM:-$(pwd)/anomalies_network.json}"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/correlated_anomalies.json}"
CORR_WINDOW_SEC="${CORR_WINDOW_SEC:-300}"

for f in "$AUTH_ANOM" "$PROC_ANOM" "$NET_ANOM"; do
    if [ ! -f "$f" ]; then
        echo "Error: Required anomaly file not found at $f" >&2
        exit 1
    fi
done

python3 - "$AUTH_ANOM" "$PROC_ANOM" "$NET_ANOM" "$OUTPUT_FILE" "$CORR_WINDOW_SEC" <<'PYTHON_EOF'
import sys
import json
import hashlib
from datetime import datetime, timezone

auth_file = sys.argv[1]
proc_file = sys.argv[2]
net_file = sys.argv[3]
output_file = sys.argv[4]
corr_window_sec = int(sys.argv[5])

def load_anomalies(path, source_name):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    items = data.get("anomalies", [])
    result = []
    for item in items:
        ts_str = item.get("timestamp")
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        item_copy = dict(item)
        item_copy["_source"] = source_name
        item_copy["_dt"] = dt
        result.append(item_copy)
    return result

auth_items = load_anomalies(auth_file, "auth")
proc_items = load_anomalies(proc_file, "process")
net_items = load_anomalies(net_file, "network")

all_anomalies = auth_items + proc_items + net_items
total_single_source = len(all_anomalies)

# Host üzrə anomaliyaları qruplaşdırırıq
host_groups = {}
for item in all_anomalies:
    host = item.get("host", "unknown")
    if host not in host_groups:
        host_groups[host] = []
    host_groups[host].append(item)

correlated_findings = []

for host, items in host_groups.items():
    items.sort(key=lambda x: x["_dt"])
    visited = [False] * len(items)

    for i in range(len(items)):
        if visited[i]:
            continue

        cluster = [items[i]]
        visited[i] = True
        cluster_start = items[i]["_dt"]
        cluster_end = cluster_start

        for j in range(i + 1, len(items)):
            if visited[j]:
                continue
            curr_dt = items[j]["_dt"]
            # 300 saniyəlik sürüşən zaman pəncərəsi yoxlaması
            if (curr_dt - cluster_start).total_seconds() <= corr_window_sec:
                cluster.append(items[j])
                visited[j] = True
                if curr_dt > cluster_end:
                    cluster_end = curr_dt

        # Yalnız 2 və ya daha çox anomaliya olduqda correlation yaradılır
        if len(cluster) >= 2:
            sources_involved = sorted(list(set(item["_source"] for item in cluster)))
            anomaly_types = sorted(list(set(item.get("anomaly_type", "unknown") for item in cluster)))

            member_refs = []
            for item in cluster:
                ref_id = item.get("event_refs", [None])[0] or f"{item['_source']}_{item['_dt'].isoformat()}"
                member_refs.append(ref_id)

            # Score hesablanması:
            # 1 bal hər daxil olan mənbə üçün + 1 bal hər unikal anomaliya növü üçün
            # Asset criticality multiplier: kritik serverlər üçün 1.5x, digərləri üçün 1.0x
            base_score = len(sources_involved) + len(anomaly_types)
            criticality_multiplier = 1.5 if ("dc" in host.lower() or "prod" in host.lower() or "db" in host.lower()) else 1.0
            final_score = int(round(base_score * criticality_multiplier))

            # Deterministik correlation_id
            id_string = f"{host}_{cluster_start.isoformat()}_{'_'.join(sources_involved)}"
            correlation_id = "CORR-" + hashlib.sha256(id_string.encode('utf-8')).hexdigest()[:8].upper()

            correlated_findings.append({
                "correlation_id": correlation_id,
                "host": host,
                "window_start": cluster_start.isoformat(),
                "window_end": cluster_end.isoformat(),
                "sources_involved": sources_involved,
                "anomaly_types": anomaly_types,
                "member_refs": member_refs,
                "score": final_score
            })

multi_host_findings = 0
max_score = max([f["score"] for f in correlated_findings]) if correlated_findings else 0

output_doc = {
    "total_single_source_anomalies": total_single_source,
    "total_correlated_findings": len(correlated_findings),
    "max_score": max_score,
    "correlated_findings": correlated_findings
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(output_doc, f, indent=2, ensure_ascii=False)

print(f"single-source anomalies  : {total_single_source}")
print(f"correlated findings      : {len(correlated_findings)}")
print(f"multi-host findings      : {multi_host_findings}")
print(f"max score                : {max_score}")
print(f"{output_file} written")

PYTHON_EOF
