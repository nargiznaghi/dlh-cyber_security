#!/bin/bash
#
# 9-enrich.sh - Task 9: Context Enrichment
#

set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
CONTEXT_DIR="$EVIDENCE_PACK/context"

INPUT_FILE="$WORKDIR/cleaned_events.json"
ASSET_FILE="$CONTEXT_DIR/asset_inventory.json"
ZONE_FILE="$CONTEXT_DIR/network_zones.json"
OUTPUT_FILE="$WORKDIR/enriched_events.json"

for file in "$INPUT_FILE" "$ASSET_FILE" "$ZONE_FILE"; do
    if [ ! -f "$file" ]; then
        echo "Error: Required file $file not found." >&2
        exit 1
    fi
done

python3 - "$INPUT_FILE" "$ASSET_FILE" "$ZONE_FILE" "$OUTPUT_FILE" <<'PYTHON'
import sys
import json
import ipaddress

input_file = sys.argv[1]
asset_file = sys.argv[2]
zone_file = sys.argv[3]
output_file = sys.argv[4]

# 1. Asset Inventory-ni yüklə (kiçik hərflərlə lookup üçün)
with open(asset_file, "r", encoding="utf-8") as f:
    assets_raw = json.load(f)

assets = {}
if isinstance(assets_raw, list):
    for item in assets_raw:
        host = item.get("hostname")
        if host:
            assets[host.lower()] = item
elif isinstance(assets_raw, dict):
    for k, v in assets_raw.items():
        assets[k.lower()] = v

# 2. Network Zones CIDR obyektlərini hazırla
with open(zone_file, "r", encoding="utf-8") as f:
    zones_raw = json.load(f)

zone_networks = []
if isinstance(zones_raw, list):
    for z in zones_raw:
        z_name = z.get("zone") or z.get("name")
        cidrs = z.get("cidrs") or z.get("cidr") or []
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                zone_networks.append((net, z_name))
            except ValueError:
                pass
elif isinstance(zones_raw, dict):
    for z_name, cidrs in zones_raw.items():
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
                zone_networks.append((net, z_name))
            except ValueError:
                pass

def resolve_ip_zone(ip_str):
    if not ip_str or not isinstance(ip_str, str):
        return "unknown"
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        for net, z_name in zone_networks:
            if ip_obj in net:
                return z_name
    except ValueError:
        pass
    return "unknown"

total_events = 0
asset_added_cnt = 0
src_zone_cnt = 0
dst_zone_cnt = 0
unknown_hosts_cnt = 0

enriched_records = []

with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
        except json.JSONDecodeError:
            continue

        total_events += 1

        # Hostname üzrə Asset Enrichment
        host = rec.get("hostname")
        if host and isinstance(host, str) and host.lower() in assets:
            asset_info = assets[host.lower()]
            rec["asset"] = {
                "role": asset_info.get("role"),
                "criticality": asset_info.get("criticality"),
                "os": asset_info.get("os"),
                "owner": asset_info.get("owner"),
                "zone": asset_info.get("zone")
            }
            asset_added_cnt += 1
        else:
            rec["asset"] = None
            unknown_hosts_cnt += 1

        # IP Zonalarını təyin etmək
        src_ip = rec.get("src_ip")
        dst_ip = rec.get("dst_ip")

        src_z = resolve_ip_zone(src_ip)
        dst_z = resolve_ip_zone(dst_ip)

        rec["src_zone"] = src_z
        rec["dst_zone"] = dst_z

        if src_z != "unknown":
            src_zone_cnt += 1
        if dst_z != "unknown":
            dst_zone_cnt += 1

        enriched_records.append(rec)

# Fayla yazılması
with open(output_file, "w", encoding="utf-8") as out_f:
    for rec in enriched_records:
        out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")

# Statistik göstəricilər
asset_pct = (asset_added_cnt / total_events * 100) if total_events > 0 else 0.0
src_pct = (src_zone_cnt / total_events * 100) if total_events > 0 else 0.0
dst_pct = (dst_zone_cnt / total_events * 100) if total_events > 0 else 0.0

print(f"events processed    : {total_events}")
print(f"asset context added : {asset_added_cnt} ({asset_pct:.1f}%)")
print(f"src_zone resolved   : {src_zone_cnt} ({src_pct:.1f}%)")
print(f"dst_zone resolved   : {dst_zone_cnt} ({dst_pct:.1f}%)")
print(f"unknown hosts       : {unknown_hosts_cnt}")
print("enriched_events.json written")

PYTHON
