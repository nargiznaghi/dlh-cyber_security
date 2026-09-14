#!/bin/bash
#
# 2-query_toolkit.sh - Reusable Query Toolkit for 3x01
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ENRICHED_EVENTS="$HANDOFF_DIR/data/enriched_events.json"

if [ $# -eq 0 ] || [ "$1" = "help" ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "query_toolkit.sh <verb> [options]"
    echo "  filter   emit matching records as ndjson"
    echo "  top      top N values of a field"
    echo "  distinct distinct values of a field"
    echo "  count    number of matching records"
    echo "  window   bucketed counts by time window"
    echo "  help     this message"
    exit 0
fi

if [ ! -f "$ENRICHED_EVENTS" ]; then
    echo "Error: Dataset not found at $ENRICHED_EVENTS" >&2
    exit 1
fi

VERB="$1"
shift

python3 - "$ENRICHED_EVENTS" "$VERB" "$@" <<'PYTHON_EOF'
import sys
import json
import argparse
from datetime import datetime, timezone

dataset_file = sys.argv[1]
verb = sys.argv[2]
args_list = sys.argv[3:]

parser = argparse.ArgumentParser(prog="query_toolkit.sh", add_help=False)
parser.add_argument("--source", type=str, default=None)
parser.add_argument("--host", type=str, default=None)
parser.add_argument("--from", dest="from_time", type=str, default=None)
parser.add_argument("--to", dest="to_time", type=str, default=None)
parser.add_argument("--category", type=str, default=None)
parser.add_argument("--field", type=str, default=None)
parser.add_argument("--limit", type=int, default=10)
parser.add_argument("--bucket", type=str, choices=["hour", "day"], default="hour")

parsed_args, _ = parser.parse_known_args(args_list)

def parse_iso(ts_str):
    if not ts_str:
        return None
    try:
        ts_s = ts_str.strip()
        if ts_s.endswith("Z"):
            ts_s = ts_s[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

from_dt = parse_iso(parsed_args.from_time)
to_dt = parse_iso(parsed_args.to_time)

def get_field_val(record, field_name):
    if not field_name:
        return None
    parts = field_name.split(".")
    val = record
    for p in parts:
        if isinstance(val, dict):
            val = val.get(p)
        else:
            return None
    return val

def record_matches(rec):
    if parsed_args.source and rec.get("source_type") != parsed_args.source:
        return False
    if parsed_args.host:
        h = rec.get("hostname")
        if not h or h.lower() != parsed_args.host.lower():
            return False
    if parsed_args.category and rec.get("event_category") != parsed_args.category:
        return False
    
    if from_dt or to_dt:
        rec_dt = parse_iso(rec.get("timestamp"))
        if not rec_dt:
            return False
        if from_dt and rec_dt < from_dt:
            return False
        if to_dt and rec_dt > to_dt:
            return False
            
    return True

matched_records = []

with open(dataset_file, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line_str = line.strip()
        if not line_str:
            continue
        try:
            rec = json.loads(line_str)
            if record_matches(rec):
                matched_records.append(rec)
        except json.JSONDecodeError:
            continue

if verb == "filter":
    for rec in matched_records:
        print(json.dumps(rec, ensure_ascii=False))

elif verb == "count":
    print(len(matched_records))

elif verb == "distinct":
    if not parsed_args.field:
        sys.stderr.write("Error: --field is required for distinct\n")
        sys.exit(1)
    seen = set()
    for rec in matched_records:
        val = get_field_val(rec, parsed_args.field)
        if val is not None:
            val_str = str(val)
            if val_str not in seen:
                seen.add(val_str)
                print(val_str)

elif verb == "top":
    if not parsed_args.field:
        sys.stderr.write("Error: --field is required for top\n")
        sys.exit(1)
    counts = {}
    for rec in matched_records:
        val = get_field_val(rec, parsed_args.field)
        if val is not None:
            val_str = str(val)
            counts[val_str] = counts.get(val_str, 0) + 1
    
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:parsed_args.limit]
    for k, v in sorted_items:
        print(f"{k:<40} {v}")

elif verb == "window":
    buckets = {}
    for rec in matched_records:
        dt = parse_iso(rec.get("timestamp"))
        if dt:
            if parsed_args.bucket == "day":
                b_key = dt.strftime("%Y-%m-%d")
            else:
                b_key = dt.strftime("%Y-%m-%dT%H:00:00Z")
            buckets[b_key] = buckets.get(b_key, 0) + 1
            
    sorted_buckets = sorted(buckets.items(), key=lambda x: x[0])
    for k, v in sorted_buckets:
        print(f"{k:<25} {v}")

else:
    sys.stderr.write(f"Unknown verb: {verb}\n")
    sys.exit(1)

PYTHON_EOF
