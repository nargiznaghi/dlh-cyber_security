#!/bin/bash
#
# 8-data_quality.sh - Task 8: Dirty Data Handling
#

set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"

INPUT_FILE="$WORKDIR/normalized_events.json"
CLEANED_FILE="$WORKDIR/cleaned_events.json"
LOG_FILE="$WORKDIR/cleaning_log.json"

if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: Input file $INPUT_FILE not found." >&2
    exit 1
fi

python3 - "$INPUT_FILE" "$CLEANED_FILE" "$LOG_FILE" <<'PYTHON'
import sys
import json
import re
from datetime import datetime, timezone

input_file = sys.argv[1]
cleaned_file = sys.argv[2]
log_file = sys.argv[3]

cleaned_records = []
cleaning_logs = []
seen_dedup_keys = set()

# Statistik göstəricilər
stats = {
    "malformed_ts_detected": 0,
    "malformed_ts_repaired": 0,
    "malformed_ts_dropped": 0,
    "duplicates_detected": 0,
    "duplicates_removed": 0,
    "hostname_normalized": 0,
    "encoding_detected": 0,
    "encoding_repaired": 0,
    "wrong_tz_flagged": 0
}

# Gözlənilən tarix aralığı (Mart 2026 ətrafı: 15-20 Mart 2026)
MIN_EXPECTED_TS = datetime(2026, 3, 14, 12, 0, 0, tzinfo=timezone.utc).timestamp()
MAX_EXPECTED_TS = datetime(2026, 3, 21, 12, 0, 0, tzinfo=timezone.utc).timestamp()

def try_parse_iso(ts_str):
    if not ts_str:
        return None
    try:
        ts_s = str(ts_str).strip()
        if ts_s.endswith("Z"):
            ts_s = ts_s[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts_s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def try_repair_timestamp(ts_str):
    if not ts_str:
        return None
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%b %d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S"
    ]
    ts_s = str(ts_str).strip()
    for fmt in formats:
        try:
            if "%Y" not in fmt:
                dt = datetime.strptime(f"2026 {ts_s}", f"%Y {fmt}")
            else:
                dt = datetime.strptime(ts_s, fmt)
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue
    return None

with open(input_file, "r", encoding="utf-8", errors="replace") as f:
    for rec_id, line in enumerate(f, start=1):
        line_str = line.strip()
        if not line_str:
            continue
        try:
            record = json.loads(line_str)
        except json.JSONDecodeError:
            continue

        # 1. Hostname Case Normalization
        orig_hostname = record.get("hostname")
        if orig_hostname and isinstance(orig_hostname, str):
            lowered_host = orig_hostname.lower()
            if orig_hostname != lowered_host:
                stats["hostname_normalized"] += 1
                record["hostname"] = lowered_host
                cleaning_logs.append({
                    "defect_type": "hostname_case",
                    "original_value": orig_hostname,
                    "corrected_value": lowered_host,
                    "record_id": rec_id,
                    "reason": "Normalized hostname to lowercase"
                })

        # 2. Encoding Errors Repair (Latin-1 -> UTF-8)
        raw_msg = record.get("raw_message") or ""
        if "\ufffd" in raw_msg or "Ã" in raw_msg:
            stats["encoding_detected"] += 1
            try:
                reencoded = raw_msg.encode("latin-1", errors="ignore").decode("utf-8", errors="ignore")
                if reencoded and reencoded != raw_msg:
                    stats["encoding_repaired"] += 1
                    record["raw_message"] = reencoded
                    cleaning_logs.append({
                        "defect_type": "encoding_error",
                        "original_value": raw_msg,
                        "corrected_value": reencoded,
                        "record_id": rec_id,
                        "reason": "Re-decoded raw_message from latin-1 to utf-8"
                    })
            except Exception:
                pass

        # 3. Timestamp Validation & Repair
        raw_ts = record.get("timestamp")
        dt_parsed = try_parse_iso(raw_ts)
        
        if dt_parsed is None:
            stats["malformed_ts_detected"] += 1
            repaired_ts = try_repair_timestamp(raw_ts)
            if repaired_ts:
                stats["malformed_ts_repaired"] += 1
                record["timestamp"] = repaired_ts
                cleaning_logs.append({
                    "defect_type": "malformed_timestamp",
                    "original_value": raw_ts,
                    "corrected_value": repaired_ts,
                    "record_id": rec_id,
                    "reason": "Repaired malformed timestamp using fallback parser"
                })
                dt_parsed = try_parse_iso(repaired_ts)
            else:
                stats["malformed_ts_dropped"] += 1
                cleaning_logs.append({
                    "defect_type": "unrepairable_timestamp",
                    "original_value": raw_ts,
                    "corrected_value": None,
                    "record_id": rec_id,
                    "reason": "Timestamp could not be parsed or repaired; dropped record"
                })
                continue

        # 4. Timezone Inconsistency Detection
        if dt_parsed:
            epoch_val = dt_parsed.timestamp()
            if epoch_val < MIN_EXPECTED_TS or epoch_val > MAX_EXPECTED_TS:
                stats["wrong_tz_flagged"] += 1
                cleaning_logs.append({
                    "defect_type": "suspected_wrong_tz",
                    "original_value": raw_ts,
                    "corrected_value": record.get("timestamp"),
                    "record_id": rec_id,
                    "reason": "Timestamp falls outside expected range by >12 hours"
                })

        # 5. Duplicates Handling
        dedup_key = (
            record.get("timestamp"),
            record.get("hostname"),
            record.get("source_type"),
            record.get("raw_message")
        )

        if dedup_key in seen_dedup_keys:
            stats["duplicates_detected"] += 1
            stats["duplicates_removed"] += 1
            cleaning_logs.append({
                "defect_type": "duplicate",
                "original_value": str(dedup_key),
                "corrected_value": "dropped",
                "record_id": rec_id,
                "reason": "Duplicate record detected based on timestamp, hostname, source_type, and raw_message"
            })
            continue
        else:
            seen_dedup_keys.add(dedup_key)

        cleaned_records.append(record)

# Faylları yaddaşa yazırıq
with open(cleaned_file, "w", encoding="utf-8") as out_c:
    for rec in cleaned_records:
        out_c.write(json.dumps(rec, ensure_ascii=False) + "\n")

with open(log_file, "w", encoding="utf-8") as out_l:
    json.dump(cleaning_logs, out_l, indent=2, ensure_ascii=False)

# Expected Output formatında nəticəni çap edirik
print(f"malformed timestamps   :  detected {stats['malformed_ts_detected']:>4d}   repaired {stats['malformed_ts_repaired']:>4d}    dropped {stats['malformed_ts_dropped']:>4d}")
print(f"duplicates             :  detected {stats['duplicates_detected']:>4d}   removed  {stats['duplicates_removed']:>4d}")
print(f"hostname case          :  normalized {stats['hostname_normalized']:>4d}")
print(f"encoding errors        :  detected {stats['encoding_detected']:>4d}   repaired {stats['encoding_repaired']:>4d}")
print(f"suspected wrong tz     :  flagged {stats['wrong_tz_flagged']:>4d}")
print("cleaned_events.json    written")
print("cleaning_log.json      written")

PYTHON
