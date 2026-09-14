#!/bin/bash
#
# 2-windows_parse.sh - Task 2: Windows Event Parsing
#

set -euo pipefail

# Mühit dəyişənlərini oxu (yoxdursa, default yolları götür)
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
WINDOWS_DIR="$EVIDENCE_PACK/windows"
TELEMETRY_FILE="$EVIDENCE_PACK/student_telemetry/windows_events.json"
OUTPUT_FILE="${OUTPUT_FILE:-$(pwd)/windows_events.json}"

if [ ! -d "$WINDOWS_DIR" ]; then
    echo "Error: Windows directory not found at $WINDOWS_DIR" >&2
    exit 1
fi

python3 - "$WINDOWS_DIR" "$TELEMETRY_FILE" "$OUTPUT_FILE" <<'PYTHON'
import os
import sys
import json

windows_dir = sys.argv[1]
telemetry_file = sys.argv[2]
output_file = sys.argv[3]

# Birləşdiriləcək Windows fayllarının siyahısı
files_to_process = [
    ("security.json", "reading security.json"),
    ("sysmon.json", "reading sysmon.json"),
    ("powershell.json", "reading powershell.json")
]

total_records = 0

def process_file(file_path, default_origin, out_fh):
    count = 0
    if not os.path.exists(file_path):
        return count

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                record = json.loads(line_str)
                if isinstance(record, dict):
                    # source_origin sahəsini yoxla və təyin et
                    if "source_origin" not in record or not record["source_origin"]:
                        record["source_origin"] = default_origin
                    
                    # NDJSON formatında yaz
                    out_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                    count += 1
            except json.JSONDecodeError:
                continue
    return count

with open(output_file, "w", encoding="utf-8") as out_f:
    # 1. Primary windows log fayllarını emal et
    for filename, label in files_to_process:
        path = os.path.join(windows_dir, filename)
        cnt = process_file(path, "evidence_pack", out_f)
        total_records += cnt
        print(f"{label:<26} ... {cnt:>5} records")

    # 2. Student Telemetry məlumatlarını əlavə et
    t_cnt = process_file(telemetry_file, "student_telemetry", out_f)
    total_records += t_cnt
    print(f"{'appending student telemetry':<26} ... {t_cnt:>5} records")

print(f"windows_events.json: {total_records} records")

PYTHON
