#!/bin/bash
#
# 15-baseline_validation.sh - Task 15: Baseline Validation & Backtest for 3x01
#

set -euo pipefail

SUMMARY_FILE="${SUMMARY_FILE:-$(pwd)/baseline_summary.json}"
LABELED_EVENTS="${LABELED_EVENTS:-$(pwd)/labeled_events.json}"
VALIDATION_OUT="${VALIDATION_OUT:-$(pwd)/baseline_validation.json}"

ACCEPTABLE_SELF_CHECK_LIMIT="${ACCEPTABLE_SELF_CHECK_LIMIT:-5}"
MIN_SNR="${MIN_SNR:-3.0}"

for f in "$SUMMARY_FILE" "$LABELED_EVENTS"; do
    if [ ! -f "$f" ]; then
        echo "Error: Required input file not found at $f" >&2
        exit 1
    fi
done

# Temp kataloqu
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# 1. Self-check üçün baseline_summary.json surəti
cp "$SUMMARY_FILE" "$TMP_DIR/summary_self.json"
python3 -c '
import json, sys
with open(sys.argv[1], "r+") as f:
    d = json.load(f)
    d["evaluation_window"] = d["baseline_window"]
    f.seek(0)
    json.dump(d, f, indent=2)
    f.truncate()
' "$TMP_DIR/summary_self.json"

# 2. Self-check icrası (T10, T11, T12)
SUMMARY_FILE="$TMP_DIR/summary_self.json" OUTPUT_FILE="$TMP_DIR/self_check_auth.json" ./10-anomalies_auth.sh >/dev/null 2>&1 || true
SUMMARY_FILE="$TMP_DIR/summary_self.json" OUTPUT_FILE="$TMP_DIR/self_check_process.json" ./11-anomalies_process.sh >/dev/null 2>&1 || true
if [ -f "./12-anomalies_network.sh" ]; then
    SUMMARY_FILE="$TMP_DIR/summary_self.json" OUTPUT_FILE="$TMP_DIR/self_check_network.json" ./12-anomalies_network.sh >/dev/null 2>&1 || true
else
    echo '{"total_anomalies": 0, "anomalies": []}' > "$TMP_DIR/self_check_network.json"
fi

# 3. Live-check icrası (T10, T11, T12)
SUMMARY_FILE="$SUMMARY_FILE" OUTPUT_FILE="$TMP_DIR/live_check_auth.json" ./10-anomalies_auth.sh >/dev/null 2>&1 || true
SUMMARY_FILE="$SUMMARY_FILE" OUTPUT_FILE="$TMP_DIR/live_check_process.json" ./11-anomalies_process.sh >/dev/null 2>&1 || true
if [ -f "./12-anomalies_network.sh" ]; then
    SUMMARY_FILE="$SUMMARY_FILE" OUTPUT_FILE="$TMP_DIR/live_check_network.json" ./12-anomalies_network.sh >/dev/null 2>&1 || true
else
    echo '{"total_anomalies": 0, "anomalies": []}' > "$TMP_DIR/live_check_network.json"
fi

# 4. Təhlil və Nəticənin Hesablanması
python3 - "$TMP_DIR" "$VALIDATION_OUT" "$ACCEPTABLE_SELF_CHECK_LIMIT" "$MIN_SNR" <<'PYTHON_EOF'
import sys
import json
import os
from collections import defaultdict

tmp_dir = sys.argv[1]
output_file = sys.argv[2]
limit_self = int(sys.argv[3])
min_snr = float(sys.argv[4])

def load_anomalies_from_files(files):
    total = 0
    by_type = defaultdict(int)
    for fpath in files:
        if os.path.exists(fpath):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                items = data.get("anomalies", [])
                total += len(items)
                for item in items:
                    atype = item.get("anomaly_type", "unknown")
                    by_type[atype] += 1
            except Exception:
                pass
    return total, dict(by_type)

self_files = [
    os.path.join(tmp_dir, "self_check_auth.json"),
    os.path.join(tmp_dir, "self_check_process.json"),
    os.path.join(tmp_dir, "self_check_network.json")
]

live_files = [
    os.path.join(tmp_dir, "live_check_auth.json"),
    os.path.join(tmp_dir, "live_check_process.json"),
    os.path.join(tmp_dir, "live_check_network.json")
]

self_total, self_breakdown = load_anomalies_from_files(self_files)
live_total, live_breakdown = load_anomalies_from_files(live_files)

snr = round(live_total / max(self_total, 1), 2)

is_pass = (self_total < limit_self) and (snr >= min_snr)
verdict = "pass" if is_pass else "fail"

val_doc = {
    "self_check_total": self_total,
    "live_check_total": live_total,
    "signal_to_noise_ratio": snr,
    "verdict": verdict,
    "self_check_breakdown": self_breakdown,
    "live_check_breakdown": live_breakdown
}

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(val_doc, f, indent=2, ensure_ascii=False)

print(f"self-check anomalies (baseline window): {self_total}")
print(f"live-check anomalies (evaluation win ): {live_total}")
print(f"signal-to-noise ratio                : {snr}")
print(f"verdict                              : {verdict}")
print(f"{output_file} written")

if not is_pass:
    sys.exit(1)

PYTHON_EOF
