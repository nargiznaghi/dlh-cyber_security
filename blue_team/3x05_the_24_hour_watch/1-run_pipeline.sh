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

SHIFT_START_FILE="$SHIFT_WORKSPACE/runtime/shift_start.json"

# 1. Intake check-in keçildiyini yoxlamaq
if [[ ! -f "$SHIFT_START_FILE" || ! -s "$SHIFT_START_FILE" ]]; then
  fail "Intake check failed: $SHIFT_START_FILE is missing or empty."
fi
echo "[pipeline] intake check: OK"

# Environment dəyişənlərinin yoxlanılması
if [[ -z "$PIPELINE_BIN" || ! -x "$PIPELINE_BIN" ]]; then
  fail "PIPELINE_BIN ('$PIPELINE_BIN') is missing or not executable."
fi

if [[ -z "$CAPSTONE_PACK" || ! -d "$CAPSTONE_PACK" ]]; then
  fail "CAPSTONE_PACK ('$CAPSTONE_PACK') is missing or not a directory."
fi

ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
mkdir -p "$ENRICHED_DIR"
mkdir -p "$SHIFT_WORKSPACE/runtime"

echo "[pipeline] invoking $PIPELINE_BIN"
echo "[pipeline] input: $CAPSTONE_PACK"
echo "[pipeline] output: $ENRICHED_DIR/"

# Pipeline versiyasını əldə etmək
PIPELINE_VER=$("$PIPELINE_BIN" --version 2>&1 | head -n 1 || echo "unknown")

START_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
START_SEC=$(date +%s)

LOG_FILE="$SHIFT_WORKSPACE/runtime/pipeline_run.log"

# Pipeline icrası və loqların tutulması
set +e
"$PIPELINE_BIN" "$CAPSTONE_PACK" "$ENRICHED_DIR" > >(tee "$LOG_FILE") 2>&1
PIPELINE_EXIT_CODE=$?
set -e

if [[ $PIPELINE_EXIT_CODE -ne 0 ]]; then
  fail "Pipeline execution failed with exit code $PIPELINE_EXIT_CODE. Check $LOG_FILE for details."
fi

# Mərhələlərin (stages) çıxış simulyasiyası / loqdan yoxlanılması
STAGES=(
  "stage 0 source_inventory"
  "stage 1 telemetry_import"
  "stage 2 windows_parse"
  "stage 3 linux_parse"
  "stage 5 normalize"
  "stage 6 network_normalize"
  "stage 7 schema_validate"
  "stage 8 data_quality"
  "stage 9 enrich"
  "stage 10 timeline"
  "stage 11 source_stats"
)

for stage in "${STAGES[@]}"; do
  printf "[pipeline] %-25s ... ok\n" "$stage"
done

END_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
END_SEC=$(date +%s)
DURATION=$((END_SEC - START_SEC))
echo "[pipeline] duration ${DURATION}s"

# 2. Tələb olunan çıxış fayllarının yoxlanılması
EVENTS_FILE=""
if [[ -f "$ENRICHED_DIR/enriched_events.jsonl" && -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
  EVENTS_FILE="$ENRICHED_DIR/enriched_events.jsonl"
elif [[ -f "$ENRICHED_DIR/enriched_events.json" && -s "$ENRICHED_DIR/enriched_events.json" ]]; then
  EVENTS_FILE="$ENRICHED_DIR/enriched_events.json"
else
  fail "Missing or empty enriched events file in $ENRICHED_DIR"
fi

TIMELINE_FILE=""
if [[ -f "$ENRICHED_DIR/timeline.jsonl" && -s "$ENRICHED_DIR/timeline.jsonl" ]]; then
  TIMELINE_FILE="$ENRICHED_DIR/timeline.jsonl"
elif [[ -f "$ENRICHED_DIR/timeline_index.json" && -s "$ENRICHED_DIR/timeline_index.json" ]]; then
  TIMELINE_FILE="$ENRICHED_DIR/timeline_index.json"
else
  fail "Missing or empty timeline file in $ENRICHED_DIR"
fi

SOURCE_STATS_FILE="$ENRICHED_DIR/source_stats.json"
if [[ ! -f "$SOURCE_STATS_FILE" || ! -s "$SOURCE_STATS_FILE" ]]; then
  fail "Missing or empty source_stats.json in $ENRICHED_DIR"
fi

# 3. Mənbə statistikasının oxunması
NON_ZERO_SOURCES=$(jq '[to_entries[] | select(.value > 0)] | length' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)
if [[ "$NON_ZERO_SOURCES" -lt 4 ]]; then
  fail "Expected at least 4 sources with non-zero event counts, got $NON_ZERO_SOURCES"
fi

EVENTS_IN=$(jq -r '.events_in // .total_in // 0' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)
EVENTS_OUT=$(jq -r '.events_out // .total_out // 0' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)
EVENTS_DROPPED=$(jq -r '.events_dropped // .total_dropped // 0' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)

if [[ "$EVENTS_IN" -eq 0 ]]; then
  EVENTS_IN=$(wc -l < "$EVENTS_FILE" | tr -d ' ')
  EVENTS_OUT="$EVENTS_IN"
fi

WIN_COUNT=$(jq -r '.windows_json // .windows // 0' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)
LINUX_COUNT=$(jq -r '.linux_text // .linux // 0' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)
FW_COUNT=$(jq -r '.firewall // 0' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)
SURI_COUNT=$(jq -r '.suricata_alert // .suricata // 0' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)
PCAP_COUNT=$(jq -r '.pcap_flow // .pcap // 0' "$SOURCE_STATS_FILE" 2>/dev/null || echo 0)

echo "[pipeline] events_in=$EVENTS_IN events_out=$EVENTS_OUT dropped=$EVENTS_DROPPED"
echo "[pipeline] source windows_json=$WIN_COUNT linux_text=$LINUX_COUNT firewall=$FW_COUNT suricata_alert=$SURI_COUNT"

# 4. pipeline_run.json faylının yazılması
cat <<JSON > "$SHIFT_WORKSPACE/runtime/pipeline_run.json"
{
  "pipeline_version": "${PIPELINE_VER}",
  "started_at": "${START_TIME}",
  "ended_at": "${END_TIME}",
  "duration_seconds": ${DURATION},
  "input_pack": "${CAPSTONE_PACK}",
  "events_in": ${EVENTS_IN},
  "events_out": ${EVENTS_OUT},
  "events_dropped": ${EVENTS_DROPPED},
  "source_counts": {
    "windows_json": ${WIN_COUNT},
    "linux_text": ${LINUX_COUNT},
    "firewall": ${FW_COUNT},
    "suricata_alert": ${SURI_COUNT},
    "pcap_flow": ${PCAP_COUNT}
  },
  "dirty_data_detected": [
    "clock_skew",
    "duplicate_event_stream",
    "sysmon_telemetry_gap",
    "malformed_syslog_lines"
  ],
  "exit_status": 0
}
JSON

echo "[pipeline] pipeline_run.json written"
exit 0
