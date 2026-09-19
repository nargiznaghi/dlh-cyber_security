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

PIPELINE_RUN_FILE="$SHIFT_WORKSPACE/runtime/pipeline_run.json"

# 1. Pipeline yoxlanılması
if [[ ! -f "$PIPELINE_RUN_FILE" || ! -s "$PIPELINE_RUN_FILE" ]]; then
  fail "Pipeline check failed: $PIPELINE_RUN_FILE is missing or empty."
fi

EXIT_STATUS=$(jq -r '.exit_status // 1' "$PIPELINE_RUN_FILE")
if [[ "$EXIT_STATUS" -ne 0 ]]; then
  fail "Pipeline check failed: exit_status in $PIPELINE_RUN_FILE is non-zero ($EXIT_STATUS)."
fi
echo "[baseline] pipeline check: OK"

# Environment dəyişənlərinin yoxlanılması
if [[ -z "$BASELINE_BIN" || ! -x "$BASELINE_BIN" ]]; then
  fail "BASELINE_BIN ('$BASELINE_BIN') is missing or not executable."
fi

ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
INPUT_EVENTS=""
if [[ -f "$ENRICHED_DIR/enriched_events.jsonl" && -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
  INPUT_EVENTS="$ENRICHED_DIR/enriched_events.jsonl"
elif [[ -f "$ENRICHED_DIR/enriched_events.json" && -s "$ENRICHED_DIR/enriched_events.json" ]]; then
  INPUT_EVENTS="$ENRICHED_DIR/enriched_events.json"
else
  fail "No valid enriched events file found in $ENRICHED_DIR"
fi

OUTPUT_BASELINE="$ENRICHED_DIR/baseline.json"

echo "[baseline] invoking $BASELINE_BIN"
echo "[baseline] input: $INPUT_EVENTS"
echo "[baseline] output: $OUTPUT_BASELINE"

BASELINE_VER=$("$BASELINE_BIN" --version 2>&1 | head -n 1 || echo "1.0.0")

START_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

# Baseline ikili faylının icrası
set +e
"$BASELINE_BIN" "$INPUT_EVENTS" "$OUTPUT_BASELINE" >/dev/null 2>&1
BASELINE_EXIT_CODE=$?
set -e

if [[ $BASELINE_EXIT_CODE -ne 0 ]]; then
  fail "Baseline script failed with exit code $BASELINE_EXIT_CODE."
fi

if [[ ! -f "$OUTPUT_BASELINE" || ! -s "$OUTPUT_BASELINE" ]]; then
  fail "Baseline output file $OUTPUT_BASELINE is missing or empty."
fi

END_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

# 2. baseline.json təhlili və göstəricilərin hesablanması
HOSTS_TOTAL=$(jq -r '.hosts_total // (.hosts | length) // 0' "$OUTPUT_BASELINE" 2>/dev/null || echo 0)
if [[ "$HOSTS_TOTAL" -eq 0 ]]; then
  fail "Baseline processing failed: total unique hosts processed is zero."
fi

HOSTS_WITH_DEVIATIONS=$(jq -r '.hosts_with_deviations // ([.deviation_markers[]?.host] | unique | length) // 0' "$OUTPUT_BASELINE" 2>/dev/null || echo 0)

# Hot hosts (en yüksək deviation_score toplayan top 5 host)
HOT_HOSTS_JSON=$(jq -c '
  if .hot_hosts then .hot_hosts[:5]
  elif .deviation_markers then
    [.deviation_markers[]] | group_by(.host) | map({
      host: .[0].host,
      score: (map(.deviation_score // 1) | add)
    }) | sort_by(-.score) | .[:5] | map(.host)
  else [] end
' "$OUTPUT_BASELINE" 2>/dev/null || echo "[]")

HOT_HOSTS_STR=$(echo "$HOT_HOSTS_JSON" | jq -r 'join(" ")')

# Marker növləri üzrə statistika
UNSEEN_SRC=$(jq -r '[.deviation_markers[]? | select(.marker=="unseen_src_ip")] | length' "$OUTPUT_BASELINE" 2>/dev/null || echo 0)
OFF_HOURS=$(jq -r '[.deviation_markers[]? | select(.marker=="off_hours_login")] | length' "$OUTPUT_BASELINE" 2>/dev/null || echo 0)
NEW_SERVICE=$(jq -r '[.deviation_markers[]? | select(.marker=="new_service")] | length' "$OUTPUT_BASELINE" 2>/dev/null || echo 0)
TOTAL_MARKERS=$(jq -r '.deviation_markers | length // 0' "$OUTPUT_BASELINE" 2>/dev/null || echo 0)

echo "[baseline] hosts processed: $HOSTS_TOTAL"
echo "[baseline] hosts with deviations: $HOSTS_WITH_DEVIATIONS"
echo "[baseline] hot hosts: $HOT_HOSTS_STR"
echo "[baseline] markers: $TOTAL_MARKERS total (unseen_src_ip: $UNSEEN_SRC  off_hours: $OFF_HOURS  new_service: $NEW_SERVICE)"

# 3. baseline_run.json faylının yazılması
DEVIATION_MARKERS_JSON=$(jq -c '.deviation_markers // []' "$OUTPUT_BASELINE" 2>/dev/null || echo "[]")

cat <<JSON > "$SHIFT_WORKSPACE/runtime/baseline_run.json"
{
  "baseline_version": "${BASELINE_VER}",
  "hosts_total": ${HOSTS_TOTAL},
  "hosts_with_deviations": ${HOSTS_WITH_DEVIATIONS},
  "deviation_markers": ${DEVIATION_MARKERS_JSON},
  "hot_hosts": ${HOT_HOSTS_JSON},
  "started_at": "${START_TIME}",
  "ended_at": "${END_TIME}",
  "exit_status": 0
}
JSON

echo "[baseline] baseline_run.json written"
exit 0
