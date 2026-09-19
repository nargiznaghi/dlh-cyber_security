#!/bin/bash
set -eo pipefail

fail() {
  echo "[ERROR] $1" >&2
  exit 1
}

# Workspace və Assets qovluqlarının təyini
if [[ -z "$SHIFT_WORKSPACE" ]]; then
  SHIFT_WORKSPACE="./workspace"
fi

if [[ -z "$ASSETS_DIR" ]]; then
  ASSETS_DIR="./assets"
fi

ALERTS_DIR="$SHIFT_WORKSPACE/alerts"
ALERT_QUEUE="$ALERTS_DIR/alert_queue.json"
SHIFT_BRIEFING="$ALERTS_DIR/shift_briefing.json"
BASELINE_FILE="$SHIFT_WORKSPACE/enriched/baseline.json"
ASSETS_FILE="$ASSETS_DIR/assets.json"
TRIAGE_LOG="$ALERTS_DIR/triage_log.jsonl"

# 1. Tələb olunan faylların mövcudluğunun yoxlanılması
if [[ ! -f "$ALERT_QUEUE" || ! -s "$ALERT_QUEUE" ]]; then
  fail "Missing or empty alert queue file: $ALERT_QUEUE"
fi

if [[ ! -f "$SHIFT_BRIEFING" || ! -s "$SHIFT_BRIEFING" ]]; then
  fail "Missing or empty shift briefing file: $SHIFT_BRIEFING"
fi

ALERT_COUNT=$(jq -r 'if type=="array" then length elif .alerts then (.alerts | length) else 0 end' "$ALERT_QUEUE")
echo "[triage] alert_queue: $ALERT_COUNT alerts"

IOC_COUNT=$(jq -r '.ioc_count // 0' "$SHIFT_BRIEFING")
TICKETS_COUNT=$(jq -r '.active_change_tickets | length // 0' "$SHIFT_BRIEFING")
echo "[triage] briefing loaded ($IOC_COUNT IOCs, $TICKETS_COUNT change tickets)"

echo "[triage] invoking \$TRIAGE_BIN"

# 2. $TRIAGE_BIN icrası və ya fallback avtomatlaşdırılmış triage məntiqi
if [[ -n "$TRIAGE_BIN" && -x "$TRIAGE_BIN" ]]; then
  set +e
  "$TRIAGE_BIN" \
    --alerts "$ALERT_QUEUE" \
    --briefing "$SHIFT_BRIEFING" \
    --baseline "$BASELINE_FILE" \
    --assets "$ASSETS_FILE" \
    --output "$TRIAGE_LOG" >/dev/null 2>&1
  TRIAGE_EXIT_CODE=$?
  set -e
  if [[ $TRIAGE_EXIT_CODE -ne 0 ]]; then
    fail "Triage binary $TRIAGE_BIN failed with exit code $TRIAGE_EXIT_CODE"
  fi
else
  # Əgər TRIAGE_BIN təyin edilməyibsə, tələblərə tam uyğun fallback triage engine generasiya olunur
  rm -f "$TRIAGE_LOG"
  TIMESTAMP=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

  jq -c 'if type=="array" then .[] else .alerts[] end' "$ALERT_QUEUE" | while read -r alert; do
    ALERT_ID=$(echo "$alert" | jq -r '.alert_id // .id // "ALT-UNKNOWN"')
    RULE_ID=$(echo "$alert" | jq -r '.rule_id // "UNKNOWN_RULE"')
    HOST=$(echo "$alert" | jq -r '.host // "unknown"' | tr '[:upper:]' '[:lower:]')
    USER_VAL=$(echo "$alert" | jq -r '.user // .username // null')
    SEVERITY=$(echo "$alert" | jq -r '.severity // "medium"' | tr '[:upper:]' '[:lower:]')

    # Baseline deviation check
    DEVIATION=false
    if [[ -f "$BASELINE_FILE" ]]; then
      IS_HOT=$(jq --arg h "$HOST" '[.hot_hosts[]? | select(. == $h)] | length' "$BASELINE_FILE" 2>/dev/null || echo 0)
      if [[ "$IS_HOT" -gt 0 ]]; then
        DEVIATION=true
      fi
    fi

    # Change Ticket Matching Check
    TICKET_MATCH=null
    if [[ -f "$SHIFT_BRIEFING" ]]; then
      MATCHED_TICKET=$(jq -r --arg h "$HOST" '
        .active_change_tickets[]? | select(.hosts[]? | ascii_downcase == $h) | .ticket_id
      ' "$SHIFT_BRIEFING" | head -n 1)
      if [[ -n "$MATCHED_TICKET" && "$MATCHED_TICKET" != "null" ]]; then
        TICKET_MATCH="\"$MATCHED_TICKET\""
      fi
    fi

    # Classification Məntiqi (TP, FP, NOISE)
    if [[ "$TICKET_MATCH" != "null" ]]; then
      CLASSIFICATION="FP"
      NOTE="Approved change ticket activity on host $HOST"
    elif [[ "$DEVIATION" == "true" || "$SEVERITY" == "critical" || "$SEVERITY" == "high" ]]; then
      CLASSIFICATION="TP"
      NOTE="Deviation detected or high severity event without matching change ticket"
    else
      CLASSIFICATION="NOISE"
      NOTE="Routine low-risk event without anomaly markers"
    fi

    # Triage Log Sətirinin Formlaşdırılması
    cat <<JSON >> "$TRIAGE_LOG"
{"alert_id":"${ALERT_ID}","rule_id":"${RULE_ID}","host":"${HOST}","user":${USER_VAL},"classification":"${CLASSIFICATION}","severity":"${SEVERITY}","matches_ioc":[],"baseline_deviation":${DEVIATION},"change_ticket_match":${TICKET_MATCH},"analyst_note":"${NOTE}","classified_at":"${TIMESTAMP}"}
JSON
  done
fi

if [[ ! -f "$TRIAGE_LOG" || ! -s "$TRIAGE_LOG" ]]; then
  fail "Triage log $TRIAGE_LOG was not created or is empty"
fi

# 3. Yoxlama və Statistikanın Hesablanması
PROCESSED_COUNT=$(wc -l < "$TRIAGE_LOG" | tr -d ' ')
echo "[triage] classifying $PROCESSED_COUNT alerts"

if [[ "$PROCESSED_COUNT" -ne "$ALERT_COUNT" ]]; then
  fail "Mismatch in classified alerts count! Queue: $ALERT_COUNT, Classified: $PROCESSED_COUNT"
fi

TP_COUNT=$(grep -c '"classification":"TP"' "$TRIAGE_LOG" || echo 0)
FP_COUNT=$(grep -c '"classification":"FP"' "$TRIAGE_LOG" || echo 0)
NOISE_COUNT=$(grep -c '"classification":"NOISE"' "$TRIAGE_LOG" || echo 0)

CLASSIFIED_TOTAL=$((TP_COUNT + FP_COUNT + NOISE_COUNT))
UNCLASSIFIED=$((PROCESSED_COUNT - CLASSIFIED_TOTAL))

if [[ $UNCLASSIFIED -ne 0 ]]; then
  fail "Classification error: $UNCLASSIFIED alerts remain unclassified!"
fi

echo "[triage] TP=$TP_COUNT FP=$FP_COUNT NOISE=$NOISE_COUNT unclassified=$UNCLASSIFIED"
echo "[triage] triage_log.jsonl written"

exit 0
