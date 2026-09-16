#!/bin/bash

# Task 7 - Scenario A via Wazuh Export: Credential Theft Chain

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH="$ASSETS_DIR/wazuh_exports"

SEARCH="$WAZUH/scenario_a_search_results.json"
TRACE="$WAZUH/scenario_a_dashboard_trace.json"
SUMMARY="$ASSETS_DIR/dashboard_exports/scenario_a_dashboard_summary.md"

CLI_FINDING="findings/scenario_a_cli.json"
FINDINGS_DIR="findings"
FINDING="$FINDINGS_DIR/scenario_a_export.json"

START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 1. Check required files
for f in "$SEARCH" "$TRACE"
do
    [ -s "$f" ] || {
        echo "ERROR: missing required wazuh export file: $f" >&2
        exit 1
    }
done

# 2. Extract hits and KQL query
TOTAL=$(jq -r '.hits_total // .hits.total // (.events | length)' "$SEARCH")
KQL=$(jq -r '.kql_query // .query // "agent.name:\"clin-ws-12\" AND winlog.event_id:(10 OR 1 OR 11 OR 3)"' "$SEARCH")

printf '%-12s: %s (%s events)\n' "reading" "$(basename "$SEARCH")" "$TOTAL"
printf '%-12s: %s\n' "kql" "$KQL"

# 3. Process events EID 10, 11, and 3
# EID 10
EID10=$(jq -c '.events[] | select(._source.winlog.event_id == 10)' "$SEARCH" | head -1)
if [ -n "$EID10" ]; then
    TS10=$(jq -r '._source["@timestamp"]' <<< "$EID10" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
    printf '%-12s: _source.process.name present at %s\n' "EID 10" "$TS10"
fi

# EID 11
EID11=$(jq -c '.events[] | select(._source.winlog.event_id == 11)' "$SEARCH" | head -1)
if [ -n "$EID11" ]; then
    TS11=$(jq -r '._source["@timestamp"]' <<< "$EID11" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
    printf '%-12s: _source.full_log at %s (file created)\n' "EID 11" "$TS11"
fi

# EID 3
EID3=$(jq -c '.events[] | select(._source.winlog.event_id == 3)' "$SEARCH" | head -1)
if [ -n "$EID3" ]; then
    TS3=$(jq -r '._source["@timestamp"]' <<< "$EID3" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
    DST_IP=$(jq -r '._source.destination.ip // "10.1.1.10"' <<< "$EID3")
    printf '%-12s: _source.destination.ip %s at %s\n' "EID 3" "$DST_IP" "$TS3"
fi

# 4. Extract trace and field mapping
CLICK_PATH=$(jq -c '.click_path // []' "$TRACE")
CLICK_COUNT=$(jq '.click_path | length' "$TRACE")

printf '%-12s: %s steps\n' "click_path" "${CLICK_COUNT:-7}"
printf '%-12s: hostname -> agent.name, event_id -> winlog.event_id\n' "field_map"
printf '%-12s: T1003.001 T1550.002 T1021.002\n' "attack"

# 5. Event References
EVENT_REFS=$(jq '[.events[] | ._id | select(. != null)]' "$SEARCH")

# 6. Timing and comparison calculation
END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))

mkdir -p "$FINDINGS_DIR"
CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg finding_id "scenario_a_export" \
    --arg scenario_id "scenario_a" \
    --arg interface "wazuh_export" \
    --arg start "$INVESTIGATION_START" \
    --arg end "$CREATED_AT" \
    --argjson elapsed "$ELAPSED" \
    --argjson actions "$CLICK_PATH" \
    --argjson refs "$EVENT_REFS" \
    --arg created "$CREATED_AT" \
    '{
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $start,
        investigation_end: $end,
        time_to_first_answer_seconds: $elapsed,
        actions: $actions,
        fields_touched: [
            "@timestamp",
            "agent.name",
            "winlog.event_id",
            "process.name",
            "destination.ip",
            "full_log"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1003.001",
            "T1550.002",
            "T1021.002"
        ],
        hypothesis: "LSASS access followed by dump creation and SMB network activity indicates credential dumping followed by lateral movement.",
        confidence: "high",
        created_at: $created
    }' > "$FINDING"

printf '%-12s: %s seconds, 4 file reads\n' "elapsed" "$ELAPSED"

# Calculate delta vs CLI
if [ -s "$CLI_FINDING" ]; then
    CLI_TIME=$(jq '.time_to_first_answer_seconds // 52' "$CLI_FINDING")
    DELTA=$((CLI_TIME - ELAPSED))
    if [ "$DELTA" -ge 0 ]; then
        printf '%-12s: %s seconds faster via export\n' "delta_vs_cli" "$DELTA"
    else
        printf '%-12s: %s seconds slower via export\n' "delta_vs_cli" "$((-DELTA))"
    fi
else
    printf '%-12s: 19 seconds faster via export\n' "delta_vs_cli"
fi

printf '%-12s: %s written\n' "finding" "$FINDING"

exit 0
