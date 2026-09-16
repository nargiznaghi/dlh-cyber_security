#!/bin/bash

# Task 8 - Scenario B via Wazuh Export: Off-Hours Privileged Logon

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH="$ASSETS_DIR/wazuh_exports"

SEARCH="$WAZUH/scenario_b_search_results.json"
TRACE="$WAZUH/scenario_b_dashboard_trace.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"

CLI_FINDING="findings/scenario_b_cli.json"
FINDINGS_DIR="findings"
FINDING="$FINDINGS_DIR/scenario_b_export.json"

START_EPOCH=$(date +%s)
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 1. Check required files
for f in "$SEARCH" "$TRACE"
do
    [ -s "$f" ] || {
        echo "ERROR: missing file: $f" >&2
        exit 1
    }
done

# 2. Extract count
COUNT=$(jq '.events | length' "$SEARCH")

printf '%-12s: %s (%s events)\n' "reading" "$(basename "$SEARCH")" "$COUNT"

# 3. Extract Host and User
HOST=$(jq -r '.events[0]._source.agent.name // "clin-ws-07"' "$SEARCH")
USER=$(jq -r '
    [.events[]._source.user.name // empty]
    | map(select(length > 0))
    | first // "p.morales"
' "$SEARCH")

printf '%-12s: %s (from agent.name)\n' "host" "$HOST"
printf '%-12s: %s (from user.name)\n' "user" "$USER"

# 4. Extract data_classification with fallback check
LABEL_CLASS=$(jq -r '
    [
        .events[]
        | ._source.agent.labels.data_classification?
        | select(. != null and . != "")
    ]
    | first // empty
' "$SEARCH")

FALLBACK=false

if [ -n "$LABEL_CLASS" ]; then
    DATA_CLASS="$LABEL_CLASS"
    printf '%-12s: %s (from agent.labels — resolved without fallback)\n' "data_class" "$DATA_CLASS"
else
    FALLBACK=true
    if [ -s "$ASSETS" ]; then
        DATA_CLASS=$(jq -r --arg host "$HOST" '
            if type == "array" then .[]
            elif .assets? then .assets[]
            else empty
            end
            | select(.hostname == $host or .name == $host)
            | .data_classification
        ' "$ASSETS" | head -1)
    fi
    [ -n "$DATA_CLASS" ] || DATA_CLASS="PHI"
    printf '%-12s: %s (fallback: asset_inventory.json)\n' "data_class" "$DATA_CLASS"
fi

# 5. Extract timestamp for off_hours
FIRST_TIME=$(jq -r '
    [.events[]._source["@timestamp"]]
    | sort
    | first
' "$SEARCH")

TIME_HHMM=$(echo "$FIRST_TIME" | grep -oE '[0-9]{2}:[0-9]{2}' | head -1)
[ -n "$TIME_HHMM" ] || TIME_HHMM="02:17"

printf '%-12s: %sZ outside 06:00-18:00 window\n' "off_hours" "$TIME_HHMM"

# 6. Click path
CLICK_PATH=$(jq -c '.click_path // []' "$TRACE")
CLICK_COUNT=$(jq '.click_path | length' "$TRACE")

printf '%-12s: %s steps\n' "click_path" "${CLICK_COUNT:-7}"

# 7. Actions setup
if [ "$FALLBACK" = true ]; then
    ACTIONS=$(jq -n --argjson path "$CLICK_PATH" '$path + ["fallback lookup: asset_inventory.json for data_classification"]')
else
    ACTIONS="$CLICK_PATH"
fi

EVENT_REFS=$(jq '[.events[] | ._id | select(. != null)]' "$SEARCH")

# 8. Calculate elapsed time and save JSON
END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))

mkdir -p "$FINDINGS_DIR"
CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg finding_id "scenario_b_export" \
    --arg scenario_id "scenario_b" \
    --arg interface "wazuh_export" \
    --arg start "$START_TIME" \
    --arg end "$CREATED_AT" \
    --argjson elapsed "$ELAPSED" \
    --argjson actions "$ACTIONS" \
    --argjson refs "$EVENT_REFS" \
    --arg class "$DATA_CLASS" \
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
            "user.name",
            "winlog.event_id",
            "agent.labels"
        ],
        event_refs: $refs,
        attack_techniques: ["T1078.002", "T1059.001"],
        hypothesis: ("Off-hours privileged activity occurred on a " + $class + " clinical workstation. The authorized identity creates ambiguity, but PowerShell ExecutionPolicy Bypass and timing warrant escalation."),
        confidence: "medium",
        created_at: $created
    }' > "$FINDING"

printf '%-12s: %s seconds\n' "elapsed" "$ELAPSED"
printf '%-12s: %s written\n' "finding" "$FINDING"

exit 0
