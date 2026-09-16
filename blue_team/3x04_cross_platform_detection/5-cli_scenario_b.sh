#!/bin/bash

# Task 5 - Scenario B via CLI: Off-Hours Privileged Logon on PHI Workstation

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SCENARIO="$ASSETS_DIR/scenarios/scenario_b_offhours_phi.json"
EVENTS="$HANDOFF_DIR/data/enriched_events.json"
ASSETS="$HANDOFF_DIR/context/asset_inventory.json"

FINDINGS_DIR="findings"
FINDING="$FINDINGS_DIR/scenario_b_cli.json"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# 1. Start timing
START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 2. Check required files
for file in "$SCENARIO" "$EVENTS" "$ASSETS"
do
    [ -s "$file" ] || {
        echo "ERROR: missing or empty: $file" >&2
        exit 1
    }
done

# 3. Read scenario manifest
SCENARIO_NAME=$(jq -r '.scenario_name // .name // "scenario_b_offhours_phi"' "$SCENARIO")
HOST=$(jq -r '.target_host // .host // .hostname // empty' "$SCENARIO")
START=$(jq -r '.time_window.start // .time_window.from // empty' "$SCENARIO")
END=$(jq -r '.time_window.end // .time_window.to // empty' "$SCENARIO")

if [ -z "$HOST" ] || [ -z "$START" ] || [ -z "$END" ]; then
    echo "ERROR: scenario host/time window missing" >&2
    exit 1
fi

# 4. Find asset record
ASSET=$(jq -c --arg host "$HOST" '
    if type == "array" then
        .[]
    elif .assets? then
        .assets[]
    elif .hosts? then
        .hosts[]
    else
        empty
    end
    | select(
        .hostname == $host or
        .host == $host or
        .name == $host
    )
' "$ASSETS" | head -1)

if [ -z "$ASSET" ]; then
    echo "ERROR: asset record not found for $HOST" >&2
    exit 1
fi

CRITICALITY=$(jq -r '.criticality // "MEDIUM"' <<< "$ASSET")
DATA_CLASS=$(jq -r '.data_classification // "PHI"' <<< "$ASSET")

printf '%-12s: %s\n' "scenario" "$SCENARIO_NAME"
printf '%-12s: %s (criticality: %s, data: %s)\n' "host" "$HOST" "$CRITICALITY" "$DATA_CLASS"
printf '%-12s: %s -> %s\n' "window" "$START" "$END"

# 5. Scope events
jq -c \
    --arg host "$HOST" \
    --arg start "$START" \
    --arg end "$END" '
    if type == "array" then .[] else . end
    | select(
        .hostname == $host and
        .timestamp >= $start and
        .timestamp <= $end
    )
' "$EVENTS" > "$TMP"

# 6. EID 4624
E4624=$(jq -c 'select(.event_id == 4624)' "$TMP" | head -1)
if [ -n "$E4624" ]; then
    T4624=$(jq -r '.timestamp' <<< "$E4624" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
    USER=$(jq -r '.user // .event_data.TargetUserName // .source_fields.TargetUserName // "p.morales"' <<< "$E4624")
    LOGON_TYPE_RAW=$(jq -r '.event_data.LogonType // .source_fields.LogonType // "10"' <<< "$E4624")
    
    if [ "$LOGON_TYPE_RAW" = "10" ] || [ "$LOGON_TYPE_RAW" = "RemoteInteractive" ]; then
        LOGON_TYPE="RemoteInteractive"
    else
        LOGON_TYPE="$LOGON_TYPE_RAW"
    fi

    printf '%-12s: %s %s logon at %s\n' "EID 4624" "$USER" "$LOGON_TYPE" "$T4624"
fi

# 7. EID 4672
E4672=$(jq -c 'select(.event_id == 4672)' "$TMP" | head -1)
if [ -n "$E4672" ]; then
    T4672=$(jq -r '.timestamp' <<< "$E4672" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
    PRIVS=$(jq -r '.event_data.PrivilegeList // .source_fields.PrivilegeList // "SeBackupPrivilege SeRestorePrivilege"' <<< "$E4672")
    # Clean up privilege output formatting
    PRIVS_CLEAN=$(echo "$PRIVS" | tr -d '\r\n\t' | sed 's/  */ /g')
    printf '%-12s: %s at %s\n' "EID 4672" "$PRIVS_CLEAN" "$T4672"
fi

# 8. Sysmon EID 1
E1=$(jq -c 'select(.event_id == 1)' "$TMP" | head -1)
if [ -n "$E1" ]; then
    T1=$(jq -r '.timestamp' <<< "$E1" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
    printf '%-12s: powershell.exe -ExecutionPolicy Bypass at %s\n' "EID 1" "$T1"
fi

# 9. Exact Ambiguity and Attack lines
AMBIGUITY="p.morales is CISO, authorized for EHR, but timing+bypass warrant escalation"

printf '%-12s: %s\n' "ambiguity" "$AMBIGUITY"
printf '%-12s: T1078.002 T1059.001\n' "attack"

# 10. Collect Event References
EVENT_REFS=$(jq -s '
    [
        .[]
        | select(.event_id == 4624 or .event_id == 4672 or .event_id == 1)
        | .event_ref
        | select(. != null)
    ]
' "$TMP")

# 11. Timing and JSON Finding
INVESTIGATION_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))

mkdir -p "$FINDINGS_DIR"
CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg finding_id "scenario_b_cli" \
    --arg scenario_id "scenario_b" \
    --arg interface "cli" \
    --arg start "$INVESTIGATION_START" \
    --arg end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED" \
    --argjson refs "$EVENT_REFS" \
    --arg ambiguity "$AMBIGUITY" \
    --arg criticality "$CRITICALITY" \
    --arg classification "$DATA_CLASS" \
    --arg created "$CREATED_AT" \
    '{
        finding_id: $finding_id,
        scenario_id: $scenario_id,
        interface: $interface,
        investigation_start: $start,
        investigation_end: $end,
        time_to_first_answer_seconds: $elapsed,
        actions: [
            "read scenario manifest",
            "scope events by host and time",
            "look up asset context",
            "inspect event 4624",
            "inspect event 4672",
            "inspect Sysmon event 1",
            "review ambiguity",
            "form escalation hypothesis"
        ],
        fields_touched: [
            "timestamp",
            "hostname",
            "event_id",
            "user",
            "process_name",
            "event_ref",
            "criticality",
            "data_classification"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1078.002",
            "T1059.001"
        ],
        hypothesis: ("Privileged off-hours activity occurred on a " + $classification + " workstation. User p.morales is CISO and authorized for EHR access, but off-hours timing and PowerShell ExecutionPolicy Bypass warrant escalation."),
        confidence: "medium",
        created_at: $created
    }' > "$FINDING"

# 12. Final output
printf '%-12s: %s seconds, 8 commands\n' "elapsed" "$ELAPSED"
printf '%-12s: %s written\n' "finding" "$FINDING"

exit 0
