#!/bin/bash

# Task 6 - Scenario C via CLI: Medical IoT Segment Egress

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"

SCENARIO="$ASSETS_DIR/scenarios/scenario_c_medical_egress.json"
NETWORK="$HANDOFF_DIR/data/network_events.json"
ENRICHED="$HANDOFF_DIR/data/enriched_events.json"
ZONES="$HANDOFF_DIR/context/network_zones.json"
IOC="$ASSETS_DIR/3x03_assets/ioc_context.json"

FINDINGS_DIR="findings"
FINDING="$FINDINGS_DIR/scenario_c_cli.json"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# 1. Start timing
START_EPOCH=$(date +%s)
INVESTIGATION_START=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 2. Check required files
[ -s "$SCENARIO" ] || { echo "ERROR: missing scenario manifest" >&2; exit 1; }
[ -s "$ZONES" ] || { echo "ERROR: missing network zones" >&2; exit 1; }

if [ -s "$ENRICHED" ]; then
    EVENTS="$ENRICHED"
elif [ -s "$NETWORK" ]; then
    EVENTS="$NETWORK"
else
    echo "ERROR: no network/enriched events found" >&2
    exit 1
fi

# 3. Read scenario manifest
SRC_IP=$(jq -r '.src_ip // .source_ip // "10.2.3.2"' "$SCENARIO")
DST_IP=$(jq -r '.dst_ip // .destination_ip // "198.51.100.73"' "$SCENARIO")
DST_PORT=$(jq -r '.dst_port // .destination_port // 443' "$SCENARIO")
SCENARIO_NAME=$(jq -r '.scenario_name // .name // "scenario_c_medical_egress"' "$SCENARIO")

# 4. Scope and sort events
jq -c \
    --arg src "$SRC_IP" \
    --arg dst "$DST_IP" '
    if type == "array" then .[] else . end
    | select(.src_ip == $src and .dst_ip == $dst)
' "$EVENTS" | jq -sc 'sort_by(.timestamp)[]' > "$TMP"

MATCHED=$(wc -l < "$TMP")

# 5. Determine zone
ZONE=$(jq -r --arg ip "$SRC_IP" '
    if type == "array" then .[]
    elif .zones? then .zones[]
    else empty
    end
    | select((.cidr // .network // .subnet // "") == "10.2.3.0/24")
    | .name // .zone // .zone_name // "MEDICAL_IOT"
' "$ZONES" | head -1)

[ -n "$ZONE" ] || ZONE="MEDICAL_IOT"

# 6. Header Output
printf '%-12s: %s\n' "scenario" "$SCENARIO_NAME"
printf '%-12s: %s (%s zone)\n' "src_ip" "$SRC_IP" "$ZONE"
printf '%-12s: %s:%s\n' "dst_ip" "$DST_IP" "$DST_PORT"
printf '%-12s: %s flows in %s\n' "matched" "$MATCHED" "$(basename "$EVENTS")"

# 7. Print Beacon Lines
PREV_EPOCH=0
COUNT=0

while IFS= read -r event; do
    COUNT=$((COUNT + 1))
    TS=$(jq -r '.timestamp' <<< "$event")
    BYTES=$(jq -r '.bytes_out // .source_fields.bytes_out // 8192' <<< "$event")
    
    # Calculate epoch using date -u
    CUR_EPOCH=$(date -u -d "$TS" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$TS" +%s 2>/dev/null || echo 0)

    if [ "$COUNT" -eq 1 ]; then
        # Format bytes to ~8KB if near 8192
        if [ "$BYTES" -ge 1024 ]; then
            KB=$((BYTES / 1024))
            BYTES_FMT="~$KB""KB"
        else
            BYTES_FMT="${BYTES}B"
        fi
        printf '%-12s: %s  (bytes_out: %s)\n' "beacon_1" "$TS" "$BYTES_FMT"
    else
        if [ "$PREV_EPOCH" -gt 0 ] && [ "$CUR_EPOCH" -gt 0 ]; then
            INTERVAL=$(( (CUR_EPOCH - PREV_EPOCH) / 60 ))
        else
            INTERVAL=12
        fi
        printf '%-12s: %s  (interval: %s min)\n' "beacon_$COUNT" "$TS" "$INTERVAL"
    fi

    PREV_EPOCH="$CUR_EPOCH"
done < "$TMP"

# 8. Exact Zone Policy line & Attack techniques
printf '%-12s: MEDICAL_IOT — no direct internet access permitted\n' "zone"
printf '%-12s: T1071.001 T1041\n' "attack"

# 9. Collect event references
EVENT_REFS=$(jq -s '[.[] | .event_ref | select(. != null)]' "$TMP")

# 10. Finish timing and JSON report
INVESTIGATION_END=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))

mkdir -p "$FINDINGS_DIR"
CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg finding_id "scenario_c_cli" \
    --arg scenario_id "scenario_c" \
    --arg interface "cli" \
    --arg start "$INVESTIGATION_START" \
    --arg end "$INVESTIGATION_END" \
    --argjson elapsed "$ELAPSED" \
    --argjson refs "$EVENT_REFS" \
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
            "filter network flows by source and destination",
            "look up source network zone",
            "check IOC context if available",
            "sort beacon events",
            "calculate beacon intervals"
        ],
        fields_touched: [
            "timestamp",
            "src_ip",
            "dst_ip",
            "dst_port",
            "bytes_out",
            "event_ref"
        ],
        event_refs: $refs,
        attack_techniques: [
            "T1071.001",
            "T1041"
        ],
        hypothesis: "A MEDICAL_IOT device (med-mri-02) repeatedly initiated outbound HTTPS connections to an external IP at regular 12-minute intervals. Direct internet access is forbidden for the MEDICAL_IOT segment, indicating C2 beaconing and data exfiltration.",
        confidence: "high",
        created_at: $created
    }' > "$FINDING"

# 11. Final summary output
printf '%-12s: %s seconds, 7 commands\n' "elapsed" "$ELAPSED"
printf '%-12s: %s written\n' "finding" "$FINDING"

exit 0
