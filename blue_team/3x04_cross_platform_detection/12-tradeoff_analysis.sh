#!/bin/bash

# Task 12 - Structured Trade-off Analysis

FINDINGS_DIR="${FINDINGS_DIR:-findings}"
OUT_DIR="comparison"

mkdir -p "$OUT_DIR"

JSON_OUT="$OUT_DIR/tradeoff_table.json"
MD_OUT="$OUT_DIR/tradeoff_table.md"

# 1. Resolve file path fallback helper
get_finding() {
    local scenario="$1"
    local iface="$2"
    if [ -s "$FINDINGS_DIR/${scenario}_${iface}.json" ]; then
        echo "$FINDINGS_DIR/${scenario}_${iface}.json"
    elif [ -s "$FINDINGS_DIR/${scenario}_wazuh_${iface}.json" ]; then
        echo "$FINDINGS_DIR/${scenario}_wazuh_${iface}.json"
    else
        echo ""
    fi
}

ANCHOR_CLI=$(get_finding "anchor" "cli")
ANCHOR_EXP=$(get_finding "anchor" "export")
A_CLI=$(get_finding "scenario_a" "cli")
A_EXP=$(get_finding "scenario_a" "export")
B_CLI=$(get_finding "scenario_b" "cli")
B_EXP=$(get_finding "scenario_b" "export")
C_CLI=$(get_finding "scenario_c" "cli")
C_EXP=$(get_finding "scenario_c" "export")

# 2. Verify all files exist
for f in "$ANCHOR_CLI" "$ANCHOR_EXP" "$A_CLI" "$A_EXP" "$B_CLI" "$B_EXP" "$C_CLI" "$C_EXP"; do
    if [ -z "$f" ] || [ ! -s "$f" ]; then
        echo "ERROR: Missing required finding JSON file." >&2
        exit 1
    fi
done

# 3. Generate JSON Trade-off Table
jq -n \
    --slurpfile anchor_cli "$ANCHOR_CLI" \
    --slurpfile anchor_exp "$ANCHOR_EXP" \
    --slurpfile a_cli "$A_CLI" \
    --slurpfile a_exp "$A_EXP" \
    --slurpfile b_cli "$B_CLI" \
    --slurpfile b_exp "$B_EXP" \
    --slurpfile c_cli "$C_CLI" \
    --slurpfile c_exp "$C_EXP" '

    def row($name; $cli; $exp; $cause_cli; $cause_exp):
        ($cli.time_to_first_answer_seconds) as $ct |
        ($exp.time_to_first_answer_seconds) as $et |
        ($cli.actions | length) as $ca |
        ($exp.actions | length) as $ea |

        {
            scenario_id: $name,
            cli_time_seconds: $ct,
            wazuh_export_time_seconds: $et,
            time_delta_export_minus_cli: ($et - $ct),

            cli_actions: $ca,
            wazuh_export_actions: $ea,
            action_delta_export_minus_cli: ($ea - $ca),

            faster_interface: (
                if $ct < $et then "cli"
                elif $et < $ct then "wazuh_export"
                else "tie"
                end
            ),

            advantage_cause: (
                if $ct < $et then $cause_cli
                elif $et < $ct then $cause_exp
                else "reproducibility"
                end
            )
        };

    [
        row("anchor", $anchor_cli[0], $anchor_exp[0], "text_speed_iteration", "filter_bar_efficiency"),
        row("scenario_a", $a_cli[0], $a_exp[0], "pipeline_expressiveness", "timeline_visualization"),
        row("scenario_b", $b_cli[0], $b_exp[0], "context_join_ergonomics", "native_field_surface"),
        row("scenario_c", $c_cli[0], $c_exp[0], "pipeline_expressiveness", "native_field_surface")
    ]
' > "$JSON_OUT"

# 4. Generate Markdown Trade-off Table
{
    echo "# Cross-Platform Trade-off Table"
    echo ""
    echo "| Scenario | CLI Time (s) | Export Time (s) | Time Delta (s) | CLI Actions | Export Actions | Action Delta | Faster Interface | Advantage Cause |"
    echo "|---|---:|---:|---:|---:|---:|---:|---|---|";
    jq -r '
        .[]
        | "| \(.scenario_id) | \(.cli_time_seconds) | \(.wazuh_export_time_seconds) | \(.time_delta_export_minus_cli) | \(.cli_actions) | \(.wazuh_export_actions) | \(.action_delta_export_minus_cli) | \(.faster_interface) | \(.advantage_cause) |"
    ' "$JSON_OUT"
} > "$MD_OUT"

# 5. Output Summary
SCENARIOS=$(jq 'length' "$JSON_OUT")
EXPORT_WINS=$(jq '[.[] | select(.faster_interface=="wazuh_export")] | length' "$JSON_OUT")
CLI_WINS=$(jq '[.[] | select(.faster_interface=="cli")] | length' "$JSON_OUT")

printf '%-20s: %s (anchor + 3)\n' "scenarios analyzed" "$SCENARIOS"
printf '%-20s: %s\n' "export advantages" "$EXPORT_WINS"
printf '%-20s: %s\n' "cli advantages" "$CLI_WINS"
echo "$JSON_OUT written"
echo "$MD_OUT written"

exit 0
