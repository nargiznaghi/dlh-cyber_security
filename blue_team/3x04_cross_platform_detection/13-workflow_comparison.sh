#!/bin/bash

# Task 13 - Workflow Comparison

FINDINGS_DIR="${FINDINGS_DIR:-findings}"
OUT_DIR="comparison"
OUT="$OUT_DIR/workflow_comparison.json"

mkdir -p "$OUT_DIR"

# 1. Resolve finding file paths safely
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

FILES=()
for scenario in anchor scenario_a scenario_b scenario_c; do
    for iface in cli export; do
        filepath=$(get_finding "$scenario" "$iface")
        if [ -z "$filepath" ] || [ ! -s "$filepath" ]; then
            echo "ERROR: missing finding JSON file for ${scenario} (${iface})" >&2
            exit 1
        fi
        FILES+=("$filepath")
    done
done

# 2. Process with JQ (matching both 'export' and 'wazuh_export' interface values)
jq -s '
    def median:
        sort as $a |
        ($a | length) as $n |
        if $n == 0 then 0
        elif ($n % 2) == 1 then
            $a[($n / 2 | floor)]
        else
            (($a[$n/2 - 1] + $a[$n/2]) / 2)
        end;

    # Normalize interface name check
    def is_cli: .interface == "cli";
    def is_export: .interface == "wazuh_export" or .interface == "export";

    def interface_stats($type):
        [.[] | select(if $type == "cli" then is_cli else is_export end)] as $x |
        {
            finding_count: ($x | length),
            time_to_first_answer_seconds: {
                total: ([$x[].time_to_first_answer_seconds] | add),
                average: (([$x[].time_to_first_answer_seconds] | add) / ($x | length)),
                median: ([$x[].time_to_first_answer_seconds] | median)
            },
            action_count: {
                total: ([$x[] | (.actions | length)] | add),
                average: (([$x[] | (.actions | length)] | add) / ($x | length))
            },
            fields_touched_count: {
                total: ([$x[] | (.fields_touched | length)] | add),
                average: (([$x[] | (.fields_touched | length)] | add) / ($x | length))
            },
            event_refs_count: {
                total: ([$x[] | (.event_refs | length)] | add),
                average: (([$x[] | (.event_refs | length)] | add) / ($x | length))
            }
        };

    def scenario($id):
        ([.[] | select(.scenario_id == $id and is_cli)][0]) as $c |
        ([.[] | select(.scenario_id == $id and is_export)][0]) as $w |
        {
            scenario_id: $id,
            cli_seconds: $c.time_to_first_answer_seconds,
            wazuh_export_seconds: $w.time_to_first_answer_seconds,
            delta_wazuh_export_minus_cli: ($w.time_to_first_answer_seconds - $c.time_to_first_answer_seconds),
            cli_actions: ($c.actions | length),
            wazuh_export_actions: ($w.actions | length)
        };

    {
        per_interface: {
            cli: interface_stats("cli"),
            wazuh_export: interface_stats("wazuh_export")
        },
        per_scenario: [
            scenario("anchor"),
            scenario("scenario_a"),
            scenario("scenario_b"),
            scenario("scenario_c")
        ],
        confidence_distribution: {
            cli: {
                low: ([.[] | select(is_cli and .confidence=="low")] | length),
                medium: ([.[] | select(is_cli and .confidence=="medium")] | length),
                high: ([.[] | select(is_cli and .confidence=="high")] | length)
            },
            wazuh_export: {
                low: ([.[] | select(is_export and .confidence=="low")] | length),
                medium: ([.[] | select(is_export and .confidence=="medium")] | length),
                high: ([.[] | select(is_export and .confidence=="high")] | length)
            }
        },
        generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
    }
' "${FILES[@]}" > "$OUT"

# 3. Print Expected Terminal Summary
echo "findings loaded       : 8 (4 cli + 4 wazuh_export)"
echo "per interface totals:"

CLI_TOT=$(jq '.per_interface.cli.time_to_first_answer_seconds.total' "$OUT")
CLI_AVG=$(jq '.per_interface.cli.time_to_first_answer_seconds.average | floor' "$OUT")
CLI_MED=$(jq '.per_interface.cli.time_to_first_answer_seconds.median' "$OUT")
CLI_ACT=$(jq '.per_interface.cli.action_count.total' "$OUT")
printf '  %-12s: %ss total, avg %ss, median %ss, %s actions\n' "cli" "$CLI_TOT" "$CLI_AVG" "$CLI_MED" "$CLI_ACT"

EXP_TOT=$(jq '.per_interface.wazuh_export.time_to_first_answer_seconds.total' "$OUT")
EXP_AVG=$(jq '.per_interface.wazuh_export.time_to_first_answer_seconds.average | floor' "$OUT")
EXP_MED=$(jq '.per_interface.wazuh_export.time_to_first_answer_seconds.median' "$OUT")
EXP_ACT=$(jq '.per_interface.wazuh_export.action_count.total' "$OUT")
printf '  %-12s: %ss total, avg %ss, median %ss, %s actions\n' "wazuh_export" "$EXP_TOT" "$EXP_AVG" "$EXP_MED" "$EXP_ACT"

echo "per interface confidence:"
CLI_H=$(jq '.confidence_distribution.cli.high' "$OUT")
CLI_M=$(jq '.confidence_distribution.cli.medium' "$OUT")
CLI_L=$(jq '.confidence_distribution.cli.low' "$OUT")
printf '  %-12s: high=%s medium=%s low=%s\n' "cli" "$CLI_H" "$CLI_M" "$CLI_L"

EXP_H=$(jq '.confidence_distribution.wazuh_export.high' "$OUT")
EXP_M=$(jq '.confidence_distribution.wazuh_export.medium' "$OUT")
EXP_L=$(jq '.confidence_distribution.wazuh_export.low' "$OUT")
printf '  %-12s: high=%s medium=%s low=%s\n' "wazuh_export" "$EXP_H" "$EXP_M" "$EXP_L"

echo "per scenario deltas (wazuh_export - cli):"

jq -c '.per_scenario[]' "$OUT" | while read -r item; do
    id=$(echo "$item" | jq -r '.scenario_id')
    delta=$(echo "$item" | jq -r '.delta_wazuh_export_minus_cli')
    
    if [ "$delta" -lt 0 ]; then
        printf '  %-10s: %ss (wazuh_export faster)\n' "$id" "$delta"
    elif [ "$delta" -gt 0 ]; then
        printf '  %-10s: +%ss (cli faster)\n' "$id" "$delta"
    else
        printf '  %-10s: 0s (tie)\n' "$id"
    fi
done

echo "$OUT written"
exit 0
