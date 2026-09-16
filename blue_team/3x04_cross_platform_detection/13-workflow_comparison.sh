#!/bin/bash

# Task 13 - Workflow Comparison

FINDINGS_DIR="${FINDINGS_DIR:-findings}"
OUT_DIR="comparison"
OUT="$OUT_DIR/workflow_comparison.json"

mkdir -p "$OUT_DIR"

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

FILES=(
    $(get_finding "anchor" "cli")
    $(get_finding "anchor" "export")
    $(get_finding "scenario_a" "cli")
    $(get_finding "scenario_a" "export")
    $(get_finding "scenario_b" "cli")
    $(get_finding "scenario_b" "export")
    $(get_finding "scenario_c" "cli")
    $(get_finding "scenario_c" "export")
)

for file in "${FILES[@]}"; do
    if [ -z "$file" ] || [ ! -s "$file" ]; then
        echo "ERROR: missing finding JSON file" >&2
        exit 1
    fi
done

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

    def interface_stats($name):
        [.[] | select(.interface == $name)] as $x |
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
        ([.[] | select(.scenario_id == $id and .interface == "cli")][0]) as $c |
        ([.[] | select(.scenario_id == $id and .interface == "wazuh_export")][0]) as $w |
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
                low: ([.[] | select(.interface=="cli" and .confidence=="low")] | length),
                medium: ([.[] | select(.interface=="cli" and .confidence=="medium")] | length),
                high: ([.[] | select(.interface=="cli" and .confidence=="high")] | length)
            },
            wazuh_export: {
                low: ([.[] | select(.interface=="wazuh_export" and .confidence=="low")] | length),
                medium: ([.[] | select(.interface=="wazuh_export" and .confidence=="medium")] | length),
                high: ([.[] | select(.interface=="wazuh_export" and .confidence=="high")] | length)
            }
        },
        generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
    }
' "${FILES[@]}" > "$OUT"

# Formatting exact Expected Output
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

jq -r '
    .per_scenario[] |
    if .delta_wazuh_export_minus_cli < 0 then
        "  \(.scenario_id | rpad(10)): \(.delta_wazuh_export_minus_cli)s (wazuh_export faster)"
    elif .delta_wazuh_export_minus_cli > 0 then
        "  \(.scenario_id | rpad(10)): +\(.delta_wazuh_export_minus_cli)s (cli faster)"
    else
        "  \(.scenario_id | rpad(10)): 0s (tie)"
    end
' "$OUT" 2>/dev/null || jq -r '
    .per_scenario[] |
    .scenario_id as $id |
    .delta_wazuh_export_minus_cli as $d |
    (if $d < 0 then "\($d)s (wazuh_export faster)" elif $d > 0 then "+\($d)s (cli faster)" else "0s (tie)" end) as $str |
    "  \($id)      : \($str)"
' "$OUT" | sed 's/  \(anchor\|scenario_a\|scenario_b\|scenario_c\)  */  \1      : /' | awk -F':' '{printf "  %-10s: %s\n", $1, $2}' | sed 's/  \(.*\)      :/  \1:/'

echo "$OUT written"

exit 0
