#!/bin/bash

BASELINE_SUMMARY="${BASELINE_PKG:-.}/baselines/baseline_summary.json"
RULES_DIR="rules/sigma"
OUTPUT_JSON="fp_baseline.json"

# Python vasitəsilə baseline pəncərəsinin tarixlərini götürürük
eval $(python3 -c "
import json, os
path = '$BASELINE_SUMMARY'
if not os.path.exists(path):
    path = 'baselines/baseline_summary.json'
with open(path) as f:
    data = json.load(f)
print(f'START_DATE={data.get(\"start_date\", \"2026-03-18\")}')
print(f'END_DATE={data.get(\"end_date\", \"2026-03-24\")}')
")

echo "evaluating rules against baseline window $START_DATE -> $END_DATE"

# JSON array-i başlatmaq üçün
python3 -c "import json; open('$OUTPUT_JSON', 'w').write(json.dumps([]))"

for rule in $(ls $RULES_DIR/*.yml | sort); do
    rule_name=$(basename "$rule" .yml)
    
    # Sigma runner-i çağırıb match count alırıq
    count=$(./3-sigma_runner.sh "$rule" --window "$START_DATE" "$END_DATE" --count-only 2>/dev/null | tr -d '[:space:]')
    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        count=0
    fi

    # Qayda haqqında əlavə məlumatları (id, title, level) götürürük
    eval $(python3 -c "
import yaml, json
with open('$rule') as f:
    data = yaml.safe_load(f) or {}
print(f'RULE_ID=\"{data.get(\"id\", \"\")}\"')
print(f'RULE_TITLE=\"{data.get(\"title\", \"\")}\"')
print(f'RULE_LEVEL=\"{data.get(\"level\", \"high\")}\"')
")

    # Day count (7 gün üçün fp_rate_per_day)
    fp_rate=$(python3 -c "print(round($count / 7.0, 2))")

    # JSON faylına əlavə edirik
    python3 -c "
import json
with open('$OUTPUT_JSON', 'r+') as f:
    data = json.load(f)
    data.append({
        'rule_id': '$RULE_ID',
        'rule_title': '''$RULE_TITLE''',
        'level': '$RULE_LEVEL',
        'fp_count': $count,
        'baseline_window_start': '$START_DATE',
        'baseline_window_end': '$END_DATE',
        'fp_rate_per_day': $fp_rate
    })
    f.seek(0)
    json.dump(data, f, indent=2)
    f.truncate()
"

    # Ekrana formatlanmış çıxış
    if [ "$count" -gt 10 ]; then
        printf "  %-32s fp=%3d   [TUNE]\n" "$rule_name" "$count"
    else
        printf "  %-32s fp=%3d\n" "$rule_name" "$count"
    fi
done

echo "fp_baseline.json written"
