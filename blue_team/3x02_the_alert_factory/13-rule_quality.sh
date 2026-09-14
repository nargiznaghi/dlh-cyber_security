#!/bin/bash

BASELINE_DIR="${BASELINE_PKG:-.}"
RULES_DIR="rules/sigma"
TUNED_DIR="rules/sigma/tuned"
OUTPUT_JSON="rule_quality.json"
FP_BASELINE_JSON="fp_baseline.json"

echo "evaluating rules against labeled ground truth"

python3 -c "
import os, glob, json, yaml

baseline_dir = '$BASELINE_DIR'
fp_baseline_file = '$FP_BASELINE_JSON'

# 1. Load ground truth references
gt_events = set()
anomalies_path = os.path.join(baseline_dir, 'anomalies', 'ranked_anomalies.json')
labeled_path = os.path.join(baseline_dir, 'taxonomy', 'labeled_events.json')

if os.path.exists(anomalies_path):
    with open(anomalies_path) as f:
        data = json.load(f)
        items = data if isinstance(data, list) else data.get('anomalies', [])
        for item in items:
            ref = item.get('event_id') or item.get('id') or item.get('event_ref')
            if ref: gt_events.add(str(ref))

if os.path.exists(labeled_path):
    with open(labeled_path) as f:
        data = json.load(f)
        items = data if isinstance(data, list) else data.get('events', [])
        for item in items:
            if item.get('label') in ['malicious', 'true_positive', True]:
                ref = item.get('event_id') or item.get('id') or item.get('event_ref')
                if ref: gt_events.add(str(ref))

# Load FP counts from baseline step
fp_baseline_map = {}
if os.path.exists(fp_baseline_file):
    with open(fp_baseline_file) as f:
        for entry in json.load(f):
            fp_baseline_map[entry.get('rule_id')] = entry.get('fp_count', 0)

# Collect rules from rules/sigma/ and rules/sigma/tuned/
rule_files = {}
for r in glob.glob('rules/sigma/*.yml') + glob.glob('rules/sigma/tuned/*.yml'):
    name = os.path.basename(r).replace('.yml', '')
    rule_files[name] = r

results = []

for name, filepath in sorted(rule_files.items()):
    with open(filepath) as f:
        rule_data = yaml.safe_load(f) or {}
    
    rule_id = rule_data.get('id', '')
    title = rule_data.get('title', name)
    level = rule_data.get('level', 'medium')

    # Execute runner to get matches
    import subprocess
    cmd = f'./3-sigma_runner.sh \"{filepath}\"'
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode('utf-8')
        matches = json.loads(out)
    except Exception:
        matches = []

    tp_count = 0
    fp_eval = 0

    for m in matches:
        ref = str(m.get('event_id') or m.get('id') or m.get('event_ref') or '')
        if ref in gt_events:
            tp_count += 1
        else:
            fp_eval += 1

    fp_count = fp_eval + fp_baseline_map.get(rule_id, 0)
    
    # Estimate fn_count based on ground truth category match or general expected count
    category_gt = len(gt_events) if len(gt_events) > 0 else 5
    fn_count = max(0, category_gt - tp_count)

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    results.append({
        'rule_name': name,
        'rule_id': rule_id,
        'rule_title': title,
        'level': level,
        'tp_count': tp_count,
        'fp_count': fp_count,
        'fn_count': fn_count,
        'precision': round(precision, 2),
        'recall': round(recall, 2),
        'f1': round(f1, 2)
    })

# Save results to JSON
with open('$OUTPUT_JSON', 'w') as f:
    json.dump(results, f, indent=2)

# Sort by F1 score descending
results.sort(key=lambda x: x['f1'], reverse=True)

strongest = results[:5]
weakest = results[-5:] if len(results) >= 5 else results

print('strongest')
for r in strongest:
    tag = '  [STRONG]' if r['f1'] >= 0.7 else ('  [WEAK]' if r['f1'] < 0.3 else '')
    print(f\"  {r['rule_name']:<30} f1={r['f1']:.2f}  p={r['precision']:.2f} r={r['recall']:.2f}{tag}\")

print('weakest')
for r in weakest:
    tag = '  [STRONG]' if r['f1'] >= 0.7 else ('  [WEAK]' if r['f1'] < 0.3 else '')
    print(f\"  {r['rule_name']:<30} f1={r['f1']:.2f}  p={r['precision']:.2f} r={r['recall']:.2f}{tag}\")

print('rule_quality.json written')
"
