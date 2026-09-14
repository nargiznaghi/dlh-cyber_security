#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
RISK_REGISTER="${ASSETS_DIR}/risk_register.json"
RULE_QUALITY="rule_quality.json"
ATTACK_COVERAGE="attack_coverage.json"
OUTPUT_JSON="rule_prioritization.json"

python3 -c "
import os, json, glob, yaml

assets_dir = '$ASSETS_DIR'
risk_reg_path = '$RISK_REGISTER'
rule_quality_path = '$RULE_QUALITY'
attack_coverage_path = '$ATTACK_COVERAGE'
output_json = '$OUTPUT_JSON'

# Load Risk Register
scenarios = []
if os.path.exists(risk_reg_path):
    with open(risk_reg_path) as f:
        data = json.load(f)
        scenarios = data if isinstance(data, list) else data.get('scenarios', [])

# Load Rule Quality
rule_quality = {}
if os.path.exists(rule_quality_path):
    with open(rule_quality_path) as f:
        for item in json.load(f):
            rule_quality[item.get('rule_id')] = item

# Load Attack Coverage mapping (if available)
attack_coverage = {}
if os.path.exists(attack_coverage_path):
    with open(attack_coverage_path) as f:
        attack_coverage = json.load(f)

# Collect rules and tags from YAML files
rule_files = glob.glob('rules/sigma/*.yml') + glob.glob('rules/sigma/tuned/*.yml')
rules = {}

for r in rule_files:
    name = os.path.basename(r).replace('.yml', '')
    with open(r) as f:
        data = yaml.safe_load(f) or {}
    
    rule_id = data.get('id', name)
    tags = data.get('tags', [])
    techniques = set()
    for t in tags:
        if t.startswith('attack.t') or t.startswith('attack.T'):
            # Convert attack.t1059.001 -> T1059.001
            tech = t.replace('attack.', '').upper()
            techniques.add(tech)
            techniques.add(tech.split('.')[0]) # also add base technique like T1059

    rules[rule_id] = {
        'rule_id': rule_id,
        'rule_name': name,
        'rule_title': data.get('title', name),
        'level': data.get('level', 'medium'),
        'techniques': list(techniques)
    }

prioritized = []

for rule_id, rdata in rules.items():
    q = rule_quality.get(rule_id, {})
    f1 = q.get('f1', 0.0)
    
    rule_techs = set(rdata['techniques'])
    
    # Compute Risk Score
    risk_score = 0.0
    covering_scenarios = []
    
    for sc in scenarios:
        sc_techs = set([t.upper() for t in sc.get('techniques', [])])
        if rule_techs.intersection(sc_techs):
            l = sc.get('likelihood', 1)
            imp = sc.get('impact', 1)
            risk_score += (l * imp)
            covering_scenarios.append(sc.get('id') or sc.get('name', ''))

    # Priority score calculation
    if f1 > 0:
        priority_score = risk_score * f1
    else:
        priority_score = risk_score * 0.1

    prioritized.append({
        'rule_id': rule_id,
        'rule_name': rdata['rule_name'],
        'rule_title': rdata['rule_title'],
        'risk_score': round(risk_score, 1),
        'f1': round(f1, 2),
        'priority_score': round(priority_score, 1),
        'covering_scenarios': covering_scenarios,
        'level': rdata['level']
    })

# Save output JSON
with open(output_json, 'w') as f:
    json.dump(prioritized, f, indent=2)

# Sort by priority_score descending
prioritized.sort(key=lambda x: x['priority_score'], reverse=True)

active_rules = [r for r in prioritized if r['priority_score'] > 0]
orphan_rules = [r for r in prioritized if r['priority_score'] == 0]

print('top 10 rules by priority_score')
for idx, r in enumerate(active_rules[:10], 1):
    print(f\"{idx:>2}  {r['priority_score']:>4.1f}  {r['rule_name']}\")

print(f\"orphan rules (no risk scenario covers) : {len(orphan_rules)}\")
print('rule_prioritization.json written')
"
