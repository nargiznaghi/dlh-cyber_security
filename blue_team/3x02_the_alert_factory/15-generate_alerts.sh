#!/bin/bash

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x02_handoff}"
RULES_DIR="rules/sigma"
TUNED_DIR="rules/sigma/tuned"
PRIORITIZATION_JSON="rule_prioritization.json"
QUEUE_JSON="alert_queue.json"
SCHEMA_JSON="alert_queue_schema.json"

python3 -c "
import os, glob, json, yaml, hashlib, uuid, datetime

assets_dir = '$ASSETS_DIR'
handoff_dir = '$HANDOFF_DIR'
prio_file = '$PRIORITIZATION_JSON'

# Load Prioritization Data
prio_map = {}
if os.path.exists(prio_file):
    with open(prio_file) as f:
        for item in json.load(f):
            prio_map[item.get('rule_id')] = item.get('priority_score', 0.0)

# Load Asset Inventory
asset_inv = {}
asset_path = os.path.join(handoff_dir, 'context', 'asset_inventory.json')
if not os.path.exists(asset_path):
    asset_path = os.path.join(assets_dir, 'context', 'asset_inventory.json')

if os.path.exists(asset_path):
    with open(asset_path) as f:
        asset_data = json.load(f)
        items = asset_data if isinstance(asset_data, list) else asset_data.get('assets', [])
        for a in items:
            host = a.get('hostname') or a.get('ip')
            if host:
                asset_inv[host] = a

# Identify active rule files (prefer tuned variant if exists)
rule_files = {}
for r in glob.glob('rules/sigma/*.yml'):
    name = os.path.basename(r)
    rule_files[name] = r

for r in glob.glob('rules/sigma/tuned/*.yml'):
    name = os.path.basename(r)
    rule_files[name] = r # Overwrite with tuned variant

import subprocess

raw_alerts = []
total_rules = len(rule_files)

for name, rpath in rule_files.items():
    with open(rpath) as f:
        rdata = yaml.safe_load(f) or {}

    rule_id = rdata.get('id', name.replace('.yml', ''))
    rule_title = rdata.get('title', name)
    rule_level = rdata.get('level', 'medium')
    prio_score = prio_map.get(rule_id, 0.0)

    # Extract ATT&CK techniques from tags
    tags = rdata.get('tags', [])
    attack_techs = []
    for t in tags:
        if t.startswith('attack.t') or t.startswith('attack.T'):
            attack_techs.append(t.replace('attack.', '').upper())

    # Execute runner
    cmd = f'./3-sigma_runner.sh \"{rpath}\"'
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode('utf-8')
        matches = json.loads(out)
    except Exception:
        matches = []

    for m in matches:
        event_ref = str(m.get('event_id') or m.get('id') or m.get('event_ref') or uuid.uuid4())
        timestamp = m.get('timestamp') or m.get('@timestamp') or '2026-03-24T00:00:00Z'
        hostname = m.get('hostname') or m.get('host') or m.get('ComputerName') or 'unknown'
        user = m.get('user') or m.get('User') or m.get('UserName') or 'unknown'
        src_ip = m.get('src_ip') or m.get('SourceIp') or ''
        dst_ip = m.get('dst_ip') or m.get('DestinationIp') or ''
        process_name = m.get('process_name') or m.get('Image') or ''
        canonical_label = m.get('canonical_label') or ''
        event_category = m.get('event_category') or m.get('category') or ''

        # Deterministic UUID5 for alert_id
        ns = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
        alert_id = str(uuid.uuid5(ns, f'{rule_id}_{event_ref}'))

        # Evidence Hash
        raw_str = json.dumps(m, sort_keys=True)
        evidence_hash = hashlib.sha256(raw_str.encode('utf-8')).hexdigest()

        # Asset context
        host_ctx = asset_inv.get(hostname, {})

        alert = {
            'alert_id': alert_id,
            'generated_at': datetime.datetime.utcnow().isoformat() + 'Z',
            'rule_id': rule_id,
            'rule_name': name.replace('.yml', ''),
            'rule_title': rule_title,
            'rule_level': rule_level,
            'priority_score': prio_score,
            'event_ref': event_ref,
            'event_summary': {
                'timestamp': timestamp,
                'hostname': hostname,
                'user': user,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'process_name': process_name,
                'canonical_label': canonical_label,
                'event_category': event_category
            },
            'asset_context': host_ctx,
            'attack_techniques': attack_techs,
            'status': 'new',
            'evidence_hash': evidence_hash
        }
        raw_alerts.append(alert)

raw_matches_count = len(raw_alerts)

# Deduplication logic (60 seconds window per (rule_id, hostname, user))
deduped_alerts = []
seen = {}

def parse_ts(ts_str):
    try:
        return datetime.datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
    except Exception:
        return 0.0

# Sort by timestamp ascending for deduplication window processing
raw_alerts.sort(key=lambda x: parse_ts(x['event_summary']['timestamp']))

for alert in raw_alerts:
    key = (alert['rule_id'], alert['event_summary']['hostname'], alert['event_summary']['user'])
    ts = parse_ts(alert['event_summary']['timestamp'])
    
    if key in seen:
        prev_ts = seen[key]
        if abs(ts - prev_ts) < 60:
            continue # Skip duplicate within 60s
            
    seen[key] = ts
    deduped_alerts.append(alert)

# Sort descending by priority_score, tie-break by timestamp ascending
deduped_alerts.sort(key=lambda x: (-x['priority_score'], parse_ts(x['event_summary']['timestamp'])))

# Write alert_queue.json
with open('$QUEUE_JSON', 'w') as f:
    json.dump(deduped_alerts, f, indent=2)

# Write alert_queue_schema.json
schema = {
  '$schema': 'http://json-schema.org/draft-07/schema#',
  'title': 'AlertQueue',
  'type': 'array',
  'items': {
    'type': 'object',
    'required': [
      'alert_id', 'generated_at', 'rule_id', 'rule_title', 'rule_level',
      'priority_score', 'event_ref', 'event_summary', 'asset_context',
      'attack_techniques', 'status', 'evidence_hash'
    ],
    'properties': {
      'alert_id': {'type': 'string', 'format': 'uuid'},
      'generated_at': {'type': 'string', 'format': 'date-time'},
      'rule_id': {'type': 'string'},
      'rule_name': {'type': 'string'},
      'rule_title': {'type': 'string'},
      'rule_level': {'type': 'string'},
      'priority_score': {'type': 'number'},
      'event_ref': {'type': 'string'},
      'event_summary': {
        'type': 'object',
        'properties': {
          'timestamp': {'type': 'string'},
          'hostname': {'type': 'string'},
          'user': {'type': 'string'},
          'src_ip': {'type': 'string'},
          'dst_ip': {'type': 'string'},
          'process_name': {'type': 'string'},
          'canonical_label': {'type': 'string'},
          'event_category': {'type': 'string'}
        }
      },
      'asset_context': {'type': 'object'},
      'attack_techniques': {'type': 'array', 'items': {'type': 'string'}},
      'status': {'type': 'string', 'enum': ['new', 'in_progress', 'closed']},
      'evidence_hash': {'type': 'string'}
    }
  }
}

with open('$SCHEMA_JSON', 'w') as f:
    json.dump(schema, f, indent=2)

# Output summary
print(f'rules executed            : {total_rules}')
print(f'raw matches               : {raw_matches_count}')
print(f'after deduplication       : {len(deduped_alerts)}')
print('top 5 alerts')

for idx, a in enumerate(deduped_alerts[:5], 1):
    rule_name = a.get('rule_name', a['rule_id'])
    prio = a['priority_score']
    level = a['rule_level']
    host = a['event_summary']['hostname']
    print(f\"{idx:>2}  {prio:>4.1f}  {level:<8}  {rule_name:<30}  {host}\")

print(f'alert_queue.json        : {len(deduped_alerts)} alerts')
print('alert_queue_schema.json : written')
"
