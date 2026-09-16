# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose
This playbook defines a repeatable, platform-independent workflow for Tier 1 SOC analysts to investigate security alerts across any SIEM or data store. It standardizes investigation actions into dual execution paths to ensure consistent findings regardless of interface or vendor changes.

## Scope
This playbook covers initial triage, context enrichment, timeline reconstruction, and finding generation for host, network, authentication, and egress security alerts. It does not cover long-term incident response containment, post-incident remediation, active threat hunting beyond alert boundaries, or malware reverse engineering.

## Inputs
- Enriched Event Store (raw logs with normalized schema fields)
- Asset Inventory (`network_zones.json`, device classification, subnet mapping)
- Traffic Baseline (`traffic_baseline.json`, expected operational profiles)
- Detection Catalog (SIEM rule definitions, alert correlation mappings)
- Triage Package (alert metadata, triggering query, initial time window)
- IOC Context (`threat_intel_iocs.json`, known-bad domains, hashes, and IP addresses)

## Workflow Steps

| # | Step Name | CLI Action | Export / Dashboard Action |
|---|---|---|---|
| 1 | Alert Ingestion & Scope Isolation | Filter raw JSON export or log file by `alert.id` or `src_ip` using `jq` to extract triggering events. | Paste `alert.id` or initial source IP into the dashboard search bar over the initial 24-hour window. |
| 2 | Field Normalization Check | Verify presence of standardized core fields (`timestamp`, `src_ip`, `dst_ip`, `dst_port`, `action`). | Expand event details in the web UI to verify field mapping and native field population. |
| 3 | Asset & Zone Context Enrichment | Join `src_ip` against `network_zones.json` using `jq` to identify device classification and network segment. | Review UI metadata panels or filter by `source.zone` / asset tagging tags in dashboard controls. |
| 4 | Baseline Deviation Analysis | Compare observed event counts and volume against `traffic_baseline.json` thresholds. | Toggle UI baseline overlay or compare current search results against historic dashboard metrics. |
| 5 | Chronological Timeline Assembly | Sort events chronologically using `jq 'sort_by(.timestamp)'` to calculate inter-event intervals. | Set UI visual histogram to narrow time bins (1m/5m) to visualize event frequency and beacon patterns. |
| 6 | Correlation & Pivot Search | Query destination IP or hash across all logs to check for lateral movement or multi-host impact. | Click destination IP in UI to initiate global pivot search across all dashboard indices. |
| 7 | Attack Technique Mapping | Map observed indicators and behaviors against MITRE ATT&CK techniques (e.g., T1071.001, T1041). | Tag dashboard visualization findings with MITRE IDs or select matching categories in alert UI. |
| 8 | Finding Artifact Generation | Build `finding.json` with execution time, actions taken, touched fields, and confidence level. | Click Export Report or copy dashboard session summary state into ticket record. |

## Field Name Translation Table

| Normalized Field | Wazuh Field Name |
|---|---|
| `@timestamp` | `data.timestamp` / `@timestamp` |
| `src_ip` | `data.srcip` / `source.ip` |
| `dst_ip` | `data.dstip` / `destination.ip` |
| `dst_port` | `data.dstport` / `destination.port` |
| `src_zone` | `source.zone` / `data.srczone` |
| `protocol` | `data.proto` / `network.transport` |
| `process_name` | `data.process.name` / `win.eventdata.image` |
| `user_name` | `data.dstuser` / `user.name` |
| `action` | `data.action` / `event.outcome` |
| `rule_id` | `rule.id` / `data.rule_id` |

## Query Decomposition Rule
Every security query decomposes into three distinct components: **Filter** (criteria identifying target events), **Aggregation** (grouping and counting operations), and **Time Window** (temporal boundary).

- **`jq` (CLI):** `jq 'select(.src_ip == "10.2.3.2") | group_by(.dst_ip) | map({dst: .[0].dst_ip, count: length})'` over file bounds.
- **Sigma:** `logsource: category: firewall` / `detection: selection: src_ip: '10.2.3.2'` / `timeframe: 24h`.
- **KQL (Kibana):** `source.ip : "10.2.3.2" | stats count() by destination.ip` with time picker `@timestamp >= now-24h`.
- **Lucene:** `source.ip:"10.2.3.2" AND destination.port:443` combined with time range controls `[@timestamp NOW-24HOURS TO NOW]`.

## Finding Schema
```json
{
  "finding_id": "string",
  "scenario_id": "string",
  "interface": "cli | wazuh_export",
  "investigation_start": "ISO8601",
  "investigation_end": "ISO8601",
  "time_to_first_answer_seconds": "number",
  "actions": ["array of strings"],
  "fields_touched": ["array of strings"],
  "event_refs": ["array of strings"],
  "attack_techniques": ["array of string MITRE IDs"],
  "hypothesis": "string",
  "confidence": "low | medium | high",
  "created_at": "ISO8601"
}
Exit Criteria
An investigation is complete and ready for finding emission when:
The primary source entity and external destination targets are conclusively identified.
The network zone and asset criticality are mapped using local inventory or field metadata.
Chronological event order is established with beaconing intervals or volume bursts calculated.
MITRE ATT&CK techniques are mapped with high confidence based on observed log artifacts.
All investigation actions, touched fields, and timing metrics are logged in the schema output.
Known Pitfalls
Missing or unpopulated source.zone fields require immediate fallback to network_zones.json to prevent zone misclassification.
Unsorted JSON exports skew interval calculations, making automated beacon detection produce inaccurate delta measurements.
Timezone offsets between UTC event timestamps and local analyst dashboards create artificial gaps in visual timeline analysis.
