# MedDefense Detection Engineering Specification

## Purpose
This specification defines the design, standards, execution model, and quality gates of the MedDefense Detection Engineering platform. It acts as the operational contract for authoring, testing, prioritizing, and delivering alert logic to downstream security triage operations.

## Inputs
- **Normalized Events**: `$BASELINE_PKG/taxonomy/normalized_events.json`
- **Baseline Summary**: `$BASELINE_PKG/baselines/baseline_summary.json`
- **Risk Register**: `$ASSETS_DIR/risk_register.json`
- **Asset Inventory**: `$HANDOFF_DIR/context/asset_inventory.json`
- **Environment Variables**: `BASELINE_PKG`, `ASSETS_DIR`, `HANDOFF_DIR`

## Rule Authoring Standard
Rules must follow the standard Sigma YAML structure. Required top-level fields include `title`, `id` (UUIDv4), `status`, `description`, `author`, `date`, `logsource`, `detection`, `falsepositives`, `level`, and `tags`. File naming must follow `NNN_rule_name.yml` (e.g., `001_ssh_brute_force.yml`). Every rule must include at least one valid MITRE ATT&CK tag in the format `attack.tXXXX` or `attack.tXXXX.YYY`.

## Execution Model
Rules are evaluated against normalized telemetry using `3-sigma_runner.sh`. The runner handles event preprocessing primitives, normalizes log field names, and applies sliding baseline window semantics (e.g., 7-day clean dataset evaluation). Matches represent raw detection events before quality filtering and deduplication.

## Quality Thresholds
To ship to production, a rule must satisfy the following gates:
- **Precision**: ≥ 0.50
- **Recall**: ≥ 0.50
- **F1 Score**: ≥ 0.60 (Rules with F1 < 0.30 are marked `[WEAK]`, F1 ≥ 0.70 are `[STRONG]`)
- **False Positive Rate**: Maximum of 10 false positives (`fp_count` ≤ 10) over a 7-day clean baseline window.

## Tuning Protocol
Rules exceeding false positive limits are moved to `rules/sigma/tuned/`. Tuning requires adding explicit filtering conditions (e.g., exclusions for authorized service accounts, maintenance scripts, or benign network ranges) without degrading recall on true positive ground truth events. Tuned variants override original rules in the alert pipeline.

## Risk Ranking Model
Organizational risk is derived by linking rule ATT&CK tags to threat scenarios in `$ASSETS_DIR/risk_register.json`.
- `risk_score` = Sum of `(likelihood * impact)` for all matching scenarios.
- `priority_score` = `risk_score * f1` (with a floor of `risk_score * 0.1` for rules with `f1 = 0`).

## Outputs
Deduplicated alerts are written to `alert_queue.json` along with its formal contract schema `alert_queue_schema.json`. Each alert contains `alert_id` (deterministic UUIDv5), `generated_at`, `rule_id`, `rule_title`, `rule_level`, `priority_score`, `event_ref`, `event_summary`, `asset_context`, `attack_techniques`, `status` (`new`), and `evidence_hash` (SHA-256).

## Failure Modes
1. **Schema Mismatch**: Upstream telemetry field changes cause `3-sigma_runner.sh` to silently fail to match selection criteria.
2. **Baseline Drift**: Unannounced infrastructure changes produce a surge of false positives (`fp_count` > 10).
3. **Orphan Rules**: Rule authored with ATT&CK tags that do not map to any scenario in `risk_register.json`, leading to a `priority_score` of 0.

## Reviewer Checklist
- [ ] File follows `NNN_rule_name.yml` naming and contains valid UUIDv4 `id`.
- [ ] Required fields (`title`, `logsource`, `detection`, `level`, `tags`) are present.
- [ ] At least one `attack.tXXXX` tag is included.
- [ ] Rule achieves F1 ≥ 0.60 and `fp_count` ≤ 10 on baseline data.
- [ ] Validated against `ranked_anomalies.json` without missing true positive events.
