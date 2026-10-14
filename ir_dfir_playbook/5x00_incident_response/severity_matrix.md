# MedDefense Severity Matrix

## Purpose
This matrix establishes a standardized severity classification framework across all engineering, clinical, legal, and executive teams at MedDefense. It ensures predictable escalation, response SLAs, and decision authority during security incidents.

## Severity Matrix Table
| Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| SEV1 | high | confirmed_broad | full_outage | 15 | CISO |
| SEV2 | moderate | confirmed_limited | partial_outage | 30 | IR_Commander |
| SEV3 | low | suspected | degraded | 120 | Technical_Lead |
| SEV4 | none | none | none | 1440 | Scribe |

## Level Definitions

### SEV1
- Active ransomware deployment encrypting primary Electronic Health Record (EHR) databases or clinical workstation clusters.
- Unauthenticated remote code execution (RCE) on core patient management systems with confirmed exfiltration of broad patient ePHI.
- Complete outage of regional hospital ICU telemetry network impacting real-time patient monitoring capabilities.

### SEV2
- Confirmed compromise of a clinical-access user account or privilege escalation on clinical infrastructure.
- Malware confirmed on a single workstation at a clinical site with potential lateral movement capability.
- Suspected exfiltration of patient health records under active investigation.

### SEV3
- Suspicious credential submission following an external phishing campaign targeting hospital staff.
- Isolated malware detection on a non-critical corporate workstation automatically blocked by EDR.
- Performance degradation or intermittent latency on non-clinical staff scheduling applications.

### SEV4
- High-volume external port scanning or automated brute-force login attempts successfully blocked by edge firewalls.
- Informational security scanner alert identifying non-exploitable vulnerabilities on internal assets.
- False-positive antivirus alert triggered by routine administrative script execution.

## Escalation Rule
Incident severity must be reviewed and re-evaluated at every status update during an active incident. Severity increases when new evidence reveals a higher impact on patient safety, data exposure, or service availability. Conversely, severity is lowered only after confirmed technical containment, eradication of threats, and formal approval by the IR Commander.
