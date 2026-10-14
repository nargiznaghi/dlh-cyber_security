<!-- 
Author: Nargiz Naghiyeva
Date: 2026-10-14
-->

# Severity Matrix

## Purpose
This matrix establishes a standardized severity classification framework across all engineering, clinical, legal, and executive teams at MedDefense. It ensures predictable escalation, response SLAs, and decision authority during security incidents.

## Severity Matrix Table

| Severity Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEV1** | high | confirmed_broad | full_outage | 15 | Incident Commander |
| **SEV2** | moderate | confirmed_limited | partial_outage | 30 | Incident Commander |
| **SEV3** | low | suspected | degraded | 120 | Security Operations Lead |
| **SEV4** | none | none | none | 1440 | On-Call Analyst |

## Level Definitions

### SEV1
- Active ransomware deployment encrypting primary Electronic Health Record (EHR) databases or clinical workstation clusters.
- Unauthenticated remote code execution (RCE) on core patient management systems with confirmed exfiltration of broad patient ePHI.
- Complete outage of regional hospital ICU telemetry network impacting real-time patient monitoring capabilities.

### SEV2
- Intermittent API failure or partial outage affecting pharmacy integration software and outpatient prescription routing.
- Confirmed compromise of a privileged administrator account on staging infrastructure holding limited clinical telemetry.
- Unauthorized access detected on an internal hospital file share containing limited patient registration exports.

### SEV3
- Suspicious credential submission following a phishing email caught and contained before privilege escalation or lateral movement.
- Isolated malware detection on a non-critical workstation automatically blocked and quarantined by EDR.
- Performance degradation on non-clinical staff scheduling or administrative web applications.

### SEV4
- High-volume external port scanning or automated brute-force attempts successfully blocked by edge firewalls.
- Informational security scanner alert identifying non-exploitable vulnerabilities on internal assets.
- False positive antivirus alert triggered by routine administrative script execution.

## Escalation Rule
Incident severity must be re-evaluated continuously during active response. If impact metrics exceed the assigned level's thresholds or resolution is not achieved within the auto-escalation window, the Decision Authority must immediately raise the severity to the higher level.
