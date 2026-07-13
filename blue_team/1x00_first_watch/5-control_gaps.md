# Control Gaps Analysis: MedDefense Health Systems

This document analyzes the systemic security blind spots identified within MedDefense's infrastructure by examining the empty cells in the Control Summary Matrix and correlating them with operational artifacts.

---

## 1. Systemic Control Gaps Log

Gap ID: G-001
Gap Description: Complete absence of Centralized Log Management (SIEM) and automated security event alerting. Logs are scattered locally, rotate rapidly, and are only inspected manually after an operational failure occurs[cite: 3].
Category x Function Missing: Technical Detective
Affected Asset(s) or Zone: Core Network, Directory Infrastructure (Active Directory), Operating System Layers (`ehr-srv-01`, `billing-srv-01`, `web-srv-01`)[cite: 3].
Risk if Unaddressed: **Confidentiality and Integrity Compromise.** Attackers can execute lateral movement, establish backdoors, or exfiltrate sensitive data undetected for months, as no real-time alarms indicate anomalous system activity[cite: 3].
Evidence: Artifact 8 directly states there is "No centralized log management system" and "No automated alerting on security events."[cite: 3]

Gap ID: G-002
Gap Description: Lack of Server Endpoint Protection; anti-malware licensing is restricted strictly to end-user workstations, leaving infrastructure servers entirely unmonitored at the endpoint layer[cite: 3].
Category x Function Missing: Technical Preventive / Technical Detective
Affected Asset(s) or Zone: Windows Servers (15 devices) and Linux Servers (all instances, including `billing-srv-01` and `ehr-srv-01`)[cite: 3].
Risk if Unaddressed: **Integrity and Availability Compromise.** Malicious payloads, rootkits, or crypto-miners can execute directly on production application servers without triggering host-level endpoint alarms or automated quarantines.
Evidence: Artifact 4 states that server protection license was not purchased for Windows servers, and Linux servers are completely unsupported by the current Sophos tier[cite: 3].

Gap ID: G-003
Gap Description: Complete absence of Egress Firewall Filtering; outbound traffic boundaries are configured to permit all services and ports globally without traffic validation or destination checks[cite: 3].
Category x Function Missing: Technical Preventive
Affected Asset(s) or Zone: Internal Server Subnet and DMZ Zone hosts[cite: 3].
Risk if Unaddressed: **Confidentiality and Availability Compromise.** Compromised local systems can establish arbitrary outbound connections to external Command-and-Control (C2) servers, continuous data exfiltration streams, or automated public mining pools[cite: 2, 3].
Evidence: Artifact 1 (FortiGate Config Rule 4) shows `set srcintf "internal"`, `set dstintf "wan1"`, and `set service "ALL"` with an `accept` action[cite: 3].

Gap ID: G-004
Gap Description: Lack of Regular Disaster Recovery (DR) Test Exercises and untested restoration validation for critical systems[cite: 3].
Category x Function Missing: Technical Corrective / Administrative Corrective
Affected Asset(s) or Zone: EHR Database (`ehr-db-01`), Primary Domain Controller (`ad-dc-01`), Billing Server (`billing-srv-01`)[cite: 3].
Risk if Unaddressed: **Availability Compromise.** If a catastrophic event occurs (such as a ransomware outbreak), the backup files may be corrupted, incomplete, or functionally un-restorable, resulting in permanent data loss and extended runtime downtime[cite: 3].
Evidence: Artifact 5 states that a Full DR test was "Never performed" and local recovery testing was last attempted 8 months ago solely for a minor file share[cite: 3].

Gap ID: G-005
Gap Description: Absence of Internal Surveillance and physical tracking logs around core security centers; there are no cameras or visitor logging protocols governing the server room corridor or network closets.
Category x Function Missing: Physical Detective
Affected Asset(s) or Zone: Server Room Area, Restricted Administrative Wing, Network Closets[cite: 1, 3].
Risk if Unaddressed: **Confidentiality, Integrity, and Availability Compromise.** An insider or malicious actor can physically enter core operational spaces unnoticed, manipulate hardware rigs, deploy rogue sniffing nodes, or sabotage drives without an audit trail[cite: 1, 3].
Evidence: Observation 1 explicitly notes "no camera covering the door" and "no visitor log,"[cite: 1] while Artifact 6 confirms cameras exist but there are "No cameras in server room area, network closets or administrative wing."[cite: 3]

Gap ID: G-006
Gap Description: Missing Core Asset Redundancy and Cloud Air-Gapping; vital data stores lack offsite replication, and essential healthcare subsystems are omitted from routine automated backups entirely[cite: 3].
Category x Function Missing: Technical Corrective / Technical Preventive
Affected Asset(s) or Zone: PACS Imaging Server (`pacs-srv-01`), Secondary Domain Controller (`ad-dc-02`), and the local backup vault (`NAS-01`) itself[cite: 3].
Risk if Unaddressed: **Availability Compromise.** Because the backup repository (`NAS-01`) resides in the same physical room and network domain as the live servers, a localized fire, physical flood, or ransomware spreading laterally will completely wipe out both production and backup assets simultaneously[cite: 3].
Evidence: Artifact 5 states there is "None" offsite/cloud backup, and specifies `pacs-srv-01` and `ad-dc-02` are explicitly excluded from backup runs[cite: 3].

---

## 2. Posture Trend Analysis

### Strategic Question Answer:
Looking at the uncovered gaps as a whole, a distinct, systemic pattern emerges: MedDefense's security posture is overwhelmingly **prevention-oriented** rather than detection-oriented[cite: 3]. The organization relies almost exclusively on perimeter firewalls, password criteria, and local physical locks to keep threats out, but possesses a complete blind spot regarding what happens once those parameters are breached[cite: 1, 3]. This implies that if an attacker successfully bypasses a preventive control (such as exploiting an unpatched web application or utilizing an authenticated remote VPN token), the organization has **zero practical ability** to quickly discover, isolate, or respond to the live incident, allowing the threat to dwell within the environment indefinitely until catastrophic operational failure occurs[cite: 2, 3].
