# Gap-Threat Correlation Matrix & Threat-Informed Prioritization

This document cross-references the internal gaps identified during the initial posture assessment against the threat landscape, actor behaviors, MITRE ATT&CK kill chains, and complete scenarios mapped out across the threat intelligence phase. By moving beyond inward-looking metrics to an attacker-centric model, this correlation recalibrates MedDefense's strategic remediation priorities.

---

## 1. Threat Correlation Matrix

### Gap ID: GAP-001
* **Gap Description:** Outdated/Unsupported Operating Systems and Missing Firmware Patches (e.g., Windows XP on Siemens MRI, unpatched Fortinet VPN firmware).
* **Original Risk Level:** High
* **Threat Actors:** Organized Crime/RaaS (BlackReef Profile), Advanced Persistent Threats (APTs) / Specialized Access Brokers.
* **Kill Chains:** External Ransomware Chain, Third-Party Supply Chain.
* **Scenarios:** Scenario 1 (Ransomware Campaign), Scenario 3 (Supply Chain Intrusion via Biomedical Remote Access).
* **Updated Risk Level:** **Critical** (Upgraded)
* **Justification:** While originally rated High based on routine asset vulnerability management, threat intelligence demonstrates that Initial Access Brokers actively track unpatched perimeter VPN endpoints to sell to RaaS affiliates, and legacy unpatched internal OS environments (Windows XP) serve as primary collection points for attackers targeting critical clinical machinery.

### Gap ID: GAP-005
* **Gap Description:** Flat Network Topology and Lack of Internal Logical Segmentation.
* **Original Risk Level:** High
* **Threat Actors:** Organized Crime/RaaS (BlackReef Profile), Advanced Persistent Threats (APTs), Malicious Insiders.
* **Kill Chains:** External Ransomware Chain, Insider Exfiltration Chain, Third-Party Supply Chain.
* **Scenarios:** Scenario 1 (Ransomware Campaign), Scenario 3 (Supply Chain Intrusion via Biomedical Remote Access).
* **Updated Risk Level:** **Critical** (Upgraded)
* **Justification:** This gap acts as a force multiplier for every single category of external and third-party threat actor. Once an attacker establishes an initial foothold on a standard workspace, the completely flat internal architecture allows uninhibited horizontal movement directly into critical healthcare databases and diagnostic networks with zero boundary control.

### Gap ID: GAP-007
* **Gap Description:** Vendor-Controlled Application Access Logs and Delayed Log Retrospection (48-hour request delays).
* **Original Risk Level:** Medium
* **Threat Actors:** Malicious Insiders, Advanced Persistent Threats (APTs).
* **Kill Chains:** Insider Exfiltration Chain.
* **Scenarios:** Scenario 2 (Insider Data Exfiltration).
* **Updated Risk Level:** **High** (Upgraded)
* **Justification:** Relying on vendor-dependent, retrospective log delivery guarantees that a data exfiltration event or insider abuse incident cannot be countered during execution. By the time log records are generated and processed (48+ hours later), the threat actor has already completed their objective, evaded local detection, and departed.

### Gap ID: GAP-008
* **Gap Description:** Lack of Immutable or Physical Offline Backups (Production-Network Attached Backup Storage NAS).
* **Original Risk Level:** High
* **Threat Actors:** Organized Crime/RaaS (BlackReef Profile).
* **Kill Chains:** External Ransomware Chain.
* **Scenarios:** Scenario 1 (Ransomware Campaign).
* **Updated Risk Level:** **Critical** (Upgraded)
* **Justification:** Modern ransomware groups explicitly seek out and target local, network-accessible backup solutions (`nas-srv-01`) prior to deploying their cryptographic payloads. Storing backups on the primary production subnet without immutability or physical air-gaps directly guarantees total data recovery failure during a ransomware campaign.

### Gap ID: GAP-011
* **Gap Description:** Lax Access Governance, Cleartext Credential Storage, and Absence of Multi-Factor Authentication (MFA) on VPN Gateways.
* **Original Risk Level:** High
* **Threat Actors:** Organized Crime/RaaS (BlackReef Profile), Malicious Insiders, Advanced Persistent Threats (APTs) / Specialized Access Brokers.
* **Kill Chains:** External Ransomware Chain, Insider Exfiltration Chain, Third-Party Supply Chain.
* **Scenarios:** Scenario 1 (Ransomware Campaign), Scenario 2 (Insider Data Exfiltration), Scenario 3 (Supply Chain Intrusion via Biomedical Remote Access).
* **Updated Risk Level:** **Critical** (Upgraded)
* **Justification:** Identity is the primary perimeter in modern architecture. The lack of mandatory MFA across corporate and vendor remote entry portals, combined with cleartext credentials in local application configuration files, is exploited across all active attack pathways. It completely nullifies perimeter investments.

### Gap ID: GAP-014
* **Gap Description:** Absence of Endpoint USB Media Block Restrictions and Removable Device Data Loss Prevention (DLP).
* **Original Risk Level:** Low
* **Threat Actors:** Malicious Insiders.
* **Kill Chains:** Insider Exfiltration Chain.
* **Scenarios:** Scenario 2 (Insider Data Exfiltration).
* **Updated Risk Level:** **High** (Upgraded)
* **Justification:** Initially considered an administrative nuisance, threat profiling reveals that unmonitored mass-storage writing on standard office terminals represents the easiest and least auditable exfiltration pathway for standard internal personnel attempting to steal proprietary Electronic Health Records (EHR) databases.

---

## 2. Re-prioritized Threat-Informed Gap List

1. **GAP-011: Lax Access Governance, Cleartext Credentials, and Missing MFA** — **CRITICAL** (Upgraded from High)
2. **GAP-005: Flat Network Topology and Lack of Logical Segmentation** — **CRITICAL** (Upgraded from High)
3. **GAP-001: Outdated/Unsupported Operating Systems and Missing Firmware Patches** — **CRITICAL** (Upgraded from High)
4. **GAP-008: Lack of Immutable or Offline Air-Gapped Backups** — **CRITICAL** (Upgraded from High)
5. **GAP-007: Vendor-Controlled Application Access Logs with 48-Hour Delays** — **HIGH** (Upgraded from Medium)
6. **GAP-014: Absence of Endpoint USB Media Block Restrictions and DLP** — **HIGH** (Upgraded from Low)

---

## 3. Strategic Analysis

### The Critical Three
The three strategic gaps whose immediate remediation would disrupt the largest number of attack vectors and invalidate multiple complete kill chains are:
1. **GAP-011 (Lax Access Governance & MFA Absence):** Appears in all three scenarios. Enforcing rigid MFA constraints and removing cleartext local configuration passwords blocks initial access and privilege escalation attempts uniformly.
2. **GAP-005 (Flat Network Topology):** Intersects every external, insider, and supply chain pivoting sequence. Breaking the corporate network into logical trust zones confines compromises to single hosts, shielding core clinical EHR databases.
3. **GAP-001 (Outdated OS / Patching Gaps):** Forms the foundational dependency for automated RaaS exploitation and legacy biomedical supply chain exploits. Remediating perimeter firmware and deprecating end-of-life hosts prevents severe service disruption.

### The Surprise: GAP-014 (Endpoint USB Device Control Lack)
* **Original Posture Assessment Rating:** Low
* **Threat-Informed Realignment Rating:** **High**
* **The Shift in Understanding:** Originally, unmanaged USB ports were classified as a low operational risk because they do not expose an open internet-facing surface. However, cross-referencing this gap with localized insider threat profiling (Scenario 2) changed our perspective. When disgruntled or compromised internal staff seek to monetize PHI data tables on illicit darknet markets, they avoid network-based transfers that might pass through perimeter firewalls. Instead, they rely on physical mass storage to copy gigabytes of exported files silently. Without host-level device blocks, MedDefense remains completely exposed to undetected, catastrophic data theft carried out by authorized personnel right from their office desks.
