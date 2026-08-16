# Corporate Incident Response Policy

| Metadata Field | Value |
| :--- | :--- |
| **Document ID** | POL-IR-2026-003 |
| **Version** | 1.0 |
| **Effective Date** | June 26, 2026 |
| **Policy Owner** | Chief Information Security Officer (CISO) |
| **Approved By** | Board of Directors & Global Risk Operations |
| **Regulatory Frameworks** | NIST SP 800-61 Rev. 2, ISO 27001, GDPR Art. 33 |
| **Classification** | Internal Use Only |

### Revision History
| Version | Date | Author | Description of Change |
| :--- | :---: | :--- | :--- |
| 1.0 | June 26, 2026 | Global Cyber Response Unit | Initial baseline publication for cross-border IT/OT infrastructure. |

---

### 1. Purpose & Scope
This policy defines the governance model and operational mandates for identifying, analyzing, containing, and recovering from information security incidents at GlobalTech Manufacturing. The goal is to minimize operational downtime, protect safety-critical OT/IoT manufacturing nodes, secure intellectual property, and satisfy strict multi-jurisdictional notification legalities (e.g., GDPR).

This policy applies to all cloud assets, local operational technology (OT) assembly environments, IoT telemetry logs, networks, and all employees, vendors, and contractors across all 5 operational country offices.

---

### 2. Incident Classification Matrix

| Severity | Description | Response Time | Examples |
| :--- | :--- | :---: | :--- |
| **Critical** | System-wide compromise affecting core manufacturing assembly lines (OT) or a catastrophic breach exposing GDPR-protected personal data. | **Immediate (<15 Mins)** | Active Ransomware encryption on factory floor hosts; complete SCADA control system failure; active massive exfiltration of customer database registries. |
| **High** | Widespread disruption to critical business functions (e.g., corporate email outage across a region) or localized malware infections targeting sensitive IP data. | **<1 Hour** | Targeted spear-phishing compromise of an executive account; severe DDoS attack restricting corporate VPN nodes; isolated network segment compromise. |
| **Medium** | Isolated, non-destructive security anomalies with known mitigating pathways that do not immediately threaten production capabilities. | **<4 Hours** | Single worker workstation infected with adware; unauthorized cloud configuration drift; repeated failed brute-force alerts from an internal IP address. |
| **Low** | Near-misses, routine operational security alerts, or localized minor policy infractions. | **<24 Hours** | Lost corporate smartphone with remote wipe capabilities active; single spam campaign breakout; user requesting verification of a suspicious un-executed attachment. |

---

### 3. Incident Response Team (SIRT) Roles

* **Incident Response Manager (IRM):** Coordinates tactical response workflows, authorizes escalation steps, signs off on containment strategies, and directs technical analysts.
* **Security Analysts (Tier 1/2/3):** Responsible for real-time traffic analysis, digital forensics, log parsing, threat hunting, and executing eradication scripts.
* **IT Support / OT Engineers:** Provide deep configuration infrastructure insights, manage switch patching, isolate localized hardware segments, and lead system backup restoration.
* **Legal Counsel:** Evaluates regulatory data breach reporting mandates, manages liability exposure assessment, and directs communication with law enforcement agencies.
* **Communications / PR Lead:** Controls the dissemination of corporate updates to external public channels, preventing unauthorized information leaks or reputational damage.
* **Executive Sponsor (CISO/CIO):** Provides funding alignment, delivers enterprise risk reports to the executive board, and authorizes critical corporate shutdowns if required during remediation.

---

### 4. Detection, Reporting, & Initial Assessment
* **Detection Vectors:** Incidents are continuously discovered via internal SIEM logging alerts, Endpoint Detection and Response (EDR) telemetry, external threat intelligence feeds, network anomaly detectors, or user reports.
* **Reporting Pathway:** Any employee discovering a suspicious activity must instantly notify the Security Operations Center via the **SIRT Portal** or emergency hot-line (`ext-9111`) or email `incident@globaltech.com`.
* **Initial Assessment:** The on-duty Security Analyst must verify the alert validity within the defined SLA timeline, assign a structural severity ranking using the Matrix in Section 2, and create a tracking ticket inside the central orchestration tool.

---

### 5. Tactical Response Procedures (NIST IR Lifecycle)

#### 5.1. Containment Strategy
* **Short-Term Containment:** Instantly isolate compromised hosts from the network (e.g., isolate EDR host profiles, disable specific active directory accounts, or segment factory switch interfaces).
* **Evidence Preservation:** Before hot-swapping or cutting power, analysts must capture ephemeral system volatile states (live RAM capture) and dump active network traffic captures.
* **Long-Term Containment:** Deploy temporary firewall rules, apply explicit access controls, and route traffic to safe VLAN honeypots to analyze advanced persistent threat (APT) behavior without sacrificing factory up-time.

#### 5.2. Eradication Phase
* Execute complete malware extraction routines, reset all domain wide service keys, delete backdoored cron jobs, and perform deep root-cause verification using vulnerability scanning tools before authorizing safe return states.

#### 5.3. Recovery Phase
* Re-image endpoints from authenticated gold-master backup repositories. Verify system operational behavior using targeted regression tests, and enforce enhanced telemetry monitoring parameters for a minimum of 30 days following restoration.

---

### 6. Communication Plan

| Stakeholder | When to Notify | Communication Method | Approved Spokesperson |
| :--- | :--- | :--- | :--- |
| **Executive Management** | Within 30 minutes of any **Critical** or **High** severity baseline validation. | Secure Out-of-Band Channel (Signal / Emergency Phone Briefing). | CISO / Incident Response Manager |
| **Legal Counsel** | Immediately alongside Executive notification for any event risking regulatory breach. | Internal Encrypted Telephony / Legal Team Bridge. | General Counsel Office |
| **Regulators (GDPR/DPA)** | Strictly within **72 hours** of breach awareness if personal data exposure risk is identified. | Secure Regulatory Compliance Portal Inbound Filing. | Designated Data Protection Officer (DPO) |
| **Affected Users** | Undue delay following containment stability validation, as mandated by GDPR. | Direct individual corporate dispatch / Public PR Advisory. | Corporate PR Director |

---

### 7. Evidence Handling & Post-Incident Architecture
* **Chain of Custody:** Any digital artifact, disk image, or log file extracted during forensics must be documented utilizing a strict Chain of Custody form logging the exact timestamp, custodian name, cryptographic hash identifier (SHA-256), and physical locker number.
* **Post-Incident Review:** Within 14 days of resolving a Critical or High threat event, the IRM must lead a formal **Lessons Learned** meeting with all primary stakeholders to review process execution gaps, adjust SIEM trigger mechanics, and publish the final Post-Incident Remediation Report.

---

### APPENDIX: INCIDENT REPORT TEMPLATE

```text
================================================================================
                    GLOBALTECH MANUFACTURING INCIDENT REPORT
================================================================================
[GENERAL METADATA]
* Ticket ID: IR-2026-___________         * Severity Assessment: [CRITICAL/HIGH/MED/LOW]
* Date Discovered: 2026-___-___          * Incident Analyst Assigned: _________________
* System Category: [IT Corporate / OT Manufacturing Plant / Cloud Infrastructure]

[1. INCIDENT DESCRIPTION & ROOT CAUSE]
* Detailed Summary of Events: __________________________________________________
* Initial Vector: [Phishing / Compromised Edge Device / Insider Threat / Malicious Code]
* Affected Hostnames / IP Boundaries / Component IDs: _________________________

[2. CONTAINMENT, ERADICATION & RECOVERY METRICS]
* Short-Term Containment Executed (Timestamp & Actions): _______________________
* Volatile Forensic Evidence Captured (SHA-256 Hashes): _______________________
* Root-Cause Remediation Verification Steps: ___________________________________
* System Restoration & Verification Timestamp: 2026-___-___ ___:___ UTC

[3. REGULATORY & DATA IMPACT COMPLIANCE STATUS]
* GDPR Regulated Personal Identifiable Information (PII) Exposed?: [YES / NO]
* Operational Manufacturing Assembly Line Downtime (Hours): ___________________
* External Regulatory / Law Enforcement Notifications Required?: [YES / NO]

[4. AUTHORIZATION SIGN-OFF]
* Incident Response Manager Signature: _____________________ Date: 2026-___-___
================================================================================
