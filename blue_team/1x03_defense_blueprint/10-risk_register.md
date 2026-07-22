# 10. The Risk Register

## Risk Assessment Scales

### Likelihood Scale (1-5)
1. **Rare:** Less than once every 5 years
2. **Unlikely:** Once every 2 to 5 years
3. **Possible:** Once every 1 to 2 years
4. **Likely:** Multiple times per year
5. **Almost Certain:** Monthly or continuous occurrence

### Impact Scale (1-5)
1. **Insignificant:** Minor localized disruption (<$10k loss, no compliance impact)
2. **Minor:** Short operational downtime (<$100k loss, negligible compliance exposure)
3. **Moderate:** Partial service impact ($100k–$500k loss, minor regulatory report required)
4. **Major:** Significant operational failure ($500k–$2M loss, regulatory fines)
5. **Catastrophic:** Widespread failure/ePHI breach (>$2M loss, severe litigation/regulatory action)

---

## MedDefense Top 10 Risk Register

### Entry 1: Ransomware Encryption of Core EHR Database
* **Risk ID:** RISK-001
* **Risk Description:** A ransomware actor encrypts the primary ePHI database, causing clinical service downtime and mass revenue loss.
* **Risk Category:** Operational
* **Threat Source:** Cybercrime Syndicate / Ransomware Group (e.g., BlackReef)
* **Vulnerability:** GAP-003 / Finding 003 (Flat Network, Unrestricted PostgreSQL Access)
* **Affected Asset(s):** `ehr-db-01` (ePHI Database Cluster)
* **Likelihood:** 4 (Likely)
* **Impact:** 5 (Catastrophic)
* **Inherent Risk Score:** 20 (Critical)
* **ALE:** $2,902,500
* **Risk Owner:** Deputy CISO (James Chen)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** High financial loss and clinical operational disruption demand technical mitigation controls.
* **Planned Control(s):** Network Segmentation (VLANs/ACLs), Immutable Cloud Backups (AWS Glacier), Sophos Intercept X EDR
* **Residual Risk:** Medium (Likelihood: 2, Impact: 3 = 6)
* **KRI:** Number of unsegmented endpoints attempting cross-subnet database connections
* **Review Date:** Monthly (Next: August 2026)

---

### Entry 2: Perimeter Breach via Credential Hijacking on Remote VPN
* **Risk ID:** RISK-002
* **Risk Description:** An external attacker gains internal network access by compromising single-factor user credentials on the FortiGate VPN.
* **Risk Category:** Strategic / Operational
* **Threat Source:** External Credential Brokers / Advanced Persistent Threats
* **Vulnerability:** GAP-004 / Finding 004 (Single-Factor Remote Auth / Missing MFA)
* **Affected Asset(s):** `fg-edge-01` (FortiGate Perimeter Gateway)
* **Likelihood:** 4 (Likely)
* **Impact:** 5 (Catastrophic)
* **Inherent Risk Score:** 20 (Critical)
* **ALE:** $3,628,240
* **Risk Owner:** IT Director (Sarah Park)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** Single-factor perimeter gateways create unacceptable organization-wide exposure.
* **Planned Control(s):** Mandatory Multi-Factor Authentication (MFA) Deployment via Microsoft 365 E3
* **Residual Risk:** Low (Likelihood: 1, Impact: 4 = 4)
* **KRI:** Percentage of remote VPN users authenticating without MFA enforcement
* **Review Date:** Monthly (Next: August 2026)

---

### Entry 3: Large-Scale ePHI Breach via EHR Exfiltration
* **Risk ID:** RISK-003
* **Risk Description:** Unauthorized exfiltration of patient health records leads to massive HIPAA fines and reputational loss.
* **Risk Category:** Compliance / Financial
* **Threat Source:** External Cybercrime / Malicious Insiders
* **Vulnerability:** GAP-001 / Finding 003 (Unencrypted Internal Traffic & Lack of DLP Controls)
* **Affected Asset(s):** `ehr-srv-01` & `ehr-db-01`
* **Likelihood:** 3 (Possible)
* **Impact:** 5 (Catastrophic)
* **Inherent Risk Score:** 15 (High)
* **ALE:** $2,994,750
* **Risk Owner:** Deputy CISO (James Chen)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** HIPAA penalties and civil litigation make unmitigated data breaches financially catastrophic.
* **Planned Control(s):** Database Access Control Lists, Wazuh Open-Source SIEM Log Alerting, EDR Agent Enforcement
* **Residual Risk:** Low (Likelihood: 1, Impact: 4 = 4)
* **KRI:** Volume of outbound data transfers exceeding daily baseline from database subnets
* **Review Date:** Quarterly (Next: September 2026)

---

### Entry 4: Negligent Insider Data Leakage via Workstations
* **Risk ID:** RISK-004
* **Risk Description:** Clinical staff inadvertently leak protected health data or execute malicious payloads due to lack of training and endpoint restrictions.
* **Risk Category:** Operational / Compliance
* **Threat Source:** Negligent Insiders
* **Vulnerability:** GAP-008 / Finding 008 (Shared Accounts, No Security Training, Open USB Ports)
* **Affected Asset(s):** Clinical Workstation Fleet (280 Endpoints)
* **Likelihood:** 5 (Almost Certain)
* **Impact:** 3 (Moderate)
* **Inherent Risk Score:** 15 (High)
* **ALE:** $300,000
* **Risk Owner:** Department Heads (e.g., Dr. Patel)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** High incident frequency requires endpoint containment controls and staff policy enforcement.
* **Planned Control(s):** Group Policy USB Port Restrictions, Removal of Shared Domain Accounts, Security Awareness Training
* **Residual Risk:** Low (Likelihood: 2, Impact: 2 = 4)
* **KRI:** Phishing simulation failure rate and unauthorized USB insertion alerts count
* **Review Date:** Quarterly (Next: September 2026)

---

### Entry 5: Automated Exploitation of Legacy Unpatched Server Operating Systems
* **Risk ID:** RISK-005
* **Risk Description:** Opportunistic attackers exploit known public CVEs on unpatched web or billing servers to achieve Remote Code Execution.
* **Risk Category:** Operational
* **Threat Source:** Opportunistic Cybercrime Syndicates
* **Vulnerability:** GAP-002 / Finding 001/002 (Outdated Apache / Ubuntu OS Vulnerabilities)
* **Affected Asset(s):** `billing-srv-01` (Ubuntu 18.04 Server)
* **Likelihood:** 4 (Likely)
* **Impact:** 3 (Moderate)
* **Inherent Risk Score:** 12 (High)
* **ALE:** $236,500
* **Risk Owner:** IT Director (Sarah Park)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** Known CVEs on internet-facing systems present an easily preventable exploit path.
* **Planned Control(s):** Patch Management Pipeline, Operating System In-Place Upgrade, Web Application Firewall (WAF)
* **Residual Risk:** Low (Likelihood: 1, Impact: 3 = 3)
* **KRI:** Number of unresolved High/Critical CVEs older than 30 days
* **Review Date:** Monthly (Next: August 2026)

---

### Entry 6: Tampering or Denial-of-Service on Networked Medical Devices
* **Risk ID:** RISK-006
* **Risk Description:** Unauthorized network actors exploit default credentials to disrupt or disable connected medical devices.
* **Risk Category:** Operational / Patient Safety
* **Threat Source:** Opportunistic Network Scanning Attackers
* **Vulnerability:** GAP-003 / Finding 010 (Default Credentials on BD Alaris Pumps, Flat Network)
* **Affected Asset(s):** BD Alaris Infusion Pumps (7 Units)
* **Likelihood:** 2 (Unlikely)
* **Impact:** 4 (Major)
* **Inherent Risk Score:** 8 (Medium)
* **ALE:** $95,500
* **Risk Owner:** IT Director (Sarah Park)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** Direct threats to patient safety and FDA compliance demand proactive isolation.
* **Planned Control(s):** Mandatory Credential Hardening, Dedicated Air-Gapped Medical Device VLAN
* **Residual Risk:** Low (Likelihood: 1, Impact: 2 = 2)
* **KRI:** Unauthenticated administrative login attempts on medical device subnets
* **Review Date:** Semi-Annually (Next: November 2026)

---

### Entry 7: Compromise of Unprotected Remote Branch Perimeter
* **Risk ID:** RISK-007
* **Risk Description:** Attackers compromise consumer-grade edge appliances at remote clinical sites to gain network ingress.
* **Risk Category:** Operational
* **Threat Source:** External Attackers / Scanners
* **Vulnerability:** Finding 006 (Consumer Router at Westside Clinic)
* **Affected Asset(s):** Westside Clinic Network Gateway
* **Likelihood:** 3 (Possible)
* **Impact:** 3 (Moderate)
* **Inherent Risk Score:** 9 (Medium)
* **ALE:** $45,000
* **Risk Owner:** IT Director (Sarah Park)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** Insecure branch perimeters create backdoor entry points into the primary hospital infrastructure.
* **Planned Control(s):** Deploy Enterprise Next-Gen Firewall at Westside Clinic
* **Residual Risk:** Low (Likelihood: 1, Impact: 2 = 2)
* **KRI:** Inbound perimeter connection drops and blocked malicious probes at branch router
* **Review Date:** Semi-Annually (Next: November 2026)

---

### Entry 8: Unmonitored Security Events Due to Missing Logging
* **Risk ID:** RISK-008
* **Risk Description:** Security incidents occur undetected for extended periods due to lack of centralized logging and real-time monitoring.
* **Risk Category:** Operational / Compliance
* **Threat Source:** All Threat Actors
* **Vulnerability:** GAP-005 / Finding 005 (No Centralized Logging / Missing SIEM)
* **Affected Asset(s):** Enterprise Infrastructure (All Servers & Switches)
* **Likelihood:** 4 (Likely)
* **Impact:** 3 (Moderate)
* **Inherent Risk Score:** 12 (High)
* **ALE:** $120,000
* **Risk Owner:** Security Analyst (You)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** Detection capability is required to maintain incident response readiness and regulatory compliance.
* **Planned Control(s):** Wazuh Open-Source SIEM Deployment & Active Syslog Forwarding
* **Residual Risk:** Low (Likelihood: 1, Impact: 2 = 2)
* **KRI:** Percentage of critical servers forwarding logs to SIEM with <5 min delay
* **Review Date:** Monthly (Next: August 2026)

---

### Entry 9: Ransomware Destruction of System Backups
* **Risk ID:** RISK-009
* **Risk Description:** Threat actors target and destroy online, unisolated backups prior to deploying ransomware, preventing recovery.
* **Risk Category:** Operational
* **Threat Source:** Ransomware Groups (e.g., BlackReef)
* **Vulnerability:** GAP-006 / Finding 007 (Online, Unisolated Local Backups)
* **Affected Asset(s):** Primary System Backups
* **Likelihood:** 3 (Possible)
* **Impact:** 5 (Catastrophic)
* **Inherent Risk Score:** 15 (High)
* **ALE:** $1,272,250
* **Risk Owner:** IT Director (Sarah Park)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** Unprotected backups eliminate disaster recovery capabilities and force extortion payments.
* **Planned Control(s):** Offsite AWS S3 Glacier Immutable Storage with Object Lock
* **Residual Risk:** Low (Likelihood: 1, Impact: 2 = 2)
* **KRI:** Success rate of automated immutable cloud backup replication jobs
* **Review Date:** Monthly (Next: August 2026)

---

### Entry 10: Unauthorized Exposure of Internal IT Services to the Internet
* **Risk ID:** RISK-010
* **Risk Description:** Internal administrative portals remain directly accessible over the public internet without perimeter access controls.
* **Risk Category:** Operational / Compliance
* **Threat Source:** External Scanners / Opportunistic Attackers
* **Vulnerability:** Finding 002/005 (Exposed Services & Open Management Ports)
* **Affected Asset(s):** Web Services & Infrastructure Interfaces
* **Likelihood:** 4 (Likely)
* **Impact:** 3 (Moderate)
* **Inherent Risk Score:** 12 (High)
* **ALE:** $150,000
* **Risk Owner:** IT Director (Sarah Park)
* **Treatment Decision:** Mitigate
* **Treatment Justification:** Publicly exposed management interfaces represent unnecessary attack surfaces.
* **Planned Control(s):** Inbound Firewall Filtering Rules, Removal of Public IP Bindings for Internal Services
* **Residual Risk:** Low (Likelihood: 1, Impact: 2 = 2)
* **KRI:** Number of public-facing IP addresses running unencrypted management protocols
* **Review Date:** Monthly (Next: August 2026)

---

## Risk Register Governance Note

This Risk Register is maintained by the **Security Analyst** under the direct oversight of the **Deputy CISO (James Chen)**[cite: 3]. It is formally reviewed on a **monthly schedule** by the Information Security Committee (consisting of the Deputy CISO, IT Director, and clinical department heads)[cite: 3]. An **out-of-cycle review** is triggered automatically by major technical changes, new zero-day exploit disclosures affecting MedDefense infrastructure, active security incidents, or significant updates to healthcare compliance mandates (e.g., HIPAA revisions)[cite: 3]. When a Key Risk Indicator (KRI) threshold is breached (such as phishing simulation failure rates exceeding 15% or an unpatched critical vulnerability remaining past 30 days), an immediate escalation alert is issued to the Risk Owner, requiring a written remediation action plan within 5 business days and mandatory reporting to the Executive Leadership team[cite: 3, 4].
