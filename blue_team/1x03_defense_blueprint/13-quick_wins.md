# 13. Quick Wins: Immediate Zero-Cost Security Actions

## Quick Win 1: Enable Mandatory MFA on Active Directory & FortiGate VPN for IT/Admin Users

* **Risk Addressed:** RISK-002 (Perimeter Breach via Credential Hijacking on Remote VPN)[cite: 4]
* **Action:**
  1. Enforce Conditional Access policies within the existing Microsoft 365 E3 tenant to mandate MFA for all administrative accounts[cite: 3, 4].
  2. Integrate FortiGate VPN remote access authentication with M365 E3 SAML/Azure AD MFA for all IT, administrator, and clinical remote users[cite: 3, 4].
  3. Revoke legacy single-factor VPN local accounts and verify that all remote sessions require multi-factor verification[cite: 3, 4].
* **Owner:** Systems Administrator (Marcus Vance) under IT Director (Sarah Park) oversight[cite: 4].
* **Timeline:** 3 Days
* **Cost:** $0 (Utilizes already existing Microsoft 365 E3 licenses and FortiGate native capabilities)[cite: 3, 4].
* **Risk Reduction:** Disrupts the initial access stage of threat actor kill chains (e.g., initial credential access via phishing or password spraying), preventing unauthorized entry into the network[cite: 3, 4].
* **Verification:** Run an Azure AD Conditional Access compliance audit report and attempt a test VPN login using single-factor credentials to confirm access is explicitly denied[cite: 3, 4].

---

## Quick Win 2: Enforce USB Storage Device Blocking via Active Directory Group Policy (GPO)

* **Risk Addressed:** RISK-004 (Negligent Insider Data Leakage via Workstations)[cite: 4]
* **Action:**
  1. Draft a domain-wide Active Directory Group Policy Object (GPO) targeting all clinical and operational domain workstations[cite: 3, 4].
  2. Configure GPO settings under `Computer Configuration -> Administrative Templates -> System -> Removable Storage Access` to deny read/write permissions for all removable disk classes[cite: 3, 4].
  3. Create an IT exception group for approved, encrypted business USB devices[cite: 3, 4].
  4. Link and enforce the GPO across all Active Directory Workstation Organizational Units (OUs)[cite: 3, 4].
* **Owner:** Systems Administrator (Marcus Vance)[cite: 4].
* **Timeline:** 2 Days
* **Cost:** $0 (Native Windows Active Directory domain feature)[cite: 3, 4].
* **Risk Reduction:** Disrupts execution and data exfiltration kill chain stages via physical media, preventing malware drops or accidental local ePHI copying[cite: 3, 4].
* **Verification:** Insert an unauthorized non-encrypted test USB drive into three randomly selected clinical workstations and confirm Windows denies access[cite: 3, 4].

---

## Quick Win 3: Disable Insecure/Exposed Protocols & Restrict Admin Management Ports on Perimeter Firewall

* **Risk Addressed:** RISK-010 (Unauthorized Exposure of Internal IT Services to the Internet)[cite: 4]
* **Action:**
  1. Review FortiGate edge firewall (`fg-edge-01`) listening interfaces and external WAN bindings[cite: 3, 4].
  2. Disable public WAN administrative access (HTTP/HTTPS/SSH) on the external interface[cite: 3, 4].
  3. Create explicit inbound WAN access control lists (ACLs) dropping all unencrypted management traffic (HTTP, Telnet, FTP, RDP)[cite: 3, 4].
  4. Restrict internal SSH and HTTPS administrative management to dedicated, authenticated management IP subnets[cite: 3, 4].
* **Owner:** Network Engineer (Alex Rivera)[cite: 4].
* **Timeline:** 2 Days
* **Cost:** $0 (Leverages existing FortiGate core firewall software capabilities)[cite: 3, 4].
* **Risk Reduction:** Eliminates external reconnaissance and initial access vectors targeting exposed server web interfaces and administrative portals[cite: 3, 4].
* **Verification:** Execute an external Nmap vulnerability scan against MedDefense WAN public IP addresses to verify all management ports report as `closed` or `filtered`[cite: 3, 4].

---

## Quick Win 4: Harden Billing Server Web Service Configuration & Disable Unnecessary Apache Modules

* **Risk Addressed:** RISK-005 (Automated Exploitation of Legacy Unpatched Server OS)[cite: 4]
* **Action:**
  1. Access `billing-srv-01` and update Apache web server configurations to disable directory listing (`Options -Indexes`)[cite: 3, 4].
  2. Disable server signature banners (`ServerTokens Prod` and `ServerSignature Off`) to prevent automated version fingerprinting[cite: 3, 4].
  3. Disable obsolete Apache modules (e.g., `mod_status`, `mod_info`, `cgi` if unused)[cite: 3, 4].
  4. Implement strict file permission bounds (`chmod 640` / `chown root:www-data`) on key billing web root directories[cite: 3, 4].
* **Owner:** IT Operations / Systems Administrator (Marcus Vance)[cite: 4].
* **Timeline:** 3 Days
* **Cost:** $0 (Native Linux/Apache service configuration tuning)[cite: 3, 4].
* **Risk Reduction:** Disrupts the reconnaissance and initial exploitation steps of automated attack bots by hardening public attack surfaces[cite: 3, 4].
* **Verification:** Perform an HTTP header inspection via `curl -I` and automated vulnerability scan against `billing-srv-01` to ensure service fingerprinting is masked and unauthorized access is blocked[cite: 3, 4].

---

## Quick Win 5: Deploy Free Open-Source Wazuh SIEM Monitoring Agent to Core Infrastructure

* **Risk Addressed:** RISK-008 (Unmonitored Security Events Due to Missing Logging)[cite: 4]
* **Action:**
  1. Spin up a virtual machine instance utilizing spare internal hypervisor host capacity to host the open-source Wazuh SIEM manager[cite: 3, 4].
  2. Deploy lightweight Wazuh monitoring agents via Active Directory GPO to core domain servers (`ehr-srv-01`, `ehr-db-01`, `billing-srv-01`)[cite: 3, 4].
  3. Configure Syslog forwarding on the FortiGate perimeter gateway to feed firewall events directly into Wazuh[cite: 3, 4].
  4. Enable automated email alerting for high-severity security events (e.g., multiple failed logins, unauthorized group escalation)[cite: 3, 4].
* **Owner:** Security Analyst (You) & IT Director (Sarah Park)[cite: 4].
* **Timeline:** 5 Days
* **Cost:** $0 (Free open-source software deployed on existing virtualized hardware)[cite: 3, 4].
* **Risk Reduction:** Provides immediate visibility into privilege escalation, persistence, and lateral movement stages of attack kill chains across core databases and servers[cite: 3, 4].
* **Verification:** Trigger a simulated failed login threshold on `ehr-srv-01` and verify that the alert is generated in the Wazuh dashboard within 60 seconds[cite: 3, 4].

---

## Organizational Purpose of Quick Wins

Beyond their immediate risk reduction, quick wins play a vital strategic role in establishing momentum, credibility, and security culture within the first month of a security program[cite: 3, 4]. They demonstrate to executive leadership and the Board of Directors that the security team is capable of delivering tangible operational improvements efficiently without waiting for large budget approvals[cite: 3, 4]. By leveraging existing assets to close obvious exposure gaps, quick wins build trust with financial stakeholders like CFO Robert Kim, validate the competency of the security leadership, and create momentum that eases the approval and rollout of larger, long-term strategic projects[cite: 3, 4].
