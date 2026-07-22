# Section 19: The Remediation Map

This document outlines the detailed, operationalized remediation strategy for the eight prioritized security findings identified in the assessment. Remediation in a healthcare environment must balance security posture improvements against operational uptime, clinical workflows, and system availability.

---

## Remediation Strategy Summary Matrix

| Finding ID | Title | Response Type | Timeline | Owner | Cost Estimate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FIND-01** | Unauthenticated RCE via Apache Tomcat AJP (Ghostcat) | Patch | Immediate (24-48h) | IT Infrastructure | $0 - $1K |
| **FIND-02** | Hardcoded Database Credentials in Web Application | Configuration Change | Immediate (24-48h) | Security / DevOps | $0 - $1K |
| **FIND-03** | Missing TLS Encryption on Internal Clinical Workstations | Configuration Change | 7 days | IT Infrastructure | $1K - $10K |
| **FIND-04** | Outdated Apache HTTP Server with Buffer Overflow Vulnerability | Patch | 7 days | IT Infrastructure | $0 - $1K |
| **FIND-05** | Unrestricted Active Directory NTLMv1 Authentication | Configuration Change | 30 days | Security / Active Directory Team | $1K - $10K |
| **FIND-06** | Legacy Windows Server 2008 R2 Hosting EHR Subsystem | Compensating Control | 30 days | IT / Clinical Systems | $10K - $50K |
| **FIND-07** | Lack of Multi-Factor Authentication on Remote VPN Access | Configuration Change | 30 days | IT / Security | $10K - $50K |
| **FIND-08** | Legacy Unencrypted Legacy Medical Imaging Archive (PACS) | Exception | 90 days | Security / Clinical Imaging | $50K+ |

---

## Detailed Remediation Plans

### Finding FIND-01: Unauthenticated RCE via Apache Tomcat AJP (Ghostcat / CVE-2020-1938)

* **Response Type:** Patch
* **Patch Source:** Apache Tomcat Official Download Center (`https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.31`) or OS Vendor Repository (APT/YUM).
* **Prerequisites:**
  * Validate application compatibility in the Staging/QA environment.
  * Schedule a 30-minute maintenance window outside peak clinical rounds (02:00–02:30 AM).
  * Take a full virtual machine snapshot / volume backup prior to upgrade.
* **Rollback Plan:**
  * Restore virtual machine snapshot from backup if application services fail to start or report runtime errors.
  * Revert Tomcat configuration binaries to pre-patch state within 15 minutes.
* **Operational Risk:** Web application temporary downtime during service restart; potential breakage if custom AJP attributes are used between Apache HTTPD and Tomcat without updating `secretRequired` parameters.
* **Timeline:** Immediate (24–48 hours)
* **Owner:** IT Infrastructure Team
* **Cost Estimate:** $0–$1K

---

### Finding FIND-02: Hardcoded Database Credentials in Application Source Code

* **Response Type:** Configuration Change
* **Change Description:**
  1. Remove plaintext database connection strings from application configuration files (`config.php` / `application.yml`).
  2. Implement environment variables or pull secrets dynamically from HashiCorp Vault / AWS Secrets Manager.
  3. Rotate all exposed database user passwords immediately in MySQL/PostgreSQL.
* **Impact Assessment:** Application services will experience a brief (5–10 minute) service restart during deployment of updated configuration files. No patient data access disrupted if performed in off-peak hours.
* **Timeline:** Immediate (24–48 hours)
* **Owner:** Security & Application DevOps Team
* **Cost Estimate:** $0–$1K

---

### Finding FIND-03: Missing TLS Encryption on Internal Clinical Workstations

* **Response Type:** Configuration Change
* **Change Description:**
  1. Deploy Group Policy Object (GPO) enforcing HTTPS and disabling HTTP (port 80) across all internal clinical web servers.
  2. Issue internal x509 TLS v1.3 certificates via Microsoft Active Directory Certificate Services (AD CS).
  3. Enforce HTTP Strict Transport Security (HSTS) headers across all web interfaces.
* **Impact Assessment:** Legacy internal browsers or unmanaged devices without internal CA trust anchors will trigger TLS warnings until updated. Network traffic will be briefly re-routed.
* **Timeline:** 7 days
* **Owner:** IT Infrastructure / Network Operations
* **Cost Estimate:** $1K–$10K

---

### Finding FIND-04: Outdated Apache HTTP Server with Buffer Overflow Flaw (CVE-2021-44790)

* **Response Type:** Patch
* **Patch Source:** Vendor security updates (`https://httpd.apache.org/security/vulnerabilities_24.html`) or Linux distribution package manager (`apt-get update && apt-get install --only-upgrade apache2`).
* **Prerequisites:**
  * Staging verification of `mod_lua` dependency (disable `mod_lua` if unused).
  * 1-hour maintenance window; application load balancer draining.
  * System backup / LVM snapshot.
* **Rollback Plan:**
  * Revert package upgrade using `apt-get install apache2=2.4.x-previous` or revert virtual machine snapshot.
* **Operational Risk:** Restarting Apache HTTPD drops active HTTP sessions; potential custom module incompatibility if Apache core binaries upgrade minor versions.
* **Timeline:** 7 days
* **Owner:** IT Infrastructure
* **Cost Estimate:** $0–$1K

---

### Finding FIND-05: Unrestricted Active Directory NTLMv1 Authentication Enabled

* **Response Type:** Configuration Change
* **Change Description:**
  1. Enable NTLM auditing via GPO (`Network security: Restrict NTLM: Audit NTLM authentication in this domain`).
  2. Identify legacy applications relying on NTLMv1 and upgrade authentication mechanisms to Kerberos or NTLMv2.
  3. Change GPO policy `Network security: LAN Manager authentication level` to `Send NTLMv2 response only. Refuse LM & NTLM`.
* **Impact Assessment:** Legacy devices, old embedded clinical hardware, or non-domain joined systems using hardcoded NTLMv1 will fail to authenticate to domain resources.
* **Timeline:** 30 days
* **Owner:** Active Directory / Security Operations Team
* **Cost Estimate:** $1K–$10K

---

### Finding FIND-06: End-of-Life Windows Server 2008 R2 Hosting Legacy EHR Module

* **Response Type:** Compensating Control
* **Control Description:**
  1. Isolate the server into an isolated, micro-segmented VLAN with zero direct internet access.
  2. Implement an inline Web Application Firewall (WAF) and Next-Generation Firewall (NGFW) with strict IP whitelist access rules.
  3. Install endpoint detection and response (EDR) with legacy OS support and enable strict virtual patching via host intrusion prevention (HIPS).
* **Residual Risk:** Underlying operating system vulnerabilities remain unpatched by Microsoft, leaving the host susceptible to zero-day kernel/local privilege escalation exploits if network perimeter controls are bypassed.
* **Timeline:** 30 days
* **Owner:** IT / Network Security / Clinical Systems
* **Cost Estimate:** $10K–$50K

---

### Finding FIND-07: Remote Access VPN Lacks Multi-Factor Authentication (MFA)

* **Response Type:** Configuration Change
* **Change Description:**
  1. Integrate VPN gateway (e.g., Cisco AnyConnect / Fortinet) with Azure AD / Duo MFA via RADIUS / SAML 2.0.
  2. Enforce conditional access policies requiring MFA for all remote administrative and clinical staff connections.
* **Impact Assessment:** User workflow change for remote workforce; requires device enrollment into authenticator apps or hardware token distribution.
* **Timeline:** 30 days
* **Owner:** IT / Identity & Access Management Team
* **Cost Estimate:** $10K–$50K

---

### Finding FIND-08: Legacy Unencrypted PACS Imaging Archive Server (DICOM Protocol)

* **Response Type:** Exception
* **Justification:** The legacy PACS storage array running DICOM v3.0 lacks native TLS protocol support at the firmware level. Upgrading or replacing the proprietary storage infrastructure requires vendor capital expenditure approval ($250K+) and medical device re-certification, which cannot be executed within standard remediation windows without interrupting active diagnostic imaging workflows.
* **Review Date:** Re-assess on 2027-01-15 (Annual Budget & Capital Infrastructure Review Cycle).
* **Monitoring & Mitigation:**
  1. Micro-segment PACS server traffic to dedicated VLAN accessible only by authorized RADIOLOGY workstations.
  2. Deploy Network Intrusion Detection System (NIDS) rules to detect unencrypted DICOM traffic anomalies or unauthorized connection attempts.
  3. Enforce strict 802.1X port security on all physical network drops in radiology departments.
* **Timeline:** 90 days (Exception registration and compensating monitoring setup)
* **Owner:** Security Governance / Clinical Imaging Department
* **Cost Estimate:** $50K+
