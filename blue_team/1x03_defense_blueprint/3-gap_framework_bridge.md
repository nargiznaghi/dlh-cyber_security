# 3. The Gap-to-Framework Bridge

## Gap Analysis & Framework Mapping

### Gap Reference: GAP-001
* **Description:** Absence of an automated, centralized enterprise asset management and discovery process.
* **Vulnerability Evidence:** Unmanaged devices and rogue endpoints present on internal hospital networks (Project 1x00 Asset Discovery).
* **Threat Context:** External Attackers & Insider Threats using unknown/unmonitored devices as initial execution vectors in the Attack Lifecycle (1x01).
* **NIST CSF Function:** Identify (ID)
* **CIS Control:** CIS Control 1: Inventory and Control of Enterprise Assets
* **Recommended Action:** Deploy an automated network-based asset discovery tool and enforce active IP address management to maintain an accurate, real-time asset inventory.

### Gap Reference: GAP-002
* **Description:** Unpatched OS and third-party software vulnerabilities across critical infrastructure.
* **Vulnerability Evidence:** Outdated software versions with high/critical CVEs identified during vulnerability scans (Project 1x02 Finding 001/002).
* **Threat Context:** Cybercrime Syndicates exploiting known public vulnerabilities to gain initial access and execute unauthorized code.
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 7: Continuous Vulnerability Management
* **Recommended Action:** Implement an automated patch management pipeline to schedule, test, and apply critical system updates within a 30-day window.

### Gap Reference: GAP-003
* **Description:** Flat, unsegmented enterprise network architecture separating medical devices, servers, and user workstations.
* **Vulnerability Evidence:** Open internal ports and unrestricted service access across subnets (Project 1x02 Finding 003 - PostgreSQL & SMB unrestricted access).
* **Threat Context:** Ransomware Operators moving laterally across internal networks to compromise ePHI databases and clinical workstations.
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 12: Network Infrastructure Management
* **Recommended Action:** Design and deploy VLAN-based network segmentation with firewall access control lists (ACLs) isolating medical devices and database servers from standard user networks.

### Gap Reference: GAP-004
* **Description:** Lack of Multi-Factor Authentication (MFA) on remote and administrative access endpoints.
* **Vulnerability Evidence:** Weak authentication policies and administrative interfaces accessible via single-factor credentials (Project 1x02 Finding 004).
* **Threat Context:** Credential Brokers using brute-force attacks or credential stuffing to hijack administrative sessions.
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 6: Access Control Management
* **Recommended Action:** Enforce mandatory Multi-Factor Authentication (MFA) across all remote access VPNs, cloud applications, and privileged administrative user accounts.

### Gap Reference: GAP-005
* **Description:** Absence of centralized security log aggregation and monitoring capabilities.
* **Vulnerability Evidence:** System logs remain isolated on local endpoints with zero security event correlation (Project 1x02 Finding 005).
* **Threat Context:** Advanced Persistent Threats (APTs) operating unnoticed within internal systems for extended dwell times.
* **NIST CSF Function:** Detect (DE)
* **CIS Control:** CIS Control 8: Audit Log Management
* **Recommended Action:** Deploy a centralized syslog server or lightweight SIEM to aggregate event logs from domain controllers, firewalls, and critical servers.

### Gap Reference: GAP-006
* **Description:** Insecure backup architecture lacking isolation, immutability, and routine restoration testing.
* **Vulnerability Evidence:** Online, unencrypted network share backups susceptible to ransomware encryption (Project 1x02 Finding 006).
* **Threat Context:** Ransomware Groups deliberately seeking out and destroying network backups prior to executing data encryption.
* **NIST CSF Function:** Recover (RC)
* **CIS Control:** CIS Control 11: Data Recovery
* **Recommended Action:** Establish immutable, air-gapped backup storage and perform quarterly restoration exercises to guarantee operational recovery times.

### Gap Reference: GAP-007
* **Description:** Lack of formal, tested Incident Response plans and breach notification procedures.
* **Vulnerability Evidence:** Absence of written playbooks for triaging, containing, and reporting active security breaches (Project 1x02 Finding 007).
* **Threat Context:** Incident Responders delayed during active ransomware or data breach events, escalating operational downtime and regulatory penalties.
* **NIST CSF Function:** Respond (RS)
* **CIS Control:** CIS Control 17: Incident Response Management
* **Recommended Action:** Draft a formal Incident Response Plan with clear escalation workflows and conduct tabletop exercises with key stakeholders.

### Gap Reference: GAP-008
* **Description:** Lack of a structured security awareness and phishing training program for workforce personnel.
* **Vulnerability Evidence:** Non-technical staff susceptible to social engineering, phishing, and credential harvest attacks (Project 1x02 Finding 008).
* **Threat Context:** Phishing Threat Actors targeting clinical staff to deliver initial malware payloads or harvest domain credentials.
* **NIST CSF Function:** Protect (PR)
* **CIS Control:** CIS Control 14: Security Awareness and Skills Training
* **Recommended Action:** Launch a mandatory security awareness training curriculum paired with quarterly simulated phishing campaigns for all hospital employees.

---

## Traceability Summary Table

| Gap Ref | Description | Vulnerability Evidence | Threat Context | NIST CSF | CIS Control | Recommended Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **GAP-001** | Unmonitored Asset Inventory | Rogue endpoints in 1x00 | External & Insider Attackers | Identify (ID) | CIS Control 1 | Automated asset discovery & IPAM deployment. |
| **GAP-002** | Unpatched Critical Vulnerabilities | Outdated OS/Software (1x02) | Cybercrime / Exploit Kits | Protect (PR) | CIS Control 7 | Deploy automated 30-day patch management. |
| **GAP-003** | Flat Unsegmented Network | Unrestricted Database Access (1x02) | Ransomware Lateral Movement | Protect (PR) | CIS Control 12 | Implement VLAN segmentation & firewall ACLs. |
| **GAP-004** | Missing MFA for Admin Access | Single-Factor Auth (1x02) | Credential Stuffing / Hijacking | Protect (PR) | CIS Control 6 | Enforce MFA on VPNs, Cloud & Admin access. |
| **GAP-005** | No Centralized Logging | Isolated Local Logs (1x02) | Undetected Threat Actors / APTs | Detect (DE) | CIS Control 8 | Deploy centralized log server / SIEM pipeline. |
| **GAP-006** | Unprotected Backup Infrastructure | Online Unencrypted Shares (1x02) | Ransomware Backup Destruction | Recover (RC) | CIS Control 11 | Establish air-gapped, immutable backups. |
| **GAP-007** | Absence of IR Playbooks | No Breach Escalation Process (1x02) | Delayed Incident Response | Respond (RS) | CIS Control 17 | Develop IR Plan & conduct tabletop drills. |
| **GAP-008** | Lack of Employee Training | Phishing Susceptibility (1x02) | Social Engineering / Phishing | Protect (PR) | CIS Control 14 | Implement awareness training & phishing simulation. |
