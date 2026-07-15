# MedDefense Comprehensive Threat Scenarios

This document outlines three high-consequence, realistic threat scenarios targeting MedDefense Health Systems. Each scenario integrates threat actor profiles, initial vectors, attack surfaces, MITRE ATT&CK mapping, STRIDE classifications, and exploited security gaps to illustrate the systemic risks faced by the organization.

---

## Scenario 1: "Operation Flatline" Ransomware Campaign (External Attack)

* **Title:** Scenario 1 - The BlackReef Double-Extortion Ransomware Campaign
* **Threat Actor:** BlackReef Affiliate (Organized Crime / Ransomware-as-a-Service [RaaS] Group)
* **Motivation:** Financial Gain (Extortion/Ransom)
* **Initial Vector:** Spear-phishing Link / Exploit Public-Facing VPN Appliance
* **Attack Surface Exploited:** Human (Phishing Email) and External (Unpatched Fortinet VPN Gateway)

### Attack Sequence:
* **Step 1: Reconnaissance (Tactic: Reconnaissance)**
  The BlackReef affiliate purchases an initial access list containing external, unpatched Fortinet VPN gateway configurations for healthcare systems, identifying MedDefense's public-facing assets.
* **Step 2: Resource Development & Initial Access (Tactics: Resource Development, Initial Access)**
  The affiliate delivers a targeted spear-phishing email containing a link to a credential-harvesting/fake support portal to IT Director Sarah Park, executing a malicious macro document upon download to run a reverse shell.
* **Step 3: Establish Foothold & Persistence (Tactic: Persistence)**
  The reverse shell connects back to the attacker's command-and-control (C2) server and establishes persistence by setting up a malicious Windows scheduled task disguised as a standard system update running every 30 minutes.
* **Step 4: Discovery (Tactic: Discovery)**
  The attacker runs automated discovery scripts (`nltest`, `net group`, and `arp -a`) to discover active assets (`ad-dc-01`, `ehr-srv-01`, `ehr-db-01`, `nas-srv-01`) on the unsegmented, flat internal network.
* **Step 5: Credential Access (Tactic: Credential Access)**
  The attacker runs Mimikatz on Sarah’s workstation to dump cached administrative credentials, capturing the NTLM hash of a Domain Admin service account (`svc_backup`) left in memory.
* **Step 6: Lateral Movement (Tactic: Lateral Movement)**
  The attacker performs a Pass-the-Hash attack using the hijacked `svc_backup` credentials to authenticate directly to the active Domain Controller (`ad-dc-01`).
* **Step 7: Collection & Exfiltration (Tactics: Collection, Exfiltration)**
  The attacker queries `ehr-db-01` via Port 5432, extracts approximately 35 GB of EHR patient data tables, and compresses and exfiltrates the archive over HTTPS using Rclone.
* **Step 8: Impact - System Recovery Invalidation (Tactic: Impact)**
  Using Domain Admin privileges, the attacker accesses the network-accessible backup storage (`nas-srv-01`) management console, deletes active backup configurations and existing backups, and purges host Volume Shadow Copies.
* **Step 9: Impact - Ransomware Execution (Tactic: Impact)**
  The attacker creates an Active Directory Group Policy Object (GPO) to execute the ransomware payload domain-wide within 90 minutes, while Linux servers are encrypted via SSH using configurations harvested in plain-text.

### STRIDE Categories Triggered:
* **Spoofing (EHR-S2):** Bypassing controls by mimicking local trusted systems on the unsegmented network.
* **Tampering (EHR-T1):** Modifying host operating systems and directory settings.
* **Information Disclosure (EHR-I1):** Exfiltrating sensitive patient records.
* **Denial of Service (EHR-D2):** Encrypting systems and wiping operational files.
* **Elevation of Privilege (EHR-E1):** Escalating from standard workstation access to Domain Admin.

### MedDefense Assets Impacted:
* `ad-dc-01` / `ad-dc-02` (Active Directory Domain Controllers)
* `ehr-srv-01` & `ehr-db-01` (Core Electronic Health Records system)
* `nas-srv-01` / `NAS-01` (Local Storage Backup System)
* Workstations at Corporate HQ (`WS-HQ-01`)

### Business Impact:
* **Clinical:** High-priority clinical operations freeze. Complete blackout of patient charts, forcing ambulance diversion and delaying life-critical surgeries.
* **Financial:** Massive business interruption losses, restoration and consulting fees, and possible double-extortion ransom demands.
* **Regulatory:** Severe OCR HIPAA investigation, potentially leading to millions in penalties due to failure to protect patient databases.
* **Reputational:** Heavy local coverage, leading to permanent loss of patient and partner trust.

### Gaps Exploited:
* **GAP-001 (Outdated OS / Patching):** Firewalls left unpatched, allowing Initial Access Brokers to easily profile and compromise outer networks.
* **GAP-005 (Flat Network Architecture):** Allowed complete horizontal lateral movement from HQ to central EHR and database assets.
* **GAP-008 (Lack of Offline Backups):** The local backup NAS was attached to the production network, facilitating easy compromise and deletion of backup files.
* **GAP-011 (Weak Identity Policies & Missing MFA):** Lack of MFA on remote gateways and weak local security allowed simple credential extraction and Pass-the-Hash movement.

### Detection Opportunities:
* **Step 3 (Backdoor Setup):** Endpoint Detection and Response (EDR) software on Sarah's workstation could have flagged the creation of an abnormal scheduled task executing system cmdlines.
* **Step 5 (Mimikatz):** Real-time endpoint memory monitoring (LSA protection) would block LSASS reading attempts, alerting on credential dumping.
* **Step 7 (Data Exfiltration):** Network-level flow logs and automated Data Loss Prevention (DLP) alerts could flag massive outgoing HTTPS transfers to unfamiliar cloud endpoints.

---

## Scenario 2: "The Quiet Departure" (Internal Attack)

* **Title:** Scenario 2 - Insider Exfiltration of EHR Billing and Patient Records
* **Threat Actor:** Malicious Insider (Disgruntled billing department employee [Maria])
* **Motivation:** Financial Gain (selling stolen records on darknet markets) and Revenge
* **Initial Vector:** Abuse of Active Legitimate Access
* **Attack Surface Exploited:** Human & Internal Corporate Network

### Attack Sequence:
* **Step 1: Reconnaissance (Tactic: Reconnaissance)**
  Upon finding out she faces layoffs, Maria inventories the network directories and software systems she can reach using her valid company credentials.
* **Step 2: Collection (Tactic: Collection)**
  Using normal billing and read-only EHR search views, Maria queries patient lists, noting the EHR app lacks query limits or suspicious activity volume alarms.
* **Step 3: Collection (Tactic: Collection)**
  Maria systematically utilizes the application’s built-in export features to export batches of 200 patient profiles daily to local CSV spreadsheets.
* **Step 4: Exfiltration (Tactic: Exfiltration)**
  Maria copies the compiled spreadsheets onto a personal, unencrypted USB drive plugged directly into her office desktop terminal.
* **Step 5: Defense Evasion (Tactic: Defense Evasion)**
  To erase host footprints, Maria deletes the downloaded CSV files and purges her local trash folder.
* **Step 6: Credential Access (Tactic: Credential Access)**
  Maria locates a cleartext system configuration file stored locally on her system that contains hardcoded administrative credentials to `billing-srv-01` and copies it to her USB.
* **Step 7: Persistence (Tactic: Persistence)**
  Maria departs the firm, but her active network identities are not deactivated immediately by IT due to a long ticket backlog.
* **Step 8: Lateral Movement & Exfiltration (Tactics: Lateral Movement, Exfiltration)**
  Three days post-termination, Maria connects to the remote VPN using her still-active profile, logs into the billing server database, and steals another 400 records.

### STRIDE Categories Triggered:
* **Spoofing (EHR-S1):** Re-authenticating post-termination to pose as a valid team member.
* **Repudiation (EHR-R1):** Bulk exports occur under a common administrative system login, preventing precise verification of the actual actor.
* **Information Disclosure (EHR-I2):** Saving patient datasets to an unmanaged personal USB drive.

### MedDefense Assets Impacted:
* `billing-srv-01` (Internal Billing Server)
* `ehr-srv-01` (EHR App Server)
* Billing Workstations

### Business Impact:
* **Clinical:** Low direct operational downtime, but compromises clinical care continuity if stolen patient identities are modified or swapped on the black market.
* **Financial:** Massive civil litigation liabilities from compromised patients, forensic analysis costs, and legal defense fees.
* **Regulatory:** Major OCR investigation for failing to restrict administrative privileges, leading to substantial HIPAA civil monetary penalties.
* **Reputational:** Devastating disclosure of insider theft, resulting in loss of community and client trust.

### Gaps Exploited:
* **GAP-007 (Audit Log Retrospection):** Application access logs are vendor-controlled, requiring 48-hour requests, and are never reviewed proactively.
* **GAP-011 (Lax Access Governance & MFA Absence):** Absence of automated offboarding triggers, lack of VPN MFA, and administrative passwords left in local text files.
* **GAP-014 (Lack of USB Control):** Missing GPO restrictions on local workstations to block data copying to unauthorized USB mass storage.

### Detection Opportunities:
* **Step 3 (Bulk Export):** Application-layer behavior profiling could alert on an unusual export volume threshold from a single billing terminal.
* **Step 4 (USB Copy):** Endpoint protection software could block data transfers or alert on bulk data writing activities targeting removable USB drives.
* **Step 8 (Post-Termination Login):** Automated HR offboarding integration could disable VPN access instantly upon termination, blocking the remote session entirely.

---

## Scenario 3: "The Shadow Gateway" (Third-Party Attack)

* **Title:** Scenario 3 - Supply Chain Intrusion via Third-Party Biomedical Remote Access
* **Threat Actor:** External APT / Specialized Access Brokers
* **Motivation:** Espionage / Financial Gain / Disruptive Intent
* **Initial Vector:** Compromise of Third-Party Remote Support Connection
* **Attack Surface Exploited:** External (Vendor Remote Connection Interface) and Internal (Biomedical Network Segment)

### Attack Sequence:
* **Step 1: Initial Access (Tactic: Initial Access)**
  Attackers compromise the offsite corporate network of MedDefense’s remote medical device maintenance vendor (e.g., HVAC or biomedical support). They harvest valid, unauthenticated VPN connection keys and jump directly onto the MedDefense internal network.
* **Step 2: Discovery (Tactic: Discovery)**
  Operating inside the network, the attacker performs automated discovery scans, discovering the Siemens MRI controller workstation running an outdated operating system (Windows XP) and the central PACS archive (`pacs-srv-01`).
* **Step 3: Privilege Escalation & Lateral Movement (Tactics: Privilege Escalation, Lateral Movement)**
  The attacker exploits legacy SMBv1 vulnerabilities (such as EternalBlue) to establish remote SYSTEM command execution on the Windows XP MRI console, bypassing local user authorization.
* **Step 4: Tampering & Collection (Tactics: Tampering, Collection)**
  The attacker gains full access to the PACS image repository, downloading sensitive patient imaging files and modifying diagnostic MRI data attributes to alter radiological results.
* **Step 5: Impact (Tactic: Impact)**
  The attacker deploys a destructive payload that crashes the MRI workstation's software, corrupting local system folders and preventing clinical personnel from carrying out imaging work.

### STRIDE Categories Triggered:
* **Spoofing (EHR-S2):** Utilizing unmonitored vendor connections to bypass local host-based network boundary controls.
* **Tampering (EHR-T1):** Altering DICOM records and PACS imaging metadata.
* **Information Disclosure (EHR-I1):** Accessing and exfiltrating private medical scan archives.
* **Denial of Service (EHR-D1):** Disabling critical clinical diagnostic hardware.

### MedDefense Assets Impacted:
* Siemens MRI Workstation (running Windows XP)
* `pacs-srv-01` (Primary Medical Imaging PACS Server)
* Connected local radiology workstations

### Business Impact:
* **Clinical:** High immediate patient impact. Halting MRI diagnostic schedules delays critical surgeries, and altered scans lead to incorrect medical treatments.
* **Financial:** Significant costs to rebuild and sanitize clinical computers, plus potential litigation from treatment errors.
* **Regulatory:** Serious HIPAA violations for exposing PHI and failing to protect diagnostic databases.
* **Reputational:** Loss of clinical referrals due to questions over the integrity of medical diagnoses.

### Gaps Exploited:
* **GAP-001 (Legacy OS Support):** Use of end-of-life Windows XP hosts with unpatched remote execution vulnerabilities.
* **GAP-005 (Lack of Logical Segmentation):** Flat network architecture allowed vendor access paths to directly reach internal clinical segments.
* **GAP-011 (Lax Third-Party Access Controls):** Unmonitored, multi-session remote vendor accounts with no MFA or administrative session timeouts.

### Detection Opportunities:
* **Step 1 (Vendor Connection):** Multi-factor authentication challenges on all incoming partner VPN connections would block stolen credential usage.
* **Step 2 (Network Scanning):** Network Intrusion Detection Systems (NIDS) would alert on discovery scans launched from a vendor maintenance terminal.
* **Step 3 (SMB Exploitation):** Host-based firewalls and endpoint security software could detect and block exploit behaviors targeting deprecated SMBv1 ports.
