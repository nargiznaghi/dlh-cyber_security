# MITRE ATT&CK Mapping for MedDefense Security Scenarios

## 1. Scenario Alpha: "Operation Flatline" Ransomware Campaign

### Step 1: BlackReef affiliate purchases a target list containing MedDefense's unpatched VPN interfaces from a dark web Initial Access Broker.
* **Tactic:** Reconnaissance
* **Technique:** Gather Victim Network Information: IP Addresses (T1590.005)
* **MedDefense Factor:** Public disclosure of internet-facing vulnerabilities due to outdated firewall firmware and a lack of continuous external attack surface management.

### Step 2: Affiliate crafts and sends a spear-phishing email containing a link to a fake Fortinet support portal to IT Director Sarah Park, who downloads and runs a malicious macro document.
* **Tactic:** Initial Access
* **Technique:** Phishing: Spearphishing Link (T1566.002)
* **MedDefense Factor:** Lack of email security gateways, missing DMARC/SPF/DKIM alignment, absent macro execution block GPOs, and low employee security training rates.

### Step 3: Malicious macro runs a PowerShell command that establishes a persistent reverse shell disguised as a Windows Update scheduled task running every 30 minutes.
* **Tactic:** Persistence
* **Technique:** Scheduled Task/Job: Scheduled Task (T1053.005)
* **MedDefense Factor:** Lax outbound firewall egress policies allowing arbitrary traffic, combined with a lack of local endpoint logging or behavioral analysis to flag abnormal system scripts mimicking legitimate OS updates.

### Step 4: Affiliate runs network discovery commands from Sarah's workstation to scan the flat subnet and identify Domain Controllers, EHR servers, and backup systems.
* **Tactic:** Discovery
* **Technique:** System Network Configuration Discovery (T1016)
* **MedDefense Factor:** A completely flat internal network topology lacking internal subnet segregation, allowing any compromised endpoint to fully scan and query critical servers.

### Step 5: Affiliate executes Mimikatz on Sarah's workstation, harvesting the NTLM hash of a Domain Admin service account (`svc_backup`) cached from a previous session.
* **Tactic:** Credential Access
* **Technique:** OS Credential Dumping: LSASS Memory (T1003.001)
* **MedDefense Factor:** Missing local security features (such as Windows Credential Guard or LSA protection) and poor admin practices where high-privilege credentials are used on standard endpoints.

### Step 6: Affiliate executes a Pass-the-Hash attack using the harvested `svc_backup` credentials to authenticate directly to the Domain Controller.
* **Tactic:** Lateral Movement
* **Technique:** Use Alternate Authentication Material: Pass the Hash (T1550.002)
* **MedDefense Factor:** Active Directory accepting insecure legacy authentication methods (NTLM v1/v2), paired with the lack of host-to-host communication blocks.

### Step 7: Affiliate dumps 35 GB of EHR patient database tables over port 5432 and 8 GB of internal corporate documents, exfiltrating the data via Rclone over HTTPS.
* **Tactic:** Exfiltration
* **Technique:** Exfiltration Over Web Service: Exfiltration to Cloud Storage (T1567.002)
* **MedDefense Factor:** Open internal access to database engines network-wide (GAP-005) and lack of outbound Data Loss Prevention (DLP) controls to alert on large, encrypted file transfers.

### Step 8: Affiliate accesses the local backup NAS management interface via port 5001 to delete all backup folders, and executes commands to purge Volume Shadow Copies on local hosts.
* **Tactic:** Impact
* **Technique:** Inhibit System Recovery (T1490)
* **MedDefense Factor:** Backup NAS reachable directly over the main local flat network, use of shared/default credentials, and the absence of immutable or physical offline backups.

### Step 9: Affiliate deploys ransomware to all Windows hosts globally via Active Directory Group Policy Objects, and encrypts Linux servers separately using SSH keys found in plaintext.
* **Tactic:** Impact
* **Technique:** Data Encrypted for Impact (T1486)
* **MedDefense Factor:** Group Policy deployment processes lacking technical dual-authorization gates, and administrative credentials for Linux workloads stored in cleartext configurations.

---

## 2. Scenario Beta: "The Quiet Departure" -- Insider Data Theft

### Step 1: A billing clerk (Maria) notified of pending layoffs abuses her active administrative credentials to plan a high-volume theft of patient records.
* **Tactic:** Initial Access
* **Technique:** Valid Accounts: Domain Accounts (T1078.002)
* **MedDefense Factor:** Lack of automated HR-to-IT collaboration triggers to immediately place departing employees under strict security profile monitoring or restricted access tiers.

### Step 2: Maria assesses EHR access permissions and notes that she can access detailed clinical history without meeting rate-limiting thresholds or triggering security alerts.
* **Tactic:** Discovery
* **Technique:** File and Directory Discovery (T1083)
* **MedDefense Factor:** EHR lack of built-in threshold alerts or behavior-profiling capabilities regarding high-volume read transactions.

### Step 3: Maria bulk-exports clinical summaries of 200 patients per day over two weeks to local CSV files. Audit logs are recorded but never proactively reviewed.
* **Tactic:** Collection
* **Technique:** Data from Information Repositories: Medical Records (T1213)
* **MedDefense Factor:** Permissive EHR configurations permitting bulk exports of patient details without a manager's digital approval, and lack of SIEM integration to auto-parse application logs.

### Step 4: Maria copies the exported CSV database files from her workstation to a personal USB drive.
* **Tactic:** Exfiltration
* **Technique:** Exfiltration Over Physical Medium: Exfiltration over USB (T1052.001)
* **MedDefense Factor:** Lack of active Endpoint Protection policies to block write permissions to unapproved, non-encrypted external USB devices.

### Step 5: Maria deletes the extracted files from her workstation and empties the recycle bin to remove physical indicators on the host.
* **Tactic:** Defense Evasion
* **Technique:** Indicator Removal: File Deletion (T1070.004)
* **MedDefense Factor:** Clunky, vendor-managed local application logs that are not ingested by a centralized corporate security team in near real-time.

### Step 6: Maria discovers database connection profiles containing plaintext administrative credentials in a local application configuration file and saves it to her USB.
* **Tactic:** Credential Access
* **Technique:** Credentials in Files: Cleartext Passwords (T1552.001)
* **MedDefense Factor:** Poor secure development practices where hardcoded databases credentials reside in local configuration files on standard endpoints.

### Step 7: HR initiates Maria's departure processing, but the IT deactivation ticket sits unresolved in a backlog queue for 5 days.
* **Tactic:** Persistence
* **Technique:** Valid Accounts: Domain Accounts (T1078.002)
* **MedDefense Factor:** Lack of automated identity provisioning systems or operational Service Level Agreements (SLAs) for offboarding terminated workers.

### Step 8: Maria uses her active VPN session credentials from home to access the billing server database and steal 400 additional records before disconnecting.
* **Tactic:** Initial Access / Exfiltration
* **Technique:** External Remote Services (T1133)
* **MedDefense Factor:** Outbound VPN services allowing continuous authenticated access from home without enforcing active Multi-Factor Authentication (MFA) challenges.

---

## 3. ATT&CK Coverage Assessment

Looking at both threat scenarios, the tactics of **Initial Access**, **Credential Access**, **Discovery**, and **Exfiltration** appear in both attack sequences. This cross-scenario convergence shows that MedDefense's most critical operational detection gap lies in the **Credential Access** and **Discovery** stages. Because the internal network is completely flat and local user workstations lack behavioral endpoint protection, attackers (whether an external Ransomware affiliate or a malicious internal employee) can easily dump local memory, read plain-text database credentials, discover high-value targets across subnets, and query database tables globally without triggering a single alert. MedDefense urgently needs to deploy an Endpoint Detection and Response (EDR) agent across all workstations to detect credential-harvesting tools like Mimikatz, and integrate network-level behavioral monitoring to flag unexpected network discovery activities.
