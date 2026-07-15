# MedDefense Attack Kill Chains

## Kill Chain 1: The External RaaS Pivot (Double Extortion)
* **Threat Actor:** Ransomware Groups (Organized Crime)
* **Target Asset:** Electronic Health Record Database (`ehr-db-01`)
* **Expected Impact:** Total operational freeze, massive data exfiltration, regulatory penalties, and reputational collapse.
* **Step 1 - Initial Access:**
    * **Vector:** Vulnerable Software Exploit
    * **Surface:** External
    * **Detail:** Attackers use an automated public exploit kit against the unpatched Apache 2.4.29 service running on `billing-srv-01` to establish a remote web shell foothold.
* **Step 2 - Establish Foothold:**
    * **Action:** The web shell drops a persistent command-and-control (C2) beacon running via memory injection to evade signature scans.
    * **MedDefense Weakness:** Outdated operating system and software stacks (Ubuntu 18.04 LTS EOL) combined with a lack of real-time endpoint threat monitoring.
* **Step 3 - Lateral Movement / Escalation:**
    * **Action:** Attackers execute network discovery scans and find `ehr-db-01` listening on port 5432. They run credential dumpers to extract active admin sessions left in memory.
    * **MedDefense Weakness:** A completely flat internal network topology with zero subnets or firewalls separating public web servers from core internal clinical servers.
* **Step 4 - Objective Execution:**
    * **Action:** Attackers connect directly to the PostgreSQL database engine, exfiltrate over 50,000 patient records to an external cloud bucket, wipe the local backup NAS directory paths, and execute domain-wide encryption.
    * **Data/System Affected:** `ehr-db-01` production database files and `nas-srv-01` backup shares.
* **Step 5 - Impact:**
    * **Business Impact:** Clinical downtime forcing ambulance diversion, massive financial ransom demands, and severe regulatory HIPAA penalties.
    * **CIA Pillars:** Confidentiality (High - patient records stolen), Integrity (High - configuration and data altered), Availability (High - databases encrypted).
* **Gaps Exploited:** GAP-001, GAP-005, GAP-008, GAP-011.
* **Break Points:**
    * *Intervention at Step 1:* Vulnerability Management Policy and automated patch deployment would have closed the Apache CVE, preventing the web shell from executing.
    * *Intervention at Step 3:* Implementing Network Segmentation (VLANs / Zero Trust Architecture) would block any direct connections from a DMZ server like `billing-srv-01` to an internal database server like `ehr-db-01`.

---

## Kill Chain 2: The Ghost Account Ransomware Raid
* **Threat Actor:** Ransomware Groups (Organized Crime / Initial Access Broker Affiliate)
* **Target Asset:** Active Directory Domain Controllers (`ad-dc-01` / `ad-dc-02`)
* **Expected Impact:** Complete enterprise infrastructure compromise and full Active Directory forest loss.
* **Step 1 - Initial Access:**
    * **Vector:** VPN Exploit / Stolen Credentials
    * **Surface:** External
    * **Detail:** An attacker purchases or cracks the legitimate remote VPN credentials belonging to an IT support contractor whose contract ended weeks prior.
* **Step 2 - Establish Foothold:**
    * **Action:** The attacker authenticates via the corporate remote VPN gateway during off-hours, gaining an interactive network presence.
    * **MedDefense Weakness:** Lack of multi-factor authentication (MFA) on remote entry points and stale contractor identities left enabled.
* **Step 3 - Lateral Movement / Escalation:**
    * **Action:** Operating from the authenticated VPN session, the attacker scans the network, targets a legacy system (`print-srv-01`), uses an exploit to harvest domain admin credentials, and logs into a Domain Controller.
    * **MedDefense Weakness:** A flat internal network topology combined with the presence of unpatched, legacy systems (Windows Server 2012 R2).
* **Step 4 - Objective Execution:**
    * **Action:** The attacker uses domain admin privileges to execute a mass Group Policy Object (GPO) deployment that disables endpoint antivirus engines and distributes ransomware to all connected devices.
    * **Data/System Affected:** Entire Active Directory domain structure and all domain-joined servers and workstations.
* **Step 5 - Impact:**
    * **Business Impact:** Total business paralysis, full infrastructure reconstruction costs, loss of communication channels, and extended administrative downtime.
    * **CIA Pillars:** Confidentiality (Low), Integrity (High - group policies corrupted), Availability (High - domain authentication services offline).
* **Gaps Exploited:** GAP-003, GAP-005, GAP-011.
* **Break Points:**
    * *Intervention at Step 1:* Automated Identity Lifecycle Management / HR offboarding workflows would disable domain identities instantly upon contract expiration, stopping authentication.
    * *Intervention at Step 2:* Enforcing mandatory Multi-Factor Authentication (MFA) on all external VPN sessions would block access even if the password was compromised.

---

## Kill Chain 3: The High-Profile EHR Insider Leak
* **Threat Actor:** Insider (Malicious)
* **Target Asset:** Electronic Health Record Database (`ehr-db-01`)
* **Expected Impact:** Extreme reputational damage, patient privacy lawsuits, and heavy statutory fines.
* **Step 1 - Initial Access:**
    * **Vector:** Shared / Default Credentials
    * **Surface:** Human / Internal
    * **Detail:** A registration desk clerk opens the patient database search panel using a shared administrative account that is left permanently logged in at a front-desk terminal.
* **Step 2 - Establish Foothold:**
    * **Action:** The clerk uses standard, authorized access parameters to search for and isolate the medical records of a high-profile local politician currently admitted to the hospital.
    * **MedDefense Weakness:** Reliance on shared generic logins without separate individual identity logging or automated terminal lock sessions.
* **Step 3 - Lateral Movement / Escalation:**
    * **Action:** Instead of editing data, the clerk takes photos of the private health records directly from the screen with a personal smartphone to bypass local logging blocks.
    * **MedDefense Weakness:** Lack of strict physical mobile device restrictions in open administrative desk areas and missing data security visibility.
* **Step 4 - Objective Execution:**
    * **Action:** The clerk leaks the patient data by sending the captured images to an external contact via personal social media channels, leading to a public broadcast.
    * **Data/System Affected:** Protected Health Information (PHI) corresponding to high-profile patients.
* **Step 5 - Impact:**
    * **Business Impact:** Massive media scandal, patient civil litigation, OCR investigation for HIPAA non-compliance, and severe institutional loss of trust.
    * **CIA Pillars:** Confidentiality (High - patient privacy compromised), Integrity (Low), Availability (Low).
* **Gaps Exploited:** GAP-007, GAP-011.
* **Break Points:**
    * *Intervention at Step 1:* Eliminating shared generic profiles and enforcing single, authenticated individual employee logins paired with an idle session timeout GPO.
    * *Intervention at Step 3:* Deploying User Behavior Analytics (UBA) or dedicated EHR audit log monitoring tools to alert security teams when a non-clinical administrative role views high-profile records outside their assigned assignment scope.

---

## Kill Chain 4: The Shadow IT Supply Chain Breach
* **Threat Actor:** Insider (Negligent) / Supply Chain Vulnerabilities
* **Target Asset:** Core Internal Clinical Network / Medical Subnets
* **Expected Impact:** Lateral network intrusion, potential corruption of diagnostic services, and downstream system infections.
* **Step 1 - Initial Access:**
    * **Vector:** Removable Devices / Unmanaged Endpoints
    * **Surface:** Internal
    * **Detail:** A senior cardiologist physically connects an unmanaged, unencrypted personal NAS appliance directly into an active, open office Ethernet port to save convenience copies of research data.
* **Step 2 - Establish Foothold:**
    * **Action:** The personal NAS requests and receives an active local DHCP lease on the internal hospital network, operating invisibly without IT authorization or tracking.
    * **MedDefense Weakness:** Absence of physical Network Access Control (NAC) and loose configuration enforcement over active office network ports.
* **Step 3 - Lateral Movement / Escalation:**
    * **Action:** Automated internet-facing malware strains infect the unprotected NAS device via its built-in legacy services. The malware scans out into the flat network and targets the unsegmented Siemens MRI workstation using legacy SMB vulnerabilities.
    * **MedDefense Weakness:** A completely flat internal network design with no isolation rules keeping unmanaged research hardware separated from life-critical medical imaging equipment.
* **Step 4 - Objective Execution:**
    * **Action:** The malware establishes control over the legacy Windows XP MRI console software, disrupting active imaging workflows and staging local file archives for exfiltration.
    * **Data/System Affected:** Siemens MRI controller console and local network image cache folders.
* **Step 5 - Impact:**
    * **Business Impact:** Interruption of diagnostic imaging services, delayed patient treatments, expensive device cleanup costs, and significant medical liability exposures.
    * **CIA Pillars:** Confidentiality (Medium), Integrity (High - imaging workstation parameters altered), Availability (High - clinical diagnostic system offline).
* **Gaps Exploited:** GAP-001, GAP-005, GAP-014.
* **Break Points:**
    * *Intervention at Step 1:* Implementing IEEE 802.1X Network Access Control (NAC) to detect and automatically quarantine any unauthorized hardware assets attempting to connect to physical wall jacks.
    * *Intervention at Step 3:* Enforcing strict Internal Network Segmentation to isolate clinical diagnostic equipment subnets from standard office utility jacks and unmanaged end-user hardware.

---

## Kill Chain 5: The Executive Spear-Phishing Wire Fraud
* **Threat Actor:** Business Email Compromise (BEC) / Impersonation Specialists
* **Target Asset:** Corporate Financial Assets / O365 Email Architecture
* **Expected Impact:** Major capital theft, executive profile takeovers, and compromised business communications.
* **Step 1 - Initial Access:**
    * **Vector:** Business Email Compromise (BEC) / Typosquatting
    * **Surface:** Human / External
    * **Detail:** The CFO receives an urgent email that mimics the exact naming convention of the hospital CEO, sent from an external lookalike domain, demanding an emergency invoice payment.
* **Step 2 - Establish Foothold:**
    * **Action:** The attacker establishes clear social communication parity with the CFO, utilizing pressure tactics ("confidential acquisition") to isolate the executive from standard administrative double-check workflows.
    * **MedDefense Weakness:** Absence of automated external email warning banners and weak configuration of inbound email authentication tools.
* **Step 3 - Lateral Movement / Escalation:**
    * **Action:** The CFO follows the instructions and circumvents standard accounting sign-offs, instructing the accounts team to authorize an emergency wire transfer of $85,000 to an unverified off-site account.
    * **MedDefense Weakness:** Lack of strict dual-authorization requirements or mandatory out-of-band phone call validation policies for out-of-band financial transactions.
* **Step 4 - Objective Execution:**
    * **Action:** The funds are wire-transferred out of the hospital's primary bank account directly into an external corporate money-laundering network, where they are quickly cleared.
    * **Data/System Affected:** Liquid operational capital reserves.
* **Step 5 - Impact:**
    * **Business Impact:** Direct financial loss, audit failures, internal administrative conflict, and a spike in executive liability insurance premiums.
    * **CIA Pillars:** Confidentiality (Low), Integrity (High - unauthorized transactions completed), Availability (Low).
* **Gaps Exploited:** GAP-011.
* **Break Points:**
    * *Intervention at Step 1:* Configuring an Email Security Gateway with strict DMARC reject rules and external email tagging to label the lookalike domain message with an explicit `[EXTERNAL]` warning banner.
    * *Intervention at Step 3:* Enforcing a formal Dual-Authorization Expense Policy requiring independent secondary sign-offs and verified out-of-band communication (such as a phone call or in-person check) before finalizing any high-value wire transfers.
