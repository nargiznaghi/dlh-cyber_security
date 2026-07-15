# MedDefense Attack Surface Map

## Section 1: External Surface

*   **Entry Point:** Patient Portal (`web-srv-01`)
    *   **What it is:** Public-facing web application used by patients to access records and billing.
    *   **Asset Behind It:** Apache 2.4.29 web server hosting patient interface.
    *   **Protection Exists:** Standard TLS encryption; perimeter firewall filtering basic ports.
    *   **Gap Documented:** GAP-001 (Unpatched public-facing vulnerabilities; runs an outdated software stack susceptible to remote code execution).

*   **Entry Point:** VPN Endpoints
    *   **What it is:** Remote access gateway for clinical staff and external contractors.
    *   **Asset Behind It:** FortiGate 100F Perimeter Firewall appliance.
    *   **Protection Exists:** Standard username/password authentication profile.
    *   **Gap Documented:** GAP-011 (Missing Multi-Factor Authentication for administrative and remote connections) and GAP-001 (Unpatched firmware CVEs on the perimeter appliance).

*   **Entry Point:** Email Infrastructure
    *   **What it is:** Enterprise cloud communications and collaboration framework.
    *   **Asset Behind It:** Microsoft Office 365 E3 Tenant.
    *   **Protection Exists:** Basic built-in Microsoft cloud spam filtering.
    *   **Gap Documented:** GAP-011 (Lack of enforced MFA across all standard user mailboxes, enabling easy credential stuffing and hijacking).

*   **Entry Point:** Public Website / Billing Interface (`billing-srv-01`)
    *   **What it is:** Public-facing web interface handling payment routing and hospital marketing.
    *   **Asset Behind It:** Linux-based application server.
    *   **Protection Exists:** Static network perimeter packet filtering.
    *   **Gap Documented:** GAP-001 (Unpatched public vulnerabilities; recently exploited via automated scripts to drop an unauthorized cryptocurrency miner).

*   **Entry Point:** Authoritative DNS Infrastructure
    *   **What it is:** Name resolution records directing traffic to MedDefense public assets.
    *   **Asset Behind It:** External DNS registration and local zone files.
    *   **Protection Exists:** Domain registrar lock.
    *   **Gap Documented:** GAP-007 (Lack of continuous external monitoring, leaving the domain vulnerable to brand impersonation and undetected typosquatting setup).

---

## Section 2: Internal Surface

*   **Exposed Databases (MySQL on `billing-srv-01` / PostgreSQL on `ehr-db-01`)**
    *   **Asset:** Core Billing Server and the Electronic Health Record (EHR) Database Engine.
    *   **Exposure:** Port 3306 (MySQL) and Port 5432 (PostgreSQL) accepting connections network-wide.
    *   **Why it matters in a flat network:** Because MedDefense lacks any internal network segmentation (GAP-005), these critical databases are completely exposed to every single endpoint on the network. A compromise of a front-desk reception PC or a public-facing web shell allows an attacker to immediately query, dump, or encrypt our core PHI data directly without needing to bypass an internal firewall.

*   **Management Interfaces (NAS, FortiGate Admin, IoT Web Interfaces)**
    *   **Asset:** Local Backup NAS Rack, Core Firewall management portal, and medical device consoles.
    *   **Exposure:** Port 80/443 (HTTP/HTTPS) and Port 22 (SSH) open internally.
    *   **Why it matters in a flat network:** Administrative access is not restricted to dedicated IT management subnets. An attacker or Ransomware affiliate can interact with the authentication pages of the backup NAS or firewall from any standard clinical terminal, enabling brute-force attempts and credential dumping.

*   **Legacy Systems (Windows XP Workstations, Windows Server 2012 R2)**
    *   **Asset:** Siemens MRI Controller workstation and legacy internal application servers.
    *   **Exposure:** Port 445 (SMB) running obsolete, unpatched network protocols.
    *   **Why it matters in a flat network:** These systems cannot run modern Endpoint Detection and Response (EDR) agents and remain completely unpatchable. In a flat network environment, they act as ideal lateral movement springboards; an attacker inside the network can exploit vulnerabilities like EternalBlue to compromise these legacy hosts instantly and pivot across the entire infrastructure.

*   **Default Credentials (PACS Workstations, Medical IoT Devices)**
    *   **Asset:** Radiology PACS imaging server and connected patient monitoring devices.
    *   **Exposure:** Shared administrative account (`raduser/radiology1`) and default vendor settings.
    *   **Why it matters in a flat network:** These profiles are not gated by individual identity validation or MFA (GAP-011). Because the flat network allows anyone to reach these login endpoints, an attacker can use publicly documented default manufacturer credentials to gain administrative control over live medical hardware.

---

## Section 3: Human Surface

*   **Role:** Clinical Staff (Physicians and Nurses)
    *   **Access Level:** High read/write access to the EHR system and patient medical histories.
    *   **Social Engineering Vulnerability:** High susceptibility to Vishing and Pretexting due to an intense, fast-paced clinical workflow and an inherent professional focus on being helpful during emergencies.
    *   **Gap Increased Risk:** GAP-011 (Widespread use of shared clinical credentials) and a historical lack of phishing/social engineering security training completion.

*   **Role:** Reception / Front-Desk Clerks
    *   **Access Level:** Front-end registration applications, basic patient scheduling lookups, and direct physical network access points.
    *   **Social Engineering Vulnerability:** High exposure to physical tailgating, impersonation props, and curious employee browsing temptations.
    *   **Gap Increased Risk:** GAP-007 (Lack of User Behavior Analytics / EHR lookup logging, allowing unauthorized patient lookups to go undetected until leaked).

*   **Role:** IT Department Staff
    *   **Access Level:** Full domain admin, network infrastructure, and root cloud application privileges.
    *   **Social Engineering Vulnerability:** High susceptibility to targeted spear-phishing (brand impersonation) and severe operational fatigue due to a small, overworked team.
    *   **Gap Increased Risk:** GAP-012 (Lack of privileged access management, resulting in poor habits like writing automated credential-clearing scripts in plaintext on local desktops).

*   **Role:** Executive Leadership (CEO, CFO)
    *   **Access Level:** Strategic financial control, wire transfer authorization, and internal governance files.
    *   **Social Engineering Vulnerability:** High-value target for Business Email Compromise (BEC) and phishing leveraging authority and artificial operational urgency.
    *   **Gap Increased Risk:** GAP-011 (Missing MFA on executive communications and lack of enforced out-of-band multi-person sign-off policies for high-value financial actions).

*   **Role:** External Contractors (MedTech Solutions, Siemens Technicians)
    *   **Access Level:** Remote administrative database maintenance VPN sessions and unmonitored local physical device configurations.
    *   **Social Engineering Vulnerability:** Operational workflows that operate entirely outside of MedDefense's direct security logging controls.
    *   **Gap Increased Risk:** GAP-003 (Lack of automated identity lifecycle management, allowing ghost access credentials to remain active for 47 days after contract termination).

---

## Surface Assessment Summary

The **Internal Surface** represents the greatest risk for MedDefense today. While our external perimeter is heavily exposed due to unpatched public applications, the complete absence of internal network segmentation (GAP-005) converts any singular external perimeter breach or minor social engineering compromise into an instant, company-wide catastrophe. Because our core production databases (MySQL/PostgreSQL), unencrypted local backup NAS arrays, legacy Windows XP medical systems, and administrative interfaces sit on a completely flat architecture with widespread shared credentials, an attacker who gains a foothold does not face a single secondary internal barrier. They can freely map, exploit, and encrypt our entire infrastructure within hours, bypassing standard perimeter controls and rendering MedDefense completely defenseless against modern ransomware operations.
