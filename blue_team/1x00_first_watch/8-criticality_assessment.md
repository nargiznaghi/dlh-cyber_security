# Asset Criticality Assessment: MedDefense Health Systems

This assessment evaluates and ranks the logical asset categories of MedDefense Health Systems based on the CIA Triad framework, calibrated specifically to healthcare operational continuity, patient safety, and regulatory compliance.

---

## 1. Asset Criticality Matrix

| Asset Category | Confidentiality | Integrity | Availability | Overall Criticality | Operational & Business Justification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Electronic Health Records (EHR) System** | Critical | Critical | Critical | **Critical** | Houses live Protected Health Information (PHI) for all active patients. Compromise of Confidentiality triggers HIPAA breach notifications and catastrophic legal fines. Integrity loss (altered records/dosages) directly threatens patient lives. Availability loss halts clinical operations across all sites, forcing blind medical treatment or diversion of critical care. |
| **PACS / Imaging Infrastructure** | High | Critical | High | **Critical** | Contains life-critical medical imaging data (MRIs, X-rays). If Integrity is compromised, altered imaging or corrupted diagnostics lead to fatal misdiagnoses. Availability degradation stalls surgeries and specialized diagnostics for approximately 45 patients per day, resulting in severe patient care delays and financial loss. |
| **Network Core Infrastructure** | High | High | Critical | **Critical** | Comprises routers, switches, and the central firewall (`FW-CENTRAL`). If Availability is compromised, all communication lines between Central Hospital, Westside Clinic, and Corporate HQ instantly drop. This effectively disconnects the EHR clients from database storage, rendering the entire digital enterprise blind. |
| **Billing & Financial Infrastructure** | High | High | High | **High** | Manages insurance claims and patient billing logs. Loss of Availability (as seen in the ransomware attack) freezes corporate cash flow by preventing claim processing, while Integrity compromise leads to fraudulent invoices or unrecoverable financial discrepancies. |
| **Medical IoT Devices** | Medium | Critical | Critical | **Critical** | Includes connected vital sign monitors and infusion pumps. While they hold limited chronic history (Medium Confidentiality), a compromise of Integrity or Availability directly impacts patient safety. Hacked infusion pumps can deliver lethal dosages, and corrupted vital monitors lead to un-triggered codes in intensive care. |
| **Endpoints (Clinical)** | High | High | High | **High** | Includes workstations at nurse stations and active treatment floors. They serve as the primary gateway to the EHR application. While local compromise is recoverable, these endpoints handle immediate PHI exposure and serve as prime vectors for lateral malware movement. |
| **Endpoints (Administrative)** | High | Medium | Medium | **High** | Comprises front desk and corporate laptops. Administrative endpoints contain sensitive corporate contracts, financial planning documents, and HR records, presenting high exposure risks under HIPAA compliance but low risk to immediate clinical operations. |
| **Physical Security Systems** | Medium | Medium | Medium | **Medium** | Covers security guard access logs and entrance DVR camera feeds. While important for facility perimeter accountability and local access auditing, a temporary failure does not immediately degrade medical delivery networks or expose core databases. |

---

## 2. Top 5 Most Critical Strategic Assets

The following assets represent the single points of catastrophic failure within the MedDefense ecosystem, ranked by their combined risk to patient safety, financial survival, and legal liability.

### 1. `ehr-db-01` (Core PostgreSQL Database Server)
* **Rank:** 1
* **Why it holds this position:** This asset is the primary repository for all active Protected Health Information (PHI) and clinical records across the entire enterprise. A breach of confidentiality here impacts every patient in the MedDefense ecosystem, driving mandatory federal regulatory intervention and devastating class-action litigation. Furthermore, because it is open to the entire flat internal network (`10.10.0.0/16`), any unmitigated integrity compromise on this server allows for systemic medication database corruption, placing thousands of active lives at immediate risk.

### 2. `ehr-srv-01` (EHR Clinical Application Server)
* **Rank:** 2
* **Why it holds this position:** This host acts as the functional layer required by clinical staff to query, update, and read patient history data. If this application server experience downtime, physicians lose all electronic access to patient data, triggering immediate clinical regression to slow, error-prone paper records. It sits immediately below the database in criticality, because a failure here completely isolates medical teams from executing informed treatment protocols.

### 3. `FW-CENTRAL` (FortiGate 100F Perimeter Firewall)
* **Rank:** 3
* **Why it holds this position:** This security appliance acts as the structural gateway for all internet traffic, site-to-site VPN connectivity, and internal network separation boundaries. If this device experiences a catastrophic failure or denial-of-service attack, remote operations at the Westside Clinic and Corporate HQ are completely severed from the main server room infrastructure, freezing cross-site clinical operations and exposing internal network interfaces to lateral perimeter failure.

### 4. `pacs-srv-01` (Picture Archiving and Communication System Server)
* **Rank:** 4
* **Why it holds this position:** This system handles the storage and translation of critical radiology files, directly serving the daily operational workflow of the Radiology department. Because this asset is explicitly excluded from automated nightly backup runs, an integrity failure (such as data corruption) or a targeted ransomware attack results in the permanent, unrecoverable destruction of vital historical patient diagnostic files and immediate clinical paralysis.

### 5. `ad-dc-01` (Primary Windows Active Directory Domain Controller)
* **Rank:** 5
* **Why it holds this position:** This asset provides centralized identity and access management for every domain-joined workstation, server, and administrative user account in the hospital. If an attacker seizes control of the primary domain controller, they gain total administrative dominance over the network layer. This allows for the instant distribution of automated malicious payloads, global account lockouts, or widespread privilege abuse across all connected endpoints.
