# STRIDE Threat Model for the MedDefense EHR System

## 1. STRIDE Threat Inventory

### Spoofing (S)

#### Threat ID: EHR-S1 (Workstation Session Hijacking)
* **Description:** An unauthorized user or malicious actor sits down at an unattended clinical workstation in an open ward and acts under the identity of a logged-in nurse or doctor.
* **Attack Vector:** Default / Shared Credentials & Unsecure Physical Environments.
* **Impact:** Unauthorized entry of false patient diagnostic data or prescription orders under a legitimate clinician's name, compromising clinical chart integrity.
* **Existing Control:** AC-01 (Access Control Policy).
* **Gap:** GAP-011 (Lack of enforced individual accounts, single sign-on, and lack of automatic idle session timeout GPOs).

#### Threat ID: EHR-S2 (IP Address Spoofing via Flat Network)
* **Description:** An attacker spoofing a trusted workstation's IP address to bypass native host-based access controls on `ehr-db-01`.
* **Attack Vector:** Unsecure Networks.
* **Impact:** The attacker gains unauthenticated database connection access to PostgreSQL (Port 5432) from a low-privilege network jack.
* **Existing Control:** None.
* **Gap:** GAP-005 (Lack of logical network segmentation and subnets to isolate the database server).

---

### Tampering (T)

#### Threat ID: EHR-T1 (Direct Database Modification)
* **Description:** An attacker connects directly to the PostgreSQL instance and alters medication dosage values or drug allergy lists inside the production database tables.
* **Attack Vector:** Open Service Ports.
* **Impact:** Patients receive lethal doses of medication or contraindicated treatments due to altered clinical charts.
* **Existing Control:** SI-03 (Malicious Code Protection running on endpoints, but doesn't prevent direct network query tampering).
* **Gap:** GAP-005 (Database ports exposed network-wide) and GAP-011 (Weak default PostgreSQL system credentials).

#### Threat ID: EHR-T2 (Local Configuration Manipulation)
* **Description:** A negligent or malicious user modifies critical host configuration files on `ehr-srv-01` to bypass security validation checks.
* **Attack Vector:** Insider (Malicious / Negligent).
* **Impact:** EHR application security controls are disabled, allowing unvalidated API requests to execute on backend application servers.
* **Existing Control:** CM-03 (Configuration Change Processes).
* **Gap:** GAP-012 (Lack of file integrity monitoring and secure coding standards).

---

### Repudiation (R)

#### Threat ID: EHR-R1 (Shared Account Actions Deniability)
* **Description:** A technician administers or alters a medical imaging entry on a workstation, but later denies doing so, claiming someone else used the shared "raduser" login credentials.
* **Attack Vector:** Default / Shared Credentials.
* **Impact:** Complete breakdown of medical and legal accountability; unable to forensically prove who modified patient files.
* **Existing Control:** AU-02 (Audit Events Policy).
* **Gap:** GAP-011 (Pervasive use of shared accounts across clinical workstations).

#### Threat ID: EHR-R2 (Audit Log Erasure)
* **Description:** A malicious administrator deletes system log files on `ehr-srv-01` or `ehr-db-01` to cover up unauthorized access patterns.
* **Attack Vector:** Insider (Malicious).
* **Impact:** Forensic investigators cannot trace the source, timeline, or extent of a data breach event.
* **Existing Control:** AU-02 (Audit Events Policy).
* **Gap:** GAP-007 (Lack of log centralization, SIEM, or write-once-read-many log storage).

---

### Information Disclosure (I)

#### Threat ID: EHR-I1 (Network Sniffing of PHI)
* **Description:** An attacker connects a rogue device to an unmanaged network switchport and sniffs unencrypted SQL traffic passing between workstations and `ehr-db-01`.
* **Attack Vector:** Unsecure Networks / Removable Devices.
* **Impact:** Massive leakage of Protected Health Information (PHI) to unauthorized external parties, violating HIPAA.
* **Existing Control:** Standard network perimeter security controls.
* **Gap:** GAP-005 (Lack of network-level encryption, such as IPSec or TLS, for internal database sessions).

#### Threat ID: EHR-I2 (Convenience Copy Exfiltration)
* **Description:** A physician copies unencrypted clinical database files onto a personal NAS device connected to an office port to work on research files at home.
* **Attack Vector:** Removable Devices / Unmanaged Endpoints.
* **Impact:** High-volume patient data exposure if the unmanaged, unencrypted NAS is stolen or compromised via secondary household exploits.
* **Existing Control:** MP-07 (Media Use Policy).
* **Gap:** GAP-014 (Lack of Network Access Control to block rogue physical NAS devices, and lack of USB/peripheral control GPOs).

---

### Denial of Service (D)

#### Threat ID: EHR-D1 (Database Port Resource Exhaustion)
* **Description:** An attacker launches a script that floods the PostgreSQL database port (5432) on `ehr-db-01` with thousands of junk connection requests.
* **Attack Vector:** Open Service Ports.
* **Impact:** Complete EHR application blackout, preventing doctors from looking up critical patient files or checking drug allergy matches in real-time.
* **Existing Control:** Basic network perimeter firewalls.
* **Gap:** GAP-005 (Exposed database ports internally network-wide with zero rate-limiting/firewalling rules between subnets).

#### Threat ID: EHR-D2 (Ransomware Encryption of Backup & Host)
* **Description:** A Ransomware affiliate maps active network files shares, discovers the local backup NAS, deletes recovery folders, and encrypts `ehr-srv-01` system files.
* **Attack Vector:** Vulnerable Software Exploit / VPN Exploit.
* **Impact:** Total, long-term system outage with no immediate restore capability, leading to emergency hospital diversion.
* **Existing Control:** Standard local file system backups.
* **Gap:** GAP-008 (Lack of network-isolated, immutable offline backup infrastructure).

---

### Elevation of Privilege (E)

#### Threat ID: EHR-E1 (Local Credential Harvesting)
* **Description:** An attacker executes local privilege escalation tools against unpatched service engines running on `ehr-srv-01` or a clinical workstation.
* **Attack Vector:** Vulnerable Software Exploit.
* **Impact:** The attacker elevates from standard user status to domain administrator privileges, securing full host system control.
* **Existing Control:** Standard workstation local group policy parameters.
* **Gap:** GAP-001 (Outdated OS environments and missing local host security updates).

#### Threat ID: EHR-E2 (Script-Based Privilege Leakage)
* **Description:** An attacker accesses a system administrator’s local desktop folders and discovers an unencrypted automation script containing plaintext Domain Admin credentials.
* **Attack Vector:** Insider (Negligent).
* **Impact:** The attacker obtains enterprise administrative access keys instantly, enabling them to alter security permissions domain-wide.
* **Existing Control:** IA-05 (Authenticator Management).
* **Gap:** GAP-012 (Absence of secure scripting practices and lack of Privileged Access Management vaults).

---

## 2. STRIDE Summary for EHR

The STRIDE category that represents the absolute greatest risk to the MedDefense EHR system is **Tampering (T)**. In a high-consequence healthcare environment, while Information Disclosure (data leakage) carries catastrophic compliance penalties and financial costs, Tampering directly threatens patient life and physical safety. Because MedDefense suffers from a flat network architecture (GAP-005) and widespread shared credential use (GAP-011), any compromised endpoint allows an attacker to connect directly to PostgreSQL database ports. A malicious actor altering prescription dosages, blood type markers, or life-threatening allergy alerts within patient charts can cause immediate clinical harm or death before staff realize the data has been modified. This makes data integrity the most critical defense bottleneck for our EHR system.
