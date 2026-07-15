# STRIDE Threat Model Across the MedDefense Architecture

## 1. PACS / Medical Imaging System
* **Architecture Notes:** Comprises `pacs-srv-01` (primary image repository server), a Siemens MRI workstation controller running legacy Windows XP, connected radiology viewing terminals, and unsegmented local network communication paths.

| STRIDE | Threat | Impact | Severity |
| :--- | :--- | :--- | :--- |
| **S** | Attacker spoofing trusted radiology workstations or reusing the shared `raduser` credentials to access PACS storage interfaces. | Unauthorized access to the radiology database and ability to view/edit diagnostic databases. | **High** |
| **T** | Attackers exploiting legacy Windows XP OS vulnerabilities to modify medical diagnostic images or DICOM header details. | Misdiagnoses, incorrect surgical pathways, or delayed treatments due to altered clinical imaging charts. | **Critical** |
| **R** | Attacker deletes historical patient imaging archives, claiming the action was performed by someone else using the shared `raduser` login. | Complete lack of clinical or legal accountability with zero ability to prove who deleted critical diagnostic records. | **High** |
| **I** | Attacker sniffs unencrypted DICOM/PACS traffic traversing the unsegmented flat local network from an unmanaged switchport. | Massive unauthorized disclosure of sensitive patient anatomical records and HIPAA violations. | **High** |
| **D** | Attackers execute legacy SMBv1 exploits (e.g., EternalBlue) against the unsupported Windows XP MRI controller. | Complete diagnostic system lockup and clinical imaging service outage, halting surgical preparation. | **High** |
| **E** | Attacker uses public privilege escalation exploits on the unpatched, legacy Windows XP workstation to gain local SYSTEM privileges. | Full control over the physical imaging machine host, enabling backdoors and lateral network pivoting. | **High** |

* **Top Threat:** **Tampering (T)** is the most dangerous threat for the PACS/Medical Imaging system. Altering image files or medical metadata directly leads to clinical misdiagnoses or incorrect patient treatment paths (e.g., operating on the wrong area of a patient's body), posing a direct threat to human life that far exceeds the immediate impact of data confidentiality loss.

---

## 2. Active Directory
* **Architecture Notes:** Comprises redundant domain controllers (`ad-dc-01` and `ad-dc-02`) managing identity, authentication, GPO policies, and access control lists across all domain-joined enterprise endpoints.

| STRIDE | Threat | Impact | Severity |
| :--- | :--- | :--- | :--- |
| **S** | Attacker performs Kerberoasting to harvest Active Directory authentication hashes and impersonates a domain administrator. | Immediate, unauthorized administrative command execution across the entire corporate network. | **Critical** |
| **T** | Attacker alters Active Directory Group Policy Objects (GPOs) to push malicious payloads and disable host firewall rules globally. | Automated malware and ransomware are distributed network-wide to all endpoints within minutes. | **Critical** |
| **R** | Attacker clears security logs on domain controllers after carrying out attacks to conceal lateral movement and malware execution. | Forensic teams cannot trace the entry point, path, or compromised administrative credentials during incident response. | **High** |
| **I** | Attacker dumps the Active Directory database file (`ntds.dit`) containing password hashes for all domain users. | Total compromise of all corporate credentials, enabling persistence and subsequent unauthorized logins. | **Critical** |
| **D** | Attacker floods domain controllers with LDAP requests or executes system shutdown commands using stolen admin keys. | Instantly halts all user and system authentication domain-wide, freezing clinical and administrative workflows. | **Critical** |
| **E** | Attacker exploits missing administrative MFA (GAP-011) to elevate standard network credentials to full Domain Admin privileges. | Complete takeover of the entire enterprise infrastructure, granting absolute administrative control. | **Critical** |

* **Top Threat:** **Tampering (T - GPO Modification)** is the most dangerous threat for Active Directory. Because AD is the centralized control point, the ability to modify and push hostile Group Policies acts as a direct, unblockable force multiplier. It allows an attacker to simultaneously disable endpoint defenses and deploy ransomware to 100% of domain-joined servers and workstations.

---

## 3. Network Infrastructure
* **Architecture Notes:** Comprises a perimeter FortiGate 100F firewall, internal core switches, an unmanaged Westside consumer-grade router providing wireless access, and active VPN tunnels.

| STRIDE | Threat | Impact | Severity |
| :--- | :--- | :--- | :--- |
| **S** | Rogue access point deployment or ARP poisoning on the unsecure Westside consumer-grade wireless router. | Interception of administrative or clinical credentials transmitted over local wireless connections. | **High** |
| **T** | Attackers exploit the lack of MFA to log into the FortiGate firewall management console and modify access control lists. | Internal clinical and database servers are exposed directly to the public internet, bypassing boundary rules. | **Critical** |
| **R** | Attacker wipes system event logs and administrative session histories from core switch and firewall memory. | Security teams cannot reconstruct the attacker's network entry vectors or find the source IP of remote VPN connections. | **High** |
| **I** | Attacker accesses an open network jack and sniffs unencrypted local traffic traversing the unsegmented flat network. | Interception of sensitive passwords, administrative commands, and plain-text medical records. | **High** |
| **D** | Attacker exploits unpatched firmware CVEs on the external FortiGate 100F firewall to trigger system crashes. | Total internet and network blackout, blocking cloud EHR synchronization, telemedicine, and internal communications. | **Critical** |
| **E** | Attacker exploits unauthenticated VPN profiles to move from the public internet directly into internal network segments. | Complete bypass of perimeter defenses, dropping the attacker into the soft, unsegmented internal flat network. | **Critical** |

* **Top Threat:** **Denial of Service (D)** represents the greatest threat to Network Infrastructure. If the perimeter firewall or core switches are disabled or crashed, all internal and external communication links fail instantly. This disconnects clinicians from cloud services, halts internal patient coordination, and forces emergency status (diversion of incoming ambulances to other hospitals) due to total loss of technical operation.
