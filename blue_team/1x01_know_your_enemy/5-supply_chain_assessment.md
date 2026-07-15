# Third-Party Supply Chain Risk Assessment

## 1. Vendor Risk Profiles

### Vendor: MedTech Solutions
* **Service:** Electronic Health Record (EHR) platform maintenance provider.
* **Access Type:** Network and Application Access.
* **Access Scope:** Direct administrative access to the EHR database server (`ehr-db-01`) and associated application layers via persistent remote maintenance VPN sessions.
* **Compromise Scenario:** If MedTech Solutions is breached, an attacker steals their hardcoded VPN service credentials or hijacks their remote access tunnel. The attacker leverages this legitimate administrative session to log directly into `ehr-db-01`, bypassing perimeter defenses. Once inside, they dump the entire database of Protected Health Information (PHI) and execute ransomware domain-wide.
* **Existing Controls:** AC-02 (Account Management - vendor account is defined) / AC-17 (Remote Access policies).
* **Risk Assessment:** **Critical**. MedTech possesses direct, high-privilege access to the organization's single most critical asset (the EHR system) with very little real-time session monitoring.

---

### Vendor: Microsoft
* **Service:** Office 365 E3 (Email, SharePoint, OneDrive, and Identity management).
* **Access Type:** Application, Identity, and Cloud Data Access.
* **Access Scope:** All corporate email communications, clinical and administrative files stored in SharePoint/OneDrive, and user identity directory metadata.
* **Compromise Scenario:** A tenant-level breach or a successful global admin compromise at Microsoft (or via a misconfigured MedDefense O365 tenant) allows attackers to read all executive emails, locate stored credential sheets in SharePoint, and run Business Email Compromise (BEC) wire-transfer scams. They can also lock out all users from their accounts.
* **Existing Controls:** IA-01 (Identification and Authentication) / AC-03 (Access Enforcement).
* **Risk Assessment:** **High**. While Microsoft's physical and native cloud infrastructure security is extremely high, a compromise of their administrative access or tenant configurations would instantly paralyze MedDefense's business operations and leak sensitive administrative data.

---

### Vendor: Sophos
* **Service:** Endpoint Protection (Antivirus / EDR agent platform).
* **Access Type:** Host-Level / Application Access.
* **Access Scope:** System-level (SYSTEM/root privileges) agents installed on 100% of managed Windows and macOS endpoints, including administrative laptops and billing workstations, with the capability to push remote commands and system updates.
* **Compromise Scenario:** Attackers compromise Sophos's software distribution pipeline or cloud management console. They push a malicious agent update (similar to the SolarWinds or CrowdStrike scenarios) to all MedDefense endpoints. This update silently executes malware at the kernel/SYSTEM level on every computer simultaneously, instantly disabling defenses and encrypting all drives.
* **Existing Controls:** CM-03 (Configuration Change Processes) / SI-03 (Malicious Code Protection).
* **Risk Assessment:** **Critical**. Endpoint protection agents run with the highest possible operating system privileges. A compromised software pipeline represents an unblockable, network-wide "kill switch."

---

### Vendor: Siemens
* **Service:** MRI scanner manufacturer.
* **Access Type:** Physical, Network, and Device-Level Access.
* **Access Scope:** Windows XP controller workstation physically attached to the MRI scanner, connected to the local clinical network subnet for imaging transfers.
* **Compromise Scenario:** A technician plugs a compromised, malware-infected USB drive directly into the legacy Windows XP workstation during a routine maintenance visit, or attackers compromise the remote link Siemens uses to push firmware. Because the device runs on an end-of-life operating system (Windows XP) and sits on a flat network, the malware uses known SMB exploits (like EternalBlue) to spread laterally to the rest of the clinical network.
* **Existing Controls:** MP-07 (Media Use and Sanitization - though physical USB enforcement is weak) / PE-03 (Physical Access Control).
* **Risk Assessment:** **High**. The combination of legacy, unpatchable operating systems (Windows XP) and a lack of network segmentation makes this device a prime springboard for lateral movement across the entire network.

---

### Vendor: Greenfield Building Management
* **Service:** Headquarters facility management and physical infrastructure.
* **Access Type:** Physical and Network-level Transport Access.
* **Access Scope:** Physical access to MedDefense's networking racks, shared communication closets, and logical transport layer (since MedDefense's traffic runs over a VLAN hosted on the building's managed switch infrastructure).
* **Compromise Scenario:** An attacker exploits weak physical security in the building's basement utility room to access the shared patch panels. They plug in a rogue physical device to sniff network traffic running across the unencrypted VLAN, or they compromise the building management network to access and alter switches, cutting off the hospital's internet connection.
* **Existing Controls:** PE-03 (Physical Access Control - restricted to office doors) / PE-18 (Physical Access for Transmission Medium).
* **Risk Assessment:** **Medium**. While physical tapping is rarer, the logical dependency on a landlord-managed network switch without end-to-end encryption or control over physical closets presents a significant risk to data privacy and network availability.

---

## 2. Supply Chain Risk Summary

The single vendor compromise that would cause the most catastrophic damage to MedDefense is **Sophos**. Because their endpoint protection agent is deployed with administrative kernel-level privileges across 100% of our servers and staff workstations, a compromise of their update supply chain would grant attackers complete, immediate control over every endpoint. This bypasses firewalls and network rules entirely, allowing simultaneous, un-segmentable execution of ransomware. 

To mitigate third-party supply chain risk across all vendors, the single control MedDefense must implement first is **Zero Trust Network Access (ZTNA) combined with strict Remote Access Multi-Factor Authentication and Session Monitoring (implementing Jump Servers)**. By isolating third-party connections inside a restricted, monitored jump box environment (where vendors can only interact with their designated systems via audited, MFA-gated RDP/SSH sessions), we can eliminate persistent VPN connections, block lateral movement, and ensure that vendor credentials cannot be abused to access other parts of our flat network.
