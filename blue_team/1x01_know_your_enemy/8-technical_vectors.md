# Technical Vector Assessment for MedDefense

## Vector 1: Vulnerable Software
* **Vector Category:** Vulnerable Software
* **MedDefense Evidence:** Web server running an outdated version of Apache 2.4.29 on `billing-srv-01`, hosted on an unpatched Ubuntu 18.04 LTS (End-of-Life) platform.
* **Affected Asset(s):** `billing-srv-01` (Billing Application Server) and associated web services.
* **Actor Most Likely to Exploit:** Unskilled / Opportunistic Attacker or Ransomware Groups (Organized Crime).
* **Exploitation Scenario:** An attacker scans the internet for known public exploits targeting Apache 2.4.29 to execute remote code on the server. They drop a web shell onto `billing-srv-01` to gain initial persistence, which explains how an automated script was previously able to install an unauthorized cryptocurrency miner. Once inside, they can use this host as a staging ground to scan the internal corporate network.
* **Current Protection:** Basic perimeter firewall packet filtering.
* **Gap Reference:** GAP-001 (Unpatched public-facing vulnerabilities and outdated software stacks).

---

## Vector 2: Unsupported Systems
* **Vector Category:** Unsupported Systems
* **MedDefense Evidence:** Siemens MRI workstation running legacy Windows XP, alongside `print-srv-01` running Windows Server 2012 R2.
* **Affected Asset(s):** Clinical Siemens MRI Controller workstation and the core network print server (`print-srv-01`).
* **Actor Most Likely to Exploit:** Ransomware Groups (Organized Crime).
* **Exploitation Scenario:** An affiliate who has gained access to the internal network searches for systems vulnerable to unpatched, legacy operating system bugs. They execute public exploit scripts (such as EternalBlue or BlueKeep) against the Windows XP machine over unsegmented file-sharing protocols. Because the machine cannot run modern endpoint security software, the attacker easily gains local SYSTEM execution and establishes a permanent backdoor.
* **Current Protection:** Physical access restrictions to the specialized radiology rooms housing the MRI hardware.
* **Gap Reference:** GAP-001 (Use of legacy, unpatched, and end-of-life operating systems).

---

## Vector 3: Open Service Ports
* **Vector Category:** Open Service Ports
* **MedDefense Evidence:** MySQL (Port 3306) on `billing-srv-01` and PostgreSQL (Port 5432) on `ehr-db-01` actively listening for connections across all subnets, combined with unauthenticated Remote Desktop Protocol (RDP) on specific endpoints.
* **Affected Asset(s):** `ehr-db-01` (Core Electronic Health Record Database), `billing-srv-01`, and exposed local workstations.
* **Actor Most Likely to Exploit:** Ransomware Groups (Organized Crime) or Insider (Malicious).
* **Exploitation Scenario:** An attacker inside the network connects directly to the PostgreSQL instance on Port 5432 from a compromised reception or clinical workstation. Since the port is open to all internal IP addresses, they run automated database password-cracking tools without restriction. Once they gain access, they can exfiltrate protected health records and delete the database files.
* **Current Protection:** Standard endpoint local firewall profiles (though broad internal service communication is permitted).
* **Gap Reference:** GAP-005 (Flat internal network topology and lack of host/service isolation barriers).

---

## Vector 4: Default Credentials
* **Vector Category:** Default Credentials
* **MedDefense Evidence:** Radiology department utilization of the hardcoded shared profile `raduser/radiology1` on PACS systems, and default vendor administrative setups left unchanged on BD Alaris infusion pumps.
* **Affected Asset(s):** Picture Archiving and Communication System (PACS) workstations and network-connected medical IoT infusion pumps.
* **Actor Most Likely to Exploit:** Insider (Malicious) or Insider (Negligent).
* **Exploitation Scenario:** A disgruntled employee or external threat actor looks up the public manufacturer documentation for a BD Alaris infusion pump to find its factory-default administrative login credentials. They log into the pump's web interface over the local network and modify its configuration or dose limits. This allows them to disrupt clinical workflows without needing to crack a password or bypass multi-factor authentication.
* **Current Protection:** Basic user access policies requiring password modifications for standard corporate network accounts.
* **Gap Reference:** GAP-011 (Missing Multi-Factor Authentication and reliance on shared, unmanaged privileged profiles).

---

## Vector 5: Unsecure Networks
* **Vector Category:** Unsecure Networks
* **MedDefense Evidence:** A completely flat internal network design lacking logical or physical subnets, alongside an unmanaged consumer-grade Westside router providing wireless access with unverified isolation policies.
* **Affected Asset(s):** Entire local network infrastructure, including clinical, administrative, and medical IoT devices.
* **Actor Most Likely to Exploit:** Ransomware Groups (Organized Crime) or Insider (Negligent).
* **Exploitation Scenario:** An attacker gains an initial foothold on a single low-security endpoint, such as a front-desk terminal. Because the network architecture is entirely flat, they can sniff local network traffic and move laterally to sensitive servers without encountering an internal firewall or segmentation rule. This allows them to map the entire corporate network within a few hours.
* **Current Protection:** Boundary perimeter separation between the global internet and the internal local network via a central firewall.
* **Gap Reference:** GAP-005 (Lack of internal logical network segmentation and subnets).

---

## Vector 6: Removable Devices / Unmanaged Endpoints
* **Vector Category:** Removable Devices / Unmanaged Endpoints
* **MedDefense Evidence:** Absence of a Group Policy Object (GPO) enforcing USB storage blocks, unmanaged clinical iPads, and shadow IT devices connected to network ports (such as Dr. Patel's personal NAS).
* **Affected Asset(s):** Corporate workstations, clinical data ports, and unsanctioned local network storage targets.
* **Actor Most Likely to Exploit:** Insider (Negligent) or Insider (Malicious).
* **Exploitation Scenario:** An employee plugs an unencrypted personal USB thumb drive into a clinical computer to save copies of patient files for work convenience. Unbeknownst to the employee, the drive contains data-stealing malware picked up from a personal computer at home. The malware executes automatically on the unblocked corporate endpoint and uses its network connection to exfiltrate patient data to an external command-and-control server.
* **Current Protection:** Antivirus signature scanning running on standard corporate Windows endpoints.
* **Gap Reference:** GAP-014 (Lack of Network Access Control and missing endpoint peripheral block enforcement).
