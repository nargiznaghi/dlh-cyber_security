# 14. The Segmentation Architecture

## Part 1 - Zone Definition

### Zone 1: Core Server Zone (VLAN 10)
* **IP Range:** `10.10.10.0/24`
* **Systems Included:** `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `dc-01` (Active Directory), central file servers[cite: 3, 4].
* **Allowed Outbound Connections:** `10.10.40.0/24` (Management Zone for centralized monitoring/logging via Syslog/Wazuh); restricted outbound internet via WAN over TLS (443) strictly for licensing/patch management[cite: 3, 4].
* **Allowed Inbound Connections:** Clinical Workstation Zone (`10.10.20.0/24`) on specific EHR application ports (HTTPS 443, PostgreSQL 5432) with ACL rate-limiting; Management Zone (`10.10.40.0/24`) on SSH (22), RDP (3389), and WinRM (5985/5986)[cite: 3, 4].

### Zone 2: Clinical Workstation Zone (VLAN 20)
* **IP Range:** `10.10.20.0/24`
* **Systems Included:** Nurse station PCs, physician desktop workstations, clinical mobile carts, triage terminals[cite: 3, 4].
* **Allowed Outbound Connections:** Server Zone (`10.10.10.0/24`) on ports 443 (EHR web) and 5432 (PostgreSQL) only; Internet via secure web proxy on ports 80/443[cite: 3, 4].
* **Allowed Inbound Connections:** Management Zone (`10.10.40.0/24`) for IT support (RDP 3389, EDR/SIEM agent management)[cite: 3, 4]. Inter-workstation communication within VLAN 20 is strictly blocked[cite: 3, 4].

### Zone 3: Medical Device Zone (VLAN 30)
* **IP Range:** `10.10.30.0/24`
* **Systems Included:** BD Alaris infusion pumps, patient cardiac monitors, PACS imaging systems, MRI/CT scanners[cite: 3, 4].
* **Allowed Outbound Connections:** Server Zone (`10.10.10.0/24`) on PACS DICOM port (104) and dedicated vendor update gateways[cite: 3, 4]. Internet access is completely blocked[cite: 3, 4].
* **Allowed Inbound Connections:** Dedicated VLAN 40 administrative jump boxes for maintenance[cite: 3, 4]. Direct access from general workstations or public networks is denied[cite: 3, 4].

### Zone 4: IT Management & Security Zone (VLAN 40)
* **IP Range:** `10.10.40.0/24`
* **Systems Included:** IT admin workstations, Wazuh SIEM server, backup management console, administrative jump servers[cite: 3, 4].
* **Allowed Outbound Connections:** All internal zones (VLAN 10, 20, 30, 50) on management ports (SSH 22, RDP 3389, WinRM, Syslog 514, Wazuh Agent 1514/1515); restricted HTTPS outbound to AWS Cloud Backup endpoint (`s3.amazonaws.com`)[cite: 3, 4].
* **Allowed Inbound Connections:** FortiGate Remote VPN Gateway with mandatory MFA authentication[cite: 3, 4].

### Zone 5: Guest & IoT Zone (VLAN 50)
* **IP Range:** `10.10.50.0/24`
* **Systems Included:** Patient/visitor Wi-Fi, personal BYOD mobile devices, smart facility TVs, cafeteria POS terminals[cite: 3, 4].
* **Allowed Outbound Connections:** Direct Internet access only (Ports 80, 443, 53 UDP/TCP via external DNS)[cite: 3, 4].
* **Allowed Inbound Connections:** None[cite: 3, 4]. Inter-client device communication is isolated[cite: 3, 4].

---

## Part 2 - Firewall Rules

| Rule ID | Source Zone | Destination Zone | Port / Protocol | Action | Rule Description & Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FW-001** | VLAN 20 (Clinical WS) | VLAN 10 (Servers) | TCP/443 (HTTPS), TCP/5432 (PostgreSQL) | **ALLOW** | Permits authorized clinical workstations to communicate with the EHR web interface and database[cite: 3, 4]. |
| **FW-002** | VLAN 40 (Management) | ANY Internal Zone | TCP/22 (SSH), TCP/3389 (RDP), TCP/5985-5986 (WinRM) | **ALLOW** | Enables secure administrative management from IT jump hosts[cite: 3, 4]. |
| **FW-003** | VLAN 30 (Med Devices) | VLAN 10 (Servers) | TCP/104 (DICOM) | **ALLOW** | Allows imaging systems and medical equipment to store PACS records on core database servers[cite: 3, 4]. |
| **FW-004** | Remote VPN Users | VLAN 40 (Management) | TCP/443 (HTTPS / Azure MFA), UDP/500,4500 (IPsec) | **ALLOW** | Enforces authenticated, multi-factor remote access into the IT management subnet[cite: 3, 4]. |
| **FW-005** | ALL Internal Zones | VLAN 40 (Management) | UDP/514 (Syslog), TCP/1514-1515 (Wazuh) | **ALLOW** | Allows all internal hosts to send security log telemetry to the SIEM[cite: 3, 4]. |
| **FW-006** | VLAN 50 (Guest/IoT) | WAN (Internet) | TCP/80,443, UDP/53 | **ALLOW** | Provides public internet access for visitors and non-clinical IoT endpoints[cite: 3, 4]. |
| **FW-007** | VLAN 40 (Management) | AWS S3 Cloud | TCP/443 (HTTPS) | **ALLOW** | Enables secure transmission of system backups to AWS S3 Glacier[cite: 3, 4]. |
| **FW-008** | VLAN 20 (Clinical WS) | VLAN 20 (Clinical WS) | ANY | **DENY** | **Explicit Deny:** Blocks peer-to-peer lateral movement between workstations, preventing workstation-to-workstation worm propagation[cite: 3, 4]. |
| **FW-009** | VLAN 50 (Guest/IoT) | ANY Internal Zone (VLAN 10,20,30,40) | ANY | **DENY** | **Explicit Deny:** Completely isolates guest traffic and untrusted BYOD devices from accessing corporate or clinical data networks[cite: 3, 4]. |
| **FW-001**0 | ANY Zone | ANY Zone | ANY | **DENY** | **Default Implicit Deny:** Drops all traffic not explicitly permitted by preceding rules[cite: 3, 4]. |

---

## Part 3 - Kill Chain Impact

### Ransomware Kill Chain Disruption Analysis (#1 Kill Chain)
1. **Initial Access:** Attacker compromises single-factor VPN credentials or a phishing endpoint in VLAN 20[cite: 3, 4].
2. **Execution & Reconnaissance:** Attacker attempts network scanning (`nmap`) to discover internal database servers and medical equipment[cite: 3, 4].
3. **Segmentation Disruption (Step 3 - Lateral Movement):**
   * Under the legacy flat network, an attacker on a workstation or VPN could directly query `ehr-db-01` (`10.10.10.15`), `billing-srv-01`, and medical devices across all ports[cite: 3, 4].
   * With VLAN Segmentation and Firewall Rules **FW-008**, **FW-009**, and **FW-010** enforced, lateral movement is completely blocked[cite: 3, 4]. The workstation in VLAN 20 cannot reach SMB/RDP on other workstations or administrative ports on database servers[cite: 3, 4].
4. **Impact Breakdown:** The ransomware payload remains isolated to the single compromised endpoint, preventing mass database encryption, domain controller takeover, and network-wide ransom deployment[cite: 3, 4].

### Aggregate Kill Chain Disruption Estimate
* **Disruption Rate:** **80% (4 out of Top 5 Kill Chains Disrupted)**[cite: 3, 4].
* **Explanation:** Network segmentation directly disrupts the lateral movement, remote service discovery, and privilege escalation phases of ransomware, insider data exfiltration, legacy server pivot, and medical device tampering scenarios[cite: 3, 4].
