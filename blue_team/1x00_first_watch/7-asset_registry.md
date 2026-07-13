# Comprehensive Asset Registry: MedDefense Health Systems

This registry consolidates asset data gathered across onboarding documentation, incident logs, physical site audits, control inventories, and the latest Nmap network discovery scans.

---

## 1. Asset Inventory Table

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A-01** | `ehr-srv-01` | Server | Central Basement | IT Operations | Ubuntu 20.04 LTS | EHR Clinical App | Server Subnet (`10.10.2.0/24`) | Active | Accessible via network, handles primary EHR workflow. |
| **A-02** | `ehr-db-01` | Data Store | Central Basement | IT Operations | Ubuntu 20.04 LTS | PostgreSQL Database | Server Subnet (`10.10.2.0/24`) | Active | Open to the entire `10.10.0.0/16` range. Critical PHI repository. |
| **A-03** | `pacs-srv-01` | Server | Central Basement | Radiology | Windows Server 2016 | PACS Imaging Storage | Server Subnet (`10.10.2.0/24`) | Active | Excluded from nightly automated backup processes. |
| **A-04** | `billing-srv-01` | Server | Central Basement | Finance | Ubuntu 18.04 LTS | Apache 2.4.29, MySQL | Server Subnet (`10.10.2.0/24`) | Active | Compromised with crypto-miner payload. OS support ended June 2023. |
| **A-05** | `ad-dc-01` | Server | Central Basement | IT Operations | Windows Server 2019 | Active Directory DC | Server Subnet (`10.10.2.0/24`) | Active | Primary corporate domain controller. |
| **A-06** | `ad-dc-02` | Server | Central Basement | IT Operations | Ubuntu 18.04 LTS | Active Directory DC | Server Subnet (`10.10.2.0/24`) | Active | Secondary domain controller. Excluded from routine automated backups. |
| **A-07** | `file-srv-01` | Server | Central Basement | HR / Admin | Windows Server 2016 | SMB Department Shares | Server Subnet (`10.10.2.0/24`) | Active | Holds corporate file directory; accessible from Intern's network segment. |
| **A-08** | `print-srv-01` | Server | Central Basement | IT Operations | Windows Server 2012 R2 | Local Windows Printing | Server Subnet (`10.10.2.0/24`) | Active | Legacy host, unverified in server logs but confirmed active by scan. EOL 2023. |
| **A-09** | `backup-srv-01` | Server | Central Basement | IT Operations | Ubuntu 22.04 LTS | Veeam Backup Agent | Server Subnet (`10.10.2.0/24`) | Active | Manages local infrastructure snapshots. |
| **A-10** | `web-srv-01` | Server | Central DMZ | IT Operations | Ubuntu 20.04 LTS | Public Website / Portal | DMZ Subnet (`10.10.254.0/24`) | Active | Target of April website defacement incident. Exposed to WAN. |
| **A-11** | `ws-srv-01` | Server | Westside Closet | Outpatient Clinic | Windows Server 2016 | File Storage, Scheduling | Westside Subnet (`10.10.10.0/24`) | Active | Primary local server node for suburban office coordination. |
| **A-12** | `NAS-01` | Data Store | Central Basement | IT Operations | Proprietary Linux OS | Target Network Storage | Server Subnet (`10.10.2.41`) | Active | Management interface exposed over port 5000/5001 to entire network. |
| **A-13** | `WS-RAD-01` | IoT Medical | Central Radiology | Radiology | Windows XP SP3 | MRI Control Workstation | Central Subnet (`10.10.1.70`) | Active | Embedded legacy device. Operating system cannot be modified or updated. |
| **A-14** | `WS-RECEPT-01` | Endpoint | Central 1st Floor | Administrative | Windows 10 (19045) | AD Domain Access, RDP | Central Subnet (`10.10.1.10`) | Active | Front desk terminal. Open ports include 3389 without restriction. |
| **A-15** | `WS-NURSE-03` | Endpoint | Central 3rd Floor | Clinical Staff | Windows 10 (19045) | Active EHR Client Session | Central Subnet (`10.10.1.35`) | Active | Subject of physical audit observation; left unlocked with open PHI. |
| **A-16** | `PT-MON-47` | IoT Medical | Central Patient Room | Clinical Care | Philips Embedded (v2.1.3)| Vital Signs Monitoring | Central Subnet (`10.10.3.47`) | Active | Runs vulnerable 2019 firmware on flat workstation network segment. |
| **A-17** | `BD-PUMP-88` | IoT Medical | Central 3rd Floor | Clinical Care | BD Alaris Embedded | Infusion Dosage Control | Central Subnet (`10.10.3.88`) | Active | Network-connected dosage apparatus; visible on live network scan. |
| **A-18** | `FW-CENTRAL` | Network Device | Central Basement | IT Operations | FortiOS (FortiGate 100F)| Perimeter Firewall, VPN | Gateway Segment | Active | Terminates incoming site-to-site VPN channels from Westside and HQ. |
| **A-19** | `ws-srv-02` | Server | Westside Closet | Unknown | Unknown | Unknown | Westside Subnet (`10.10.10.16`) | Shadow IT | Discovered active during Nmap scan; completely absent from IT inventory. |
| **A-20** | `INTERN-LAP` | Endpoint | Central Corporate | IT Department | Windows 11 / Linux | BitTorrent Client | Corporate Subnet (`10.10.4.112`) | Shadow IT | Intern's personal device connected to internal production network segment. |

---

## 2. Reconciliation Notes

### Undocumented Assets / Shadow IT (Found in Scan, Missing in Documentation)
* **`ws-srv-02` (`10.10.10.16`)**: This server responded actively during the network scan on the Westside Clinic subnet, running unexpected open ports. It matches Marcus's informal notes regarding a "second, unconfirmed server hidden in the clinic closet," but it is entirely undocumented in Sarah Park's master asset sheets.
* **`INTERN-LAP` (`10.10.4.112`)**: This rogue node appeared on the internal corporate wireless network segment for three weeks running a bit-torrent client. It represents a temporary Shadow IT threat asset missing from corporate asset deployment logs.

### Missing Assets (In Documentation, Missing or Contradictory in Scan)
* **`print-srv-01` Status Friction**: In the master IT ticketing inventory logs, this host was explicitly flagged as `[UNVERIFIED]` and was suspected of being offline or deprecated. However, the active network scan successfully discovered the asset online at `10.10.2.31`, confirming it is actively running legacy Windows Server 2012 R2 architecture.

### Source Discrepancies and Contradictions
* **Network Layout Fallacy**: The original structural onboarding packet claimed that the Westside Clinic and Central Hospital networks operated with distinct infrastructure integrity boundaries. The network scan invalidates this by showing that medical IoT equipment (`10.10.3.47`) and employee administrative machines (`10.10.1.10`) communicate across a completely flat, unsegmented routing field with zero operational boundary filters.
* **Database Exposure Reality**: Official administrative policy stated that access to `ehr-db-01` (PostgreSQL) was limited to authorization boundaries. The network scan contradicts this policy by proving that port 5432 is actively listening and completely exposed to any node across the entire `10.10.0.0/16` corporate network.
