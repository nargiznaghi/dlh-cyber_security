# 11. Control Selection & Dependency Architecture

## Risk-to-Control Mapping

### 1. Control Selection for RISK-001 (Ransomware Encryption of Core EHR Database)
* **Risk:** RISK-001
* **Selected Control:** Network Segmentation (VLANs & Access Control Lists) + Sophos Intercept X EDR
* **CIS Control Mapping:** CIS Control 12.1 (Ensure Network Infrastructure is Up-to-Date), CIS Control 10.1 (Deploy Automated Anti-Malware Software)
* **NIST CSF Mapping:** PR.AC-5 (Network Integrity & Isolation), PR.DS-1 (Data-at-Rest Protection)
* **Control Type:** Preventive
* **Control Category:** Technical
* **Implementation Cost:** $15,000 (Network Segmentation) + $22,000 (EDR Upgrade) = $37,000
* **Expected Risk Reduction:** Cuts ARO from 0.30 to 0.03 and reduces EF from 100% to 50%, yielding an ALE reduction of $2,757,375[cite: 3].
* **Dependencies:** None (Requires core network switch and firewall configuration)[cite: 3].

---

### 2. Control Selection for RISK-002 (Perimeter Breach via Remote VPN)
* **Risk:** RISK-002[cite: 3]
* **Selected Control:** Mandatory Multi-Factor Authentication (MFA) Deployment on FortiGate VPN & Azure AD[cite: 3]
* **CIS Control Mapping:** CIS Control 6.3 (Require MFA for Remote Access), CIS Control 6.5 (Require MFA for Administrative Access)
* **NIST CSF Mapping:** PR.AC-3 (Remote Access Management), PR.AC-7 (Role-Based Access & Authentication)
* **Control Type:** Preventive
* **Control Category:** Technical
* **Implementation Cost:** $5,000 (MFA Integration Labor via existing M365 E3 licenses)[cite: 3]
* **Expected Risk Reduction:** Drops VPN breach ARO from 0.38 to 0.02, resulting in an ALE reduction of $3,437,280[cite: 3].
* **Dependencies:** M365 E3 Identity Federation with FortiGate VPN[cite: 3].

---

### 3. Control Selection for RISK-003 (Large-Scale ePHI Breach via EHR Exfiltration)
* **Risk:** RISK-003[cite: 3]
* **Selected Control:** Database Access Control Lists (ACLs) & Wazuh Open-Source SIEM Data Exfiltration Rules[cite: 3]
* **CIS Control Mapping:** CIS Control 3.3 (Configure Data Access Control Lists), CIS Control 8.5 (Collect Detailed Audit Logs)
* **NIST CSF Mapping:** PR.DS-5 (Data Leakage Protection), DE.AE-1 (Anomalous Activity Detection)
* **Control Type:** Detective & Preventive
* **Control Category:** Technical
* **Implementation Cost:** $18,000 (Wazuh SIEM Deployment)[cite: 3]
* **Expected Risk Reduction:** Drops likelihood of unmonitored mass data egress, providing $2,800,000+ in risk mitigation[cite: 3].
* **Dependencies:** Network Segmentation (RISK-001 control) to isolate database interfaces[cite: 3].

---

### 4. Control Selection for RISK-004 (Negligent Insider Data Leakage via Workstations)
* **Risk:** RISK-004[cite: 3]
* **Selected Control:** Group Policy USB Port Blocking, Dedicated User Accounts, & Security Awareness Training[cite: 3]
* **CIS Control Mapping:** CIS Control 14.1 (Establish a Security Awareness Program), CIS Control 10.3 (Disable Auto-Run and Removable Media)
* **NIST CSF Mapping:** PR.AT-1 (Security Awareness Training), PR.IP-1 (Baseline Endpoint Security Configurations)
* **Control Type:** Preventive & Administrative
* **Control Category:** Administrative / Technical
* **Implementation Cost:** $20,000 (Phishing Platform + Active Directory Hardening Labor)[cite: 3]
* **Expected Risk Reduction:** Reduces negligent insider incident frequency (ARO) from 2.50 to 0.30 per year, cutting ALE by $264,000[cite: 3].
* **Dependencies:** Active Directory Domain Controller deployment[cite: 3, 4].

---

### 5. Control Selection for RISK-005 (Automated Exploitation of Legacy Unpatched OS)
* **Risk:** RISK-005[cite: 3]
* **Selected Control:** Automated Patch Management Pipeline & Cloudflare Web Application Firewall (WAF)[cite: 3]
* **CIS Control Mapping:** CIS Control 7.4 (Automate Application Patch Management), CIS Control 13.10 (Deploy WAF)
* **NIST CSF Mapping:** ID.RA-1 (Vulnerability Management), PR.IP-3 (Change & Patch Management)
* **Control Type:** Preventive
* **Control Category:** Technical
* **Implementation Cost:** $25,000 (Patch Management Software + WAF Subscriptions)[cite: 3]
* **Expected Risk Reduction:** Drops successful vulnerability exploitation ARO from 0.50 to 0.05, yielding an ALE reduction of $212,850[cite: 3].
* **Dependencies:** Inventory management baseline[cite: 3].

---

### 6. Control Selection for RISK-006 (Tampering on Networked Medical Devices)
* **Risk:** RISK-006[cite: 3]
* **Selected Control:** Administrative Credential Hardening & Dedicated Air-Gapped Medical VLAN[cite: 3]
* **CIS Control Mapping:** CIS Control 4.1 (Maintain Secure Configuration Baselines), CIS Control 12.2 (Establish Isolated Subnets)
* **NIST CSF Mapping:** PR.IP-1 (Baseline Configurations), PR.AC-5 (Network Isolation)
* **Control Type:** Preventive
* **Control Category:** Technical / Operational
* **Implementation Cost:** $5,000 (Credential Audit Labor & Switch Configuration)[cite: 3]
* **Expected Risk Reduction:** Reduces device compromise ARO from 0.10 to 0.005, yielding an ALE reduction of $93,725[cite: 3].
* **Dependencies:** Network Segmentation Architecture (RISK-001 control)[cite: 3].

---

### 7. Control Selection for RISK-007 (Compromise of Remote Branch Perimeter)
* **Risk:** RISK-007[cite: 3]
* **Selected Control:** Enterprise Next-Generation Firewall Deployment (Replacing Consumer Router)[cite: 3]
* **CIS Control Mapping:** CIS Control 4.4 (Leverage Enterprise Edge Appliances), CIS Control 12.4 (Enforce Firewalls at Perimeter Boundaries)
* **NIST CSF Mapping:** PR.AC-5 (Network Protection), PR.PT-4 (Network Perimeter Defense)
* **Control Type:** Preventive
* **Control Category:** Technical
* **Implementation Cost:** $4,000 (Hardware Appliance & Security Licenses)[cite: 3]
* **Expected Risk Reduction:** Drops branch compromise ARO from 0.30 to 0.02, reducing ALE by $41,000[cite: 3].
* **Dependencies:** Site-to-Site VPN Tunnel Configuration to Central Data Center[cite: 3, 4].

---

### 8. Control Selection for RISK-008 (Unmonitored Security Events Due to Missing Logging)
* **Risk:** RISK-008[cite: 3]
* **Selected Control:** Enterprise Open-Source SIEM Deployment (Wazuh) & Agent Log Forwarding[cite: 3]
* **CIS Control Mapping:** CIS Control 8.2 (Collect Audit Logs), CIS Control 8.9 (Centralize Log Management)
* **NIST CSF Mapping:** DE.AE-3 (Event Aggregation & Correlation), DE.CM-1 (Network Monitoring)
* **Control Type:** Detective
* **Control Category:** Technical
* **Implementation Cost:** $18,000 (Cloud Storage & Log Analytics Setup)[cite: 3]
* **Expected Risk Reduction:** Provides early incident detection across 100% of core assets, saving an estimated $102,000 in net risk exposure[cite: 3].
* **Dependencies:** Centralized Log Server Instance & Network Routing Setup[cite: 3].

---

### 9. Control Selection for RISK-009 (Ransomware Destruction of System Backups)
* **Risk:** RISK-009[cite: 3]
* **Selected Control:** Offsite Immutable Cloud Backup Replication (AWS S3 Glacier with Object Lock)[cite: 3]
* **CIS Control Mapping:** CIS Control 11.1 (Establish Automated Backup Recovery Processes), CIS Control 11.2 (Perform Isolated Backups)
* **NIST CSF Mapping:** PR.IP-4 (Data Backup Protections), RC.RP-1 (Recovery Execution Plan)
* **Control Type:** Corrective / Compensating
* **Control Category:** Technical / Operational
* **Implementation Cost:** $12,000 (AWS S3 Immutable Object Storage Fees)[cite: 3]
* **Expected Risk Reduction:** Guarantees 100% data recovery without ransom payments, reducing ALE by $1,272,250[cite: 3].
* **Dependencies:** Backup Agent Setup & Network Bandwidth Sizing[cite: 3].

---

### 10. Control Selection for RISK-010 (Unauthorized Exposure of Internal IT Services)
* **Risk:** RISK-010[cite: 3]
* **Selected Control:** Perimeter Inbound ACL Filtering & Removal of Direct Public IP Bindings[cite: 3]
* **CIS Control Mapping:** CIS Control 4.5 (Implement Inbound Access Control Rules), CIS Control 9.2 (Ensure Only Approved Ports/Services are Exposed)
* **NIST CSF Mapping:** PR.AC-5 (Network Perimeter Integrity), PR.PT-5 (Service Exposure Minimization)
* **Control Type:** Preventive
* **Control Category:** Operational
* **Implementation Cost:** $0 (Covered under general network firewall maintenance)[cite: 3]
* **Expected Risk Reduction:** Eliminates direct internet exposure of internal administration portals, yielding an estimated $135,000 ALE reduction[cite: 3].
* **Dependencies:** Network Segmentation & Firewall Deployment[cite: 3].

---

## Control Dependency Map

The diagram below illustrates the prerequisite relationships between selected controls. Foundation controls at the top must be implemented first to enable dependent downstream security capabilities:

```text
========================================================================================
                                 FOUNDATIONAL CONTROLS
========================================================================================
        │                                       │                                  │
        ▼                                       ▼                                  ▼
[Network Segmentation]              [M365 E3 Identity Federation]       [Branch Firewall Upgrade]
 (VLANs & Access Rules)               (Directory & Auth Foundation)       (Westside Clinic Edge)
        │                                       │                                  │
        ├────────────────────────┐              │                                  │
        │                        │              │                                  │
        ▼                        ▼              ▼                                  ▼
[Medical Device Isolation]  [Database ACLs]  [MFA Enforcement]           [Site-to-Site Tunnel]
 (Air-Gapped VLANs)          (ePHI Access)   (VPN & Admin Accounts)       (Encrypted Branch Comms)
        │                        │              │                                  │
        └────────────────────────┴──────────────┴──────────────────────────────────┘
                                 │
                                 ▼
========================================================================================
                            ENDPOINT & DETECTIVE CONTROLS
========================================================================================
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
        ▼                        ▼                        ▼
[Sophos Intercept X EDR]   [Wazuh SIEM System]     [Active Directory GPOs]
 (Endpoint Malware Block)   (Centralized Logs)      (USB Blocking & Hardening)
        │                        │                        │
        ▼                        ▼                        ▼
[Offsite Immutable Backup] [Security Alerts & KRIs] [Awareness Training]
 (AWS S3 Object Lock)       (Detection Dashboards)  (Phishing Simulations)
Dependency Execution Logic
Phase 1 (Core Perimeter & Network): Network Segmentation and M365 Identity Federation must precede database access controls, medical device isolation, and remote MFA[cite: 3].
Phase 2 (Endpoints & Logging): Centralized Network and Identity baselines allow Wazuh SIEM deployment and Sophos Intercept X EDR agent pushing across isolated subnets[cite: 3].
Phase 3 (Operational & Continuity): Active logging and endpoint security enable reliable offsite immutable backups and automated threat detection dashboards[cite: 3].
