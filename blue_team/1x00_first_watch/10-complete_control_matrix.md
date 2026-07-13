# Complete Security Control Matrix: MedDefense Health Systems

This document serves as the single consolidated, authoritative source of truth for all identified security controls across MedDefense Health Systems, mapping their structural categories, functional impact, and measured operational effectiveness.

---

## Part 1: Comprehensive Control Registry

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence / Source |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **C-001** | Inbound Perimeter Firewall Filtering | Technical | Preventive | Public Website (`web-srv-01`), DMZ Zone | Adequate | Artifact 1: Firewall Configuration |
| **C-002** | Default-Deny Firewall Policy | Technical | Preventive | Entire Internal Network Infrastructure | Strong | Artifact 1: Firewall Configuration |
| **C-003** | Explicit Public Key SSH Authentication | Technical | Preventive | EHR Application Server (`ehr-srv-01`) | Strong | Artifact 2: SSH Configuration |
| **C-004** | Root SSH Session Restriction | Technical | Preventive | EHR Application Server (`ehr-srv-01`) | Strong | Artifact 2: SSH Configuration |
| **C-005** | AD Group Policy Password Constraints | Technical | Preventive | All Domain-Joined Windows Hosts | Adequate | Artifact 3: Password Policy Document |
| **C-006** | Account Lockout Threshold | Technical | Preventive | All Enterprise User Directory Accounts | Adequate | Artifact 3: Password Policy Document |
| **C-007** | Endpoint Malware Quarantine | Technical | Preventive | Windows 10/11 Workstations | Adequate | Artifact 4: Sophos Status Report |
| **C-008** | Nightly Automated Infrastructure Backups | Technical | Corrective | Core Servers (`ehr-srv-01`, `ehr-db-01`, etc.) | Weak | Artifact 5: Backup Configuration |
| **C-009** | Information Security Policy Issuance | Administrative | Preventive | All Corporate Information Assets | Adequate | Artifact 3: Password Policy Document |
| **C-010** | Mandatory Security Awareness Training | Administrative | Preventive | Corporate Human Resources & Staff | Weak | Artifact 7: Training Records |
| **C-011** | Main Lobby Security Guard Presence | Physical | Preventive | Hospital Main Lobby Zone | Adequate | Artifact 6: Physical Security Contract |
| **C-012** | Local Perimeter Video Surveillance DVR | Physical | Detective | Central Hospital & Clinic Entrances | Adequate | Artifact 6: Physical Security Contract |
| **C-013** | Network Micro-Segmentation for Legacy MRI | Technical | Compensating | Legacy MRI Workstation (`WS-RAD-01`) | Strong | Task 6: Compensating Control Strategy |
| **C-014** | Physical Port Locks & USB Disablement | Physical | Preventive | Legacy MRI Workstation (`WS-RAD-01`) | Strong | Task 6: Compensating Control Strategy |
| **C-015** | Clinical Station Auto-Lock Policy | Administrative | Preventive | Care Floor Workstations | Weak | Task 3: Physical Walk-through |

---

## Part 2: Updated Control Summary Matrix

The following matrix represents the distribution count of identified security controls across each category and function, tracking their calculated average operational effectiveness.

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Technical** | 6 Controls <br>*(Avg: Adequate)* | 0 Controls <br>*(N/A)* | 1 Control <br>*(Avg: Weak)* | 1 Control <br>*(Avg: Strong)* | 0 Controls <br>*(N/A)* |
| **Administrative** | 3 Controls <br>*(Avg: Weak)* | 0 Controls <br>*(N/A)* | 0 Controls <br>*(N/A)* | 0 Controls <br>*(N/A)* | 0 Controls <br>*(N/A)* |
| **Physical** | 2 Controls <br>*(Avg: Strong)* | 1 Control <br>*(Avg: Adequate)* | 0 Controls <br>*(N/A)* | 0 Controls <br>*(N/A)* | 0 Controls <br>*(N/A)* |

---

## Part 3: Control Coverage Map for Top 5 Critical Assets

This section evaluates the defensive depth surrounding MedDefense's top 5 most critical assets by mapping the specific controls assigned to protect them.

| Critical Asset | Preventive Controls | Detective Controls | Corrective Controls | Compensating Controls | Coverage Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. `ehr-db-01`** <br>*(Core Database Server)* | C-002, C-005, C-006 | None | C-008 *(Weak)* | None | **Under-Protected** <br>Missing technical detective controls (no SIEM/logging) and lacks offsite or cloud-isolated backups. |
| **2. `ehr-srv-01`** <br>*(EHR App Server)* | C-002, C-003, C-004, C-005 | None | C-008 *(Weak)* | None | **Partially Protected** <br>Strong preventive access controls exist via hardened SSH, but possesses no technical real-time detection capacity. |
| **3. `FW-CENTRAL`** <br>*(Perimeter Firewall)* | C-002 | None | None | None | **Under-Protected** <br>Completely lacks an active configuration backup policy or hardware failover redundancy. |
| **4. `pacs-srv-01`** <br>*(PACS Imaging Server)* | C-002, C-005, C-006 | None | None | None | **Unprotected** <br>Completely excluded from the nightly backup routines (`C-008`), meaning a ransomware attack causes total loss. |
| **5. `ad-dc-01`** <br>*(Domain Controller)* | C-002, C-005, C-006 | None | C-008 *(Weak)* | None | **Under-Protected** <br>Highly vulnerable to internal active directory privilege escalation due to a complete lack of authentication monitoring. |
