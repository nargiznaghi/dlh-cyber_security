# Security Controls Inventory: MedDefense Health Systems

This document logs and classifies the existing security controls identified within the organization's configuration files, policy guidelines, and vendor agreements using a dual-axis taxonomy.

---

## 1. Security Controls Log

Control ID: C-001
Control Name: Inbound Perimeter Firewall Filtering
Description: Restricts external public internet traffic to the DMZ network segment by allowing only HTTP and HTTPS traffic specifically directed to web-srv-01, blocking all other services.
Category: Technical
Function: Preventive
Asset(s) Protected: Public Website and Patient Portal (`web-srv-01`), DMZ Zone.
Source: Artifact 1: Firewall Configuration Extract (FortiGate 100F)

Control ID: C-002
Control Name: Default-Deny Firewall Policy
Description: A final explicit rule that drops all traffic matching no prior whitelist parameters across any interfaces.
Category: Technical
Function: Preventive
Asset(s) Protected: Entire Internal Network Infrastructure.
Source: Artifact 1: Firewall Configuration Extract (FortiGate 100F)

Control ID: C-003
Control Name: Explicit Public Key SSH Authentication
Description: Disables standard interactive password prompts (`PasswordAuthentication no`) and forces connection validations using pre-shared asymmetric keys on ehr-srv-01.
Category: Technical
Function: Preventive
Asset(s) Protected: EHR Application Server (`ehr-srv-01`).
Source: Artifact 2: SSH Configuration

Control ID: C-004
Control Name: Root SSH Session Restriction
Description: Prevents direct remote access logins under the root administrative credential (`PermitRootLogin no`).
Category: Technical
Function: Preventive
Asset(s) Protected: EHR Application Server (`ehr-srv-01`).
Source: Artifact 2: SSH Configuration

Control ID: C-005
Control Name: Active Directory Group Policy Password Constraints
Description: Enforces specific length constraints (minimum 8 characters) and complexity criteria (uppercase, lowercase, numbers, and symbols) on Windows endpoints.
Category: Technical
Function: Preventive
Asset(s) Protected: All Domain-Joined Windows Workstations and Servers.
Source: Artifact 3: Password Policy Document

Control ID: C-006
Control Name: Account Lockout Threshold Enforcement
Description: Temporarily disables user account access for 30 minutes following 5 consecutive failed login attempts.
Category: Technical
Function: Preventive
Asset(s) Protected: All Enterprise User Directory Accounts.
Source: Artifact 3: Password Policy Document

Control ID: C-007
Control Name: Endpoint Malware Quarantine and Alerting
Description: Scans local file spaces, blocks detected payloads (such as Trojan or CryptoMiner activities), and isolates infected files on monitored endpoints.
Category: Technical
Function: Preventive
Asset(s) Protected: Windows 10/11 Workstations.
Source: Artifact 4: Sophos Antivirus Status Report

Control ID: C-008
Control Name: Nightly Automated Infrastructure Backups
Description: Executes an automated full VM snapshot migration to a local NAS storage daily at 02:00 AM.
Category: Technical
Function: Corrective
Asset(s) Protected: `ehr-srv-01`, `ehr-db-01`, `billing-srv-01`, `ad-dc-01`, `file-srv-01`, `web-srv-01`.
Source: Artifact 5: Backup Configuration

Control ID: C-009
Control Name: Information Security Policy Issuance
Description: Formally defines credential complexity parameters, account lifespan rotations, and responsibilities for corporate network resource utilization.
Category: Administrative
Function: Preventive
Asset(s) Protected: All Corporate Information Assets and User Accounts.
Source: Artifact 3: Password Policy Document

Control ID: C-010
Control Name: Mandatory Security Awareness Training
Description: An annual online instructional course (CyberSafe Basics) designed to teach staff password hygiene, phishing recognition, and physical safety actions.
Category: Administrative
Function: Preventive
Asset(s) Protected: Corporate Human Resources and Organizational Staff.
Source: Artifact 7: Training Records

Control ID: C-011
Control Name: Main Lobby Security Guard Presence
Description: Deploys a physical security guard at the central hospital main lobby from Monday to Friday (07:00 to 19:00) to register visitors and verify staff badges.
Category: Physical
Function: Preventive
Asset(s) Protected: MedDefense Central Hospital Main Lobby Zone.
Source: Artifact 6: Physical Security Contract

Control ID: C-012
Control Name: Local Perimeter Video Surveillance DVR
Description: Captures continuous footage at core access boundaries (such as main/ER entrances and the parking garage) with 30 days of retrospective local disk retention.
Category: Physical
Function: Detective
Asset(s) Protected: Central Hospital and Westside Clinic Facility Entrances.
Source: Artifact 6: Physical Security Contract

---

## 2. Control Summary Matrix

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Technical** | C-001, C-002, C-003, C-004, C-005, C-006, C-007 | | C-008 | | |
| **Administrative** | C-009, C-010 | | | | |
| **Physical** | C-011 | C-012 | | | |

---

## 3. Analysis of Structural Control Gaps

Based on the completed matrix above, several dangerous operational gaps are instantly apparent:

*   **Total Lack of Technical Detective Controls:** There are no automated Technical Detective controls (such as a SIEM, IDS/IPS, or automated alert forwarders) listed in the artifacts. Network logs are purely historical, un-centralized, and checked manually only *after* a crash occurs.
*   **Absence of Technical Corrective Redundancy:** While backups exist, they are stored in the same room, network, and rack row as production hosts, creating an architecture that completely undermines the viability of the corrective control during a ransomware outbreak.
*   **Physical Security Disconnects:** There are zero Physical Corrective or Deterrent controls formally registered. Additionally, critical backend sectors (server room corridors, network closets) have no camera coverage or active physical monitoring[cite: 3].
