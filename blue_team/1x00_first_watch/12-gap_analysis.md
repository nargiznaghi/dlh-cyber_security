# Prioritized Security Gap Analysis

This document consolidates and prioritizes the structural security gaps within MedDefense Health Systems by cross-referencing asset criticality, data classification lifecycle vulnerabilities, and control matrix effectiveness based on network monitoring logs and official artifacts.

---

## 1. Prioritized Gap Registry

### GAP-001: Absence of Centralized Log Management and Automated Alerting (SIEM)
* **Affected Asset(s):** `ehr-db-01`, `ehr-srv-01`, `ad-dc-01` (Critical)
* **Data at Risk:** Patient Medical Records (EHR) (Restricted)
* **Current Control Status:** None. Logs exist only locally with rapid rotation and require manual post-incident inspection.
* **What is Missing:** Technical Detective function.
* **Risk Level:** Critical
* **Risk Justification:** Affects top-tier critical clinical infrastructure and restricted PHI data with zero real-time detection or detective controls.
* **Potential Impact:** Attackers can establish long-term persistence, exfiltrate entire patient databases, or execute ransomware without triggering any infrastructure-level alerts before operational collapse.

### GAP-002: Server Endpoint Infrastructure Left Entirely Unmonitored
* **Affected Asset(s):** `ehr-srv-01`, `billing-srv-01`, `ehr-db-01` (Critical / High)
* **Data at Risk:** Patient Medical Records, Financial & Billing Data (Restricted)
* **Current Control Status:** Sophos Endpoint Protection covers workstations only; windows and linux servers are completely unlicensed.
* **What is Missing:** Technical Preventive and Technical Detective endpoint security.
* **Risk Level:** Critical
* **Risk Justification:** Essential application and payment servers lack host-level protection, allowing unhindered process manipulation on critical targets.
* **Potential Impact:** Threat actors can freely plant crypto-miners (as seen on `billing-srv-01`), execute memory-injection payloads, or wipe active application partitions without host-level blocking.

### GAP-003: Critical PACS Infrastructure Omitted from Automated Nightly Backups
* **Affected Asset(s):** `pacs-srv-01` (Critical)
* **Data at Risk:** Medical Imaging Data (Restricted)
* **Current Control Status:** Nightly Backups exist but explicitly exclude the PACS system.
* **What is Missing:** Technical Corrective control capability.
* **Risk Level:** Critical
* **Risk Justification:** Failure points directly toward a critical asset and restricted diagnostics without any available corrective recovery backup.
* **Potential Impact:** A storage hardware crash or ransomware attack results in the permanent, unrecoverable loss of historical patient X-Rays, MRIs, and medical diagnostics, rendering continuity impossible.

### GAP-004: Cleartext Database Interfacing Exposed to the Entire Network
* **Affected Asset(s):** `ehr-db-01` (Critical), `billing-srv-01` (High)
* **Data at Risk:** Patient Medical Records, Financial & Billing Data (Restricted)
* **Current Control Status:** Default port binding rules allow global visibility to internal ranges.
* **What is Missing:** Technical Preventive (Network Access Control and Encryption in Transit).
* **Risk Level:** Critical
* **Risk Justification:** Restricted data stores are directly accessible in cleartext by unprivileged nodes across a completely flat internal architecture.
* **Potential Impact:** Any infected floor workstation or rogue shadow device can run unauthorized queries directly against ports 5432 and 3306 to harvest entire repositories of patient data.

### GAP-005: Flat Internal Routing Topology Allowing Lateral Worm Propagation
* **Affected Asset(s):** All Internal Systems, including Medical IoT Subnets (Critical / High)
* **Data at Risk:** Patient Medical Records, Medical Device Streams (Restricted)
* **Current Control Status:** Global routing allows unverified outbound traffic between internal networks.
* **What is Missing:** Technical Preventive (Internal Network Segmentation).
* **Risk Level:** Critical
* **Risk Justification:** Compromise of a low-criticality asset grants immediate network path access to life-critical infrastructure and restricted records.
* **Potential Impact:** An automated ransomware or malware infection entering via phishing at a receptionist desk can cross subnets immediately to compromise core medical hardware and production data environments.

### GAP-006: Unrestricted Global Network Egress to the Internet
* **Affected Asset(s):** Entire Internal Network (Critical / High)
* **Data at Risk:** All Corporate Data Categories (Restricted / Confidential)
* **Current Control Status:** Perimeter Firewall accepts all outbound protocols and destinations.
* **What is Missing:** Technical Preventive (Egress Filtering / Traffic Validation).
* **Risk Level:** High
* **Risk Justification:** Incomplete perimeter control coverage affecting confidential and restricted data streams leaving the building.
* **Potential Impact:** Compromised internal systems can effortlessly open outbound Command and Control (C2) reverse shells, establish unauthorized encrypted proxy lines, or stream stolen mass archives to public drop points.

### GAP-007: Absence of Disaster Recovery Testing and System Verification
* **Affected Asset(s):** Core Server Infrastructure Cluster (Critical)
* **Data at Risk:** Patient Medical Records, Active Directory State (Restricted)
* **Current Control Status:** Nightly Backups exist on paper, but a restore test has never been executed for critical systems.
* **What is Missing:** Administrative and Technical Corrective verification.
* **Risk Level:** High
* **Risk Justification:** Incomplete control architecture over highly critical assets leaves recovery capabilities completely theoretical.
* **Potential Impact:** During a disaster recovery incident, MedDefense faces extended operational blackout because backup files may be corrupted or un-restorable, prolonging clinical downtime indefinitely.

### GAP-008: Open Physical Security Access and Surveillance Blinds around Core Assets
* **Affected Asset(s):** Server Room Corridor, Central Network Closets (Critical)
* **Data at Risk:** Direct Access to Server Physical Drives, Hardcoded Credentials (Restricted)
* **Current Control Status:** External facility entrances are monitored, but interior administrative corridors are blind.
* **What is Missing:** Physical Detective control coverage.
* **Risk Level:** High
* **Risk Justification:** High-criticality equipment corridors suffer from incomplete baseline monitoring, facilitating undocumented physical proximity threats.
* **Potential Impact:** An unauthorized actor or malicious insider can enter core server zones undetected, remove physical backup arrays, or connect rogue hardware taps to internal ports.

### GAP-009: Pervasive Shadow IT Devices Operating Outside Corporate Governance
* **Affected Asset(s):** `UNKNOWN-01` Linux Host, Westside Shadow Device (Medium / High)
* **Data at Risk:** Corporate Communications, Internal Network Traffic Metadata (Restricted / Confidential)
* **Current Control Status:** Completely unmapped and unmanaged by official security policies.
* **What is Missing:** Administrative Governance and Technical Preventive (Network Access Control).
* **Risk Level:** High
* **Risk Justification:** Confidential data assets are operating in entirely unmanaged spaces with incomplete and bypassed control coverage.
* **Potential Impact:** Vulnerable consumer-grade hardware or insecure cloud accounts leak data or act as quiet backdoors for external threat actors to pivot directly into the main enterprise infrastructure.

### GAP-010: Absence of File Integrity Monitoring on Public-Facing Infrastructure
* **Affected Asset(s):** `web-srv-01` (High)
* **Data at Risk:** Public Portal & Website Content (Public)
* **Current Control Status:** Simple firewall filtering on inbound web ports.
* **What is Missing:** Technical Detective (File Integrity Monitoring / FIM).
* **Risk Level:** Medium
* **Risk Justification:** Affects a high-priority public asset but involves lower data classification levels, featuring basic perimeter protections.
* **Potential Impact:** Malicious actors can seamlessly swap web directory code to perform public page defacement or inject hidden phishing hooks targeting external patient login credentials without detection.

---

## 2. Gap Distribution Summary

### Risk Level Metrics
* **Critical-level Gaps:** 5
* **High-level Gaps:** 4
* **Medium-level Gaps:** 1
* **Low-level Gaps:** 0

### Asset Categories with Highest Vulnerability Density
The **Core Server Infrastructure** (including `ehr-db-01`, `ehr-srv-01`, and `pacs-srv-01`) possesses the highest concentration of security gaps. This layer is directly targeted by 7 distinct gaps across network visibility, endpoint monitoring omissions, backup deficiencies, and detection failures.

### Functional Concentration Trend
The security gaps are heavily concentrated within the **Technical Detective** and **Technical Preventive (Segmentation & Encryption)** categories. While basic administrative policies and outer perimeter filters are established on paper, MedDefense completely lacks internal boundaries to slow down lateral movement or detective logging controls to identify a breach once the outer perimeter is crossed.
