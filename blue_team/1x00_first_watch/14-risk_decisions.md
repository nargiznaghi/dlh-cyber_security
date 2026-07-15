# Strategic Risk Treatment Decisions

This document outlines the risk treatment strategy, resource allocation, and budget trade-offs for the top 7 prioritized security gaps identified within MedDefense Health Systems.

---

## 1. Risk Treatment Log

### GAP-003: Critical PACS Infrastructure Omitted from Automated Nightly Backups
* **Risk Level:** Critical
* **Treatment Strategy:** Mitigate
* **Justification:** Complete data loss of medical diagnostics represents an unacceptable existential threat to patient care operations[cite: 3]. Securing backups is highly feasible with minimal capital outlay.
* **Proposed Control(s):** Technical Corrective (Automated backup inclusion for `pacs-srv-01` to an isolated, off-network backup repository).
* **Estimated Cost:** $1-10K (additional storage licenses and dedicated NAS/cloud repository).
* **Implementation Effort:** Quick Win (< 1 week)
* **Expected Risk Reduction:** High. Ensures 100% data recoverability in the event of ransomware encryption or severe hardware failure[cite: 3].
* **Trade-offs:** Increases localized backup storage footprint and requires ongoing physical isolation management.

### GAP-005: Flat Internal Routing Topology Allowing Lateral Worm Propagation
* **Risk Level:** Critical
* **Treatment Strategy:** Mitigate
* **Justification:** Flat networks allow a single desk compromise to reach life-critical medical equipment subnets and databases instantly[cite: 3]. Segmenting these networks is vital to containing breaches.
* **Proposed Control(s):** Technical Preventive (Internal Firewall Access Control Lists, VLAN segmentation dividing medical devices, servers, and staff).
* **Estimated Cost:** $10-50K (utilizing existing FortiGate architecture but requiring professional services/labor for redesign).
* **Implementation Effort:** Long-term (> 1 month)
* **Expected Risk Reduction:** Very High. Confines any localized malware or unauthorized access to its starting subnet, preventing automated lateral movement.
* **Trade-offs:** Requires thorough service mapping and causes brief operational downtime windows during migration.

### GAP-011: Lack of Automated Identity Lifecycle and Missing MFA on Remote Portals
* **Risk Level:** Critical
* **Treatment Strategy:** Mitigate
* **Justification:** Compromised credentials are the easiest point of entry for bad actors[cite: 3]. Implementing identity gates prevents simple unauthorized logins.
* **Proposed Control(s):** Technical Preventive (Enforce MFA on all VPN/EHR access points and script basic AD disable tasks triggered by HR systems).
* **Estimated Cost:** $10-50K (duo/MFA licensing and integration costs).
* **Implementation Effort:** Short-term (< 1 month)
* **Expected Risk Reduction:** High. Completely blocks brute-force and credential stuffing attacks targeting patient data and Active Directory[cite: 3].
* **Trade-offs:** Adds minor friction to remote staff login workflow and increases IT support desk ticket volume initially.

### GAP-001: Absence of Centralized Log Management and Automated Alerting (SIEM)
* **Risk Level:** Critical
* **Treatment Strategy:** Mitigate (Phased Approach)
* **Justification:** Enterprise-tier SIEM license fees ($80,000+) would consume almost our entire budget. We will mitigate this with a cost-controlled, cloud-native log aggregator instead.
* **Proposed Control(s):** Technical Detective (Centralized syslog server forwarding to a scalable, pay-as-you-go cloud SIEM platform with basic alerting rules).
* **Estimated Cost:** $10-50K (budgeting $30,000 for initial setup and log intake sizing).
* **Implementation Effort:** Long-term (> 1 month)
* **Expected Risk Reduction:** Medium-High. Grants real-time visibility into active threats across domain controllers and critical databases[cite: 3].
* **Trade-offs:** Pay-as-you-go costs can spike if logs are not strictly filtered; security staff must manually tune alerts.

### GAP-002: Server Endpoint Infrastructure Left Entirely Unmonitored
* **Risk Level:** Critical
* **Treatment Strategy:** Transfer
* **Justification:** Installing and maintaining internal server EDR/EPP tooling requires dedicated, expensive security personnel. We will transfer endpoint monitoring to a Managed Detection and Response (MDR) provider.
* **Transfer Mechanism:** Outsourced Managed Security Service Provider (MSSP) delivering 24/7 endpoint monitoring, telemetry, and response.
* **Residual Risk:** Server vulnerabilities still require manual patching by internal IT staff; the MSSP only detects and isolates active threats.
* **Trade-offs:** Reliance on an external third-party vendor SLA for immediate incident response.

### GAP-012: Insecure DMZ Egress Rules and Unmanaged Default System Credentials
* **Risk Level:** Critical
* **Treatment Strategy:** Mitigate
* **Justification:** Public-facing assets must be isolated from critical medical IoT devices to prevent pivot attacks[cite: 3].
* **Proposed Control(s):** Technical Preventive (Hardening firewall rules to block DMZ-to-Internal traffic, and initiating a biomedical-managed password cleanup campaign).
* **Estimated Cost:** $0-1K (internal configuration changes).
* **Implementation Effort:** Short-term (< 1 month)
* **Expected Risk Reduction:** High. Eliminates the ability of external web compromises to pivot directly into internal hospital operations[cite: 3].
* **Trade-offs:** Restricts direct database lookups from DMZ, requiring secure intermediate APIs.

### GAP-008: Open Physical Security Access and Surveillance Blinds around Core Assets
* **Risk Level:** High
* **Treatment Strategy:** Accept (Temporary)
* **Justification:** The physical asset risks are currently buffered by monitored external facility boundaries[cite: 3]. Rewiring interior infrastructure corridors for extra cameras and badge readers is expensive and low priority compared to software vulnerabilities.
* **Acceptance Justification:** The cost of full-scale internal physical surveillance and remodeling exceeds the current expected loss of physical server theft while outer perimeter guards are active.
* **Review Trigger:** Revisit this decision if external perimeter monitoring policies lapse or during the next annual review.
* **Trade-offs:** Accepting this risk leaves MedDefense vulnerable to an undetected physical insider threat[cite: 3].

---

## 2. Budget Summary ($120,000 Allocation)

By avoiding expensive enterprise licensing and shifting to cost-effective, smart mitigation strategies, we are able to address all top risks within the **$120,000** limit:

| Gap ID | Treatment Strategy | Solution Details | Estimated Cost |
| :--- | :--- | :--- | :--- |
| **GAP-003** | Mitigate | Isolated backup repository for PACS[cite: 3] | $8,000 |
| **GAP-005** | Mitigate | Professional services for internal network segmentation[cite: 3] | $40,000 |
| **GAP-011** | Mitigate | Remote VPN/EHR MFA & HR Integration | $20,000 |
| **GAP-001** | Mitigate (Phased) | Pay-as-you-go Cloud Log Aggregator[cite: 3] | $30,000 |
| **GAP-002** | Transfer | 1-Year MSSP / MDR Server Monitoring[cite: 3] | $21,000 |
| **GAP-012** | Mitigate | Firewall rules & administrative password hardening[cite: 3] | $1,000 |
| **GAP-008** | Accept | Temporarily accept internal physical blinds[cite: 3] | $0 |
| **TOTAL** | | | **$120,000** |

### Budget Deferrals
No critical mitigations were fully abandoned. However, the purchase of a dedicated, full-license **Enterprise On-Premises SIEM** (estimated at $80,000+) has been deferred to the next fiscal year. Instead, we are using a **$30,000 Cloud Log Aggregator** setup. This keeps us strictly within our $120,000 operational budget while immediately establishing crucial detective monitoring capabilities.
