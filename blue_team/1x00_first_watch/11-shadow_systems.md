# Shadow IT Risk Assessment and Recommendations

This document identifies unmanaged devices and cloud platforms operating outside MedDefense's official IT governance frameworks, outlining their inherent technical risks and enforcing mitigation strategies.

---

## 1. Shadow IT Asset Risk Profile & Strategy

### System 1: Dr. Patel's Personal NAS Drive (Cardiology Office)
* **Risk Assessment:**
  * **Sensitive Data Contained:** Restricted Healthcare Information (PHI), active cardiology patient records, and unapproved medical research data.
  * **Missing Official Controls:** Completely unmapped by Endpoint Malware Quarantine (C-007), entirely excluded from official Nightly Infrastructure Backups (C-008), and untracked by corporate Password Constraints (C-005).
  * **Worst-Case Scenario:** An attacker exploits outdated, unpatched software firmware on the consumer-grade NAS exposed over the flat network topology, encrypting or stealing 50,000+ patient clinical records, triggering severe HIPAA financial penalties and regulatory shutdown.
* **Recommended Response:** **Migrate and Decommission.** Move all research files and diagnostic imaging data over to the secure, authorized network fileshare (`file-srv-01`) or the PACS environment (`pacs-srv-01`). Once data integration is confirmed, physically confiscate and decommission the personal storage device to enforce strict network perimeter compliance.

### System 2: Marketing Team Shared Google Drive (Personal Gmail)
* **Risk Assessment:**
  * **Sensitive Data Contained:** Confidential internal public relations strategies, hospital press communications, employee identities, and potentially sensitive patient media release consent records.
  * **Missing Official Controls:** Completely bypasses corporate firewall logging architectures, avoids standard Account Lockout thresholds (C-006), and escapes corporate Information Security Policy Issuance monitoring loops (C-009).
  * **Worst-Case Scenario:** The personal Gmail account hosting the drive suffers a credential stuffing attack due to a weak password. Threat actors leak confidential media logs publicly or inject malicious document attachments that internal marketing staff sync back onto corporate production endpoints.
* **Recommended Response:** **Migrate.** Transition the entire marketing department's document ecosystem onto a corporate-managed Google Workspace or Microsoft 365 tenant enforced with Enterprise Single Sign-On (SSO) and mandatory Multi-Factor Authentication (MFA). Revoke access to the personal drive links.

### System 3: Abandoned Intern Raspberry Pi (Central 2nd Floor)
* **Risk Assessment:**
  * **Sensitive Data Contained:** Network topology schematics, cleartext internal system credentials captured during network monitoring, packet capture PCAP files holding active EHR metadata transit streams.
  * **Missing Official Controls:** Escapes physical monitoring bounds (C-012), has no software inventory coverage, and circumvents standard SSH key hardening or access rules (C-003, C-004).
  * **Worst-Case Scenario:** A malicious insider or external threat actor discovers the forgotten device hidden on the second floor, plugs directly into its interactive interfaces, and leverages its network monitor positioning to launch automated network-wide credential attacks on `ad-dc-01` without raising alarms.
* **Recommended Response:** **Decommission.** Locate the device physically on the second floor, disconnect it immediately from the wall patch panel socket, securely wipe its SD card flash memory storage array to prevent physical credential recovery, and dispose of the hardware kit safely.

---

## 2. Asset Registry Integration Addendum

The following entries reflect the shadow systems integrated directly into the organization's overarching asset monitoring scope:

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A-21** | `CARD-NAS-SHADOW` | Data Store | Central 2nd Floor | Cardiology | Consumer Linux | SMB File Sharing | Central Subnet (`10.10.1.x`) | Shadow IT | Personal NAS drive connected to corporate network interface ports by Dr. Patel. |
| **A-22** | `MKT-DRIVE-SHADOW`| Application | External Cloud | Marketing | Google Drive | File Storage / Media | External Public WAN | Shadow IT | Corporate data stored outside organizational tenants using a personal Gmail account. |
| **A-23** | `INTERN-PI-SHADOW`| Network Device| Central 2nd Floor | IT Operations | Raspberry Pi OS | Local Packet Capturing | Central Subnet (`10.10.1.x`) | Shadow IT | Abandoned network monitoring bridge established by a previous intern; unmonitored. |

---

## 3. Shadow IT Policy Recommendation

To systematically reduce the proliferation of unmanaged shadow assets moving forward, MedDefense must implement a strict, automated **Network Access Control (NAC)** policy framework. The organization must shift from its historically passive approach to an active technical enforcement stance: any unauthorized hardware asset plugged into an internal physical wall port or connecting to corporate wireless channels must be systematically blocked and quarantined at the hardware layer using MAC-filtering and 802.1X network authentication profiles. This technical gating must be explicitly supported by an update to the Information Security Policy mandate, making the deployment of unapproved external hardware devices or non-corporate cloud instances a severe, auditable disciplinary infraction for all personnel.
