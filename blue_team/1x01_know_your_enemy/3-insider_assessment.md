# Insider Threat Assessment for MedDefense

## Scenario 1: The Shared Login
*   **Classification:** Negligent. The clinical technicians are sharing credentials for operational efficiency and convenience to speed up patient care, rather than acting with intent to cause harm or steal data.
*   **Behavioral Indicators:** 
    *   Simultaneous or overlapping active sessions originating from different terminals under the identical user account identifier.
    *   Substantial volume spikes in PACS image views that cannot be attributed to a single clinician's working schedule.
    *   Zero explicit user logout events recorded in application logs over an extended multi-shift period.
*   **Existing Control:** AC-01 (Access Control Policy) / IA-01 (Identification and Authentication Policy).
*   **Gap Exploited:** GAP-011 (Lack of Individual Accountability / Shared Accounts).
*   **Recommended Mitigation:** Administrative & Technical: Implement Tap-and-Go proximity smart card authentication (e.g., Imprivata) on all shared clinical workstations to allow rapid, individual session switching without disrupting care workflows.

---

## Scenario 2: The Ghost Account
*   **Classification:** Malicious. Authenticating 3 times during off-hours weeks after contract termination strongly points to unauthorized, intentional system access.
*   **Behavioral Indicators:**
    *   VPN authentication events occurring during atypical off-hours (e.g., 11 PM to 4 AM) from non-standard geographic IP space.
    *   Sudden network activity associated with an account tied to a contractor whose project milestone deliverables have ceased.
    *   Interactive network logons from a user account whose primary corporate email or ticketing assignments have been quiet.
*   **Existing Control:** IA-04 (Managing User Identifiers) / AC-02 (Account Management).
*   **Gap Exploited:** GAP-003 (Lack of Automated Offboarding / Stale Accounts).
*   **Recommended Mitigation:** Administrative: Establish an automated Identity and Access Management (IAM) workflow that automatically disables domain accounts upon the arrival of the contract termination date specified in the HR/Procurement database.

---

## Scenario 3: The Personal NAS
*   **Classification:** Negligent. The physician is setting up unsanctioned infrastructure ("Shadow IT") for personal convenience to simplify his research and daily consultations, unaware of the severe data exposure risks.
*   **Behavioral Indicators:**
    *   A new, unmanaged MAC address appearing on an internal switchport requesting a local DHCP lease.
    *   Continuous, large local file transfers from core EHR or storage servers toward an unclassified internal IP address.
    *   Unusual inbound SMB/NFS protocol traffic directed inside a specific clinician's private office walljack.
*   **Existing Control:** CM-08 (Information System Component Inventory).
*   **Gap Exploited:** GAP-014 (Lack of Network Access Control / Shadow IT Deployment).
*   **Recommended Mitigation:** Technical: Deploy 802.1X Network Access Control (NAC) to automatically block any rogue, unauthorized hardware assets from connecting to the internal physical network ports.

---

## Scenario 4: The Curious Employee
*   **Classification:** Malicious. While the clerk did not alter the data, intentionally accessing the medical records of a high-profile individual without a clinical care assignment constitutes a deliberate violation of privacy laws, which resulted in an intentional data leak.
*   **Behavioral Indicators:**
    *   A user account searching for and opening an EHR record that has no relation to the patients currently scheduled or admitted at their specific front-desk unit.
    *   A sudden spike in record lookups for a high-profile or celebrity name recently admitted to the facility.
    *   An unusual volume of unique patient records viewed by a single administrative registration profile within a short timeframe.
*   **Existing Control:** AU-02 (Audit Events) / Privacy Monitoring Policy.
*   **Gap Exploited:** GAP-007 (Lack of User Behavior Analytics / Insufficient Audit Log Monitoring).
*   **Recommended Mitigation:** Technical: Implement automated User Behavior Analytics (UBA) or an EHR auditing tool (e.g., FairWarning) that automatically triggers alerts for out-of-scope lookups or high-profile patient record access.

---

## Scenario 5: The Overworked Admin
*   **Classification:** Negligent. The systems administrator is attempting to cope with a heavy operational backlog by scripting, but inadvertently introduces catastrophic vulnerabilities by storing and transmitting plaintext credentials in the clear.
*   **Behavioral Indicators:**
    *   Plaintext administrative credentials identified during automated file share scans or local endpoint directory reviews.
    *   Atypical internal email attachments or messages containing keywords like "password," "admin," or "reset_script" flagged by data loss monitors.
    *   High-privilege service accounts executing password reset commands from non-standard source directories or custom scripts.
*   **Existing Control:** IA-05 (Authenticator Management) / Private Credential Protection.
*   **Gap Exploited:** GAP-012 (Lack of Secure Coding Standards / Poor Privileged Identity Controls).
*   **Recommended Mitigation:** Technical: Deploy a Privileged Access Management (PAM) system combined with a central Enterprise Password Vault (e.g., CyberArk or LAPS) to eliminate the requirement for hardcoded or plaintext administrative credentials.

---

## Pattern Assessment
The systemic weakness that makes insider threats uniquely dangerous at MedDefense is our fundamental inability to audit, trace, and validate internal user behavior, which stems from a historical security architecture focused entirely on perimeter defense. This structural exposure is directly evidenced by the widespread use of shared clinical credentials across the Radiology department (GAP-011) and the total lack of automated user offboarding procedures for departing workforce members (GAP-003). Because multiple users leverage identical accounts and stale contractor profiles remain active for weeks in a flat network environment, MedDefense lacks forensic accountability. If an insider decides to exfiltrate patient records or deploy shadow infrastructure, our lack of log centralization (SIEM) and missing user behavior tracking ensure that malicious actions will blend seamlessly into standard operational traffic, remaining completely undetected until after data public disclosure occurs.
