# Data Classification and Handling Policy

| Metadata Field | Value |
| :--- | :--- |
| **Document ID** | POL-DATA-2026-004 |
| **Version** | 1.0 |
| **Effective Date** | June 26, 2026 |
| **Policy Owner** | Chief Information Security Officer (CISO) & Data Protection Officer (DPO) |
| **Approved By** | HealthPlus Clinical Executive Board & Legal Counsel |
| **Regulatory Frameworks** | HIPAA Security & Privacy Rules, GDPR Art. 4, NIST SP 800-88 |
| **Classification** | Internal Use Only |

### Revision History
| Version | Date | Author | Description of Change |
| :--- | :---: | :--- | :--- |
| 1.0 | June 26, 2026 | Information Governance Group | Initial release securing electronic Protected Health Information (ePHI) and employee PII. |

---

### 1. Purpose & Scope
The purpose of this policy is to establish a rigorous operational framework for identifying, classifying, and safeguarding data assets managed by HealthPlus Medical Group. Improper exposure of clinical datasets triggers severe statutory fines (HIPAA/GDPR) and breaks patient confidentiality. 

This policy governs all life-cycle phases (creation, storage, transmission, and destruction) of data residing on HealthPlus systems, vendor-managed cloud storage repositories, localized medical devices, and physical print records across all clinics.

---

### 2. Data Classification Levels

HealthPlus Medical Group programmatically segments all institutional data into four explicit tiers:

* **LEVEL 4: RESTRICTED**
    * *Description:* Highly sensitive regulatory data. Unauthorized exposure causes severe financial, legal, or catastrophic reputational damage to the organization or directly violates patient biometric privacy.
    * *Examples:* Patient Electronic Health Records (PHI/ePHI), clinical diagnoses, surgical histories, active administrative root credentials, cryptographic signing keys.
* **LEVEL 3: CONFIDENTIAL**
    * *Description:* Sensitive operational or personal data that could cause significant financial loss, legal penalties, or targeted social engineering if disclosed.
    * *Examples:* Employee personally identifiable information (PII) (e.g., SSNs, home addresses), corporate financial ledgers, active payroll metrics, unreleased biomedical research data.
* **LEVEL 2: INTERNAL**
    * *Description:* Non-public data intended strictly for internal workforce operations. Disclosure causes minimal impact but reduces organizational operational efficiency.
    * *Examples:* Internal clinical memos, corporate organization charts, intranet training materials, facilities maintenance schedules.
* **LEVEL 1: PUBLIC**
    * *Description:* Information explicitly vetted and approved for unrestricted public consumption. Dissemination poses zero risk to institutional stability.
    * *Examples:* Marketing brochures, public website copy, health education blog posts, open job vacancies.

---

### 3. Handling Requirements Matrix

The following operational directives are legally binding across all systems engineering and workforce behaviors:

| Requirement Parameter | Level 1: PUBLIC | Level 2: INTERNAL | Level 3: CONFIDENTIAL | Level 4: RESTRICTED |
| :--- | :---: | :---: | :---: | :---: |
| **Visual Labeling** | No | Optional | **Mandatory** | **Mandatory** |
| **Encryption at Rest** | No | Optional | **Yes (AES-256)** | **Yes (FIPS 140-3 validated)** |
| **Encryption in Transit** | No | **Yes (TLS 1.2+)** | **Yes (TLS 1.3 / HTTPS)** | **Yes (End-to-End Encrypted)** |
| **Access Control Mechanism** | Public Read | Role-Based (RBAC) | Attribute-Based (ABAC) | Strict Least Privilege (MFA + IAM) |

---

### 4. Lifecycles Handling Standards

#### 4.1. Labeling Standards
* **Electronic Assets:** Restricted and Confidential digital files (Word, PDF, Excel) must include a persistent header and footer text tag: `[CLASSIFICATION: RESTRICTED]` or `[CLASSIFICATION: CONFIDENTIAL]` in bold red or black caps. File naming schemas must append the tier tag as a suffix (e.g., `Patient_Record_9021_RESTRICTED.pdf`).
* **Physical Prints:** Paper charts containing PHI must be stored inside manila folders stamped with the **RESTRICTED** warning seal on the front cover face.

#### 4.2. Storage Boundaries
* **Approved Locations:** Level 3 and Level 4 data must only reside within the central Epic EHR system, approved enterprise database layers, or the dedicated Secure-Cloud-Tenant enforcing continuous logging.
* **Prohibited Locations:** Storing Restricted or Confidential information on local workstation desktops, personal BYOD unmanaged local storage, unencrypted USB thumb drives, or consumer-grade cloud apps (e.g., personal Google Drive, Dropbox) is strictly illegal.

#### 4.3. Transmission Rules
* **Email Protocols:** Level 4 (RESTRICTED) records must never be sent via standard plaintext email. If communication with external medical entities is required, files must be routed via the Secure Clinical Portal or sent through an end-to-end encrypted email link requiring identity verification.
* **File Transfers:** Internal distribution must utilize encrypted HTTPS/SFTP pipelines with automated log auditing enabled.

#### 4.4. Disposal & Media Sanitization
* **Physical Waste:** Paper records containing Internal, Confidential, or Restricted notations must be dropped directly into locked cross-cut corporate shredding bins. 
* **Digital Media:** Decommissioned storage arrays, hard drives, or medical sensors containing Level 3 or Level 4 data must be sanitized following **NIST SP 800-88 Rev. 1 Guidelines** utilizing verified cryptographic erasure or physical degaussing and shredding via authorized vendors.

#### 4.5. Access Control Reviews
* User access privileges targeting Restricted and Confidential directories must be reviewed by Clinical Department Leads every **90 days**. Any identified access creep or legacy rights must be revoked instantly.

---

### 5. Quick Reference Guide (Workforce Checklist)

```text
================================================================================
               HEALTHPLUS MEDICAL GROUP - DATA HANDLING QUICK GUIDE
================================================================================
WHAT DATA ARE YOU HANDLING? FOLLOW THE GOLDEN RULES BELOW:

[1. PATIENT PHI / CLINICAL DATA] -> LEVEL 4: RESTRICTED
    * STORAGE: Epic EHR system only. NEVER save to your local desktop/C: drive.
    * TRANSMISSION: Use the Secure Patient Portal. NEVER email patient info.
    * LABELING: File names must end with "_RESTRICTED".
    * DISPOSAL: Throw physical prints into the locked gray shredding bins.

[2. EMPLOYEE SSN / FINANCIALS]  -> LEVEL 3: CONFIDENTIAL
    * STORAGE: Enterprise HR Portal / Secured Accounting Network Drive.
    * TRANSMISSION: Encrypted internal links only. Verify recipient identity.
    * LABELING: Add "CONFIDENTIAL" to document headers and footers.

[3. INTERNAL CLINIC MEMOS]      -> LEVEL 2: INTERNAL
    * STORAGE: Shared corporate Intranet / Office 365 Teams folders.
    * TRANSMISSION: Standard work email is acceptable for internal staff only.

[4. PUBLIC MARKETING COY]       -> LEVEL 1: PUBLIC
    * STORAGE: Public Web Server / Public Sharepoint Repository.
    * TRANSMISSION: No restriction. Approved for external public release.

--------------------------------------------------------------------------------
SUSPECT A DATA LEAK OR MISSING LAPTOP? CONTACT SECURITY IMMEDIATELY:
Email: security-alert@healthplus.org | Emergency Extension: 5555
================================================================================References
NIST Special Publication 800-60: Guide for Mapping Types of Information and Information Systems to Security Categories
Health Insurance Portability and Accountability Act (HIPAA) Security Rule (45 CFR Part 160 and Part 164)
NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization
