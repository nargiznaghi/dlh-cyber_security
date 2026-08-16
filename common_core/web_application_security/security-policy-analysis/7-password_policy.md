# Corporate Password Policy & Technical Standards

| Metadata Field | Value |
| :--- | :--- |
| **Document ID** | POL-SEC-2026-PASSWORD |
| **Version** | 1.0 |
| **Effective Date** | June 26, 2026 |
| **Policy Owner** | Chief Information Security Officer (CISO) |
| **Approved By** | Risk Compliance Committee & Board of Directors |
| **Regulatory Frameworks** | PCI-DSS v4.0 (Req 8), SOX, FFIEC Guidelines |
| **Classification** | Internal Use Only |

### Revision History
| Version | Date | Author | Description of Change |
| :--- | :---: | :--- | :--- |
| 1.0 | June 26, 2026 | Information Security Directorate | Initial Release aligned with NIST SP 800-63B and PCI-DSS v4.0 requirements. |

---

## SECTION I: CORPORATE PASSWORD POLICY

### 1. Purpose
The purpose of this policy is to establish secure programmatic baselines for the deployment, structure, lifecycle, and administrative management of identity authenticators across SecureBank Financial Services. As a financial entity processing transactional data, weak credential configuration represents an existential risk to regulatory compliance and customer trust. This policy defines the operational boundaries required to defend bank systems against identity takeover, credential stuffing, and brute-force attacks.

### 2. Scope
This policy governs all active directory instances, identity providers (IdP), and single sign-on (SSO) connectors managing access to SecureBank assets. It applies universally to all internal employees, contractors, external developers, and auditors across the following segregated system environments:
* **Core Banking Systems:** Transaction ledgers, account balances, wire engines.
* **Customer Portal Boundaries:** Public-facing consumer mobile/web applications.
* **Corporate Workspace:** Employee workstations, corporate email, internal networks.
* **Administrative Interfaces:** Root access, network switch configurations, cloud IAM roles.
* **Development Environments:** CI/CD pipelines, staging environments, sandboxed code repositories.

### 3. Policy Statements

#### 3.1. Authentication Lifecycles & Forced Rotations
* **Standard Accounts:** In alignment with **NIST SP 800-63B**, standard user accounts shall not be subjected to periodic calendar-based password expiration rules unless there is an active indicator of compromise (IoC) or account disclosure. This strategy reduces the predictable transformation patterns (e.g., Spring2025! -> Summer2025!) commonly exploited by adversaries.
* **PCI-DSS Enforced Accounts:** Systems strictly bound to the **PCI-DSS v4.0 Cardholder Data Environment (CDE)** footprint must enforce password rotation every 90 days unless utilizing continuous phishing-resistant multi-factor authentication (MFA) parameters.

#### 3.2. Multi-Factor Authentication (MFA) Mandate
Multi-Factor Authentication is an absolute requirement and must be programmatically enforced for all access vectors hitting SecureBank assets.
* **Approved Methods:** Authentication pathways must prioritize hardware-backed tokens (FIDO2/WebAuthn) or corporate-managed cryptographic applications generating Time-Based One-Time Passwords (TOTP).
* **Prohibited Methods:** SMS-based text messaging, voice-based token distribution, and unencrypted email OTP transmissions are strictly prohibited for all employee and administrative operations due to vulnerability to SIM-swapping and interception.

#### 3.3. Credential Storage and Management
* **Hashing Requirements:** Under no circumstances shall passwords be stored in plaintext or reversible encryption formats within any system database. All authenticators must be cryptographically hashed using memory-hard key derivation functions such as **Argon2id** or **bcrypt** incorporating a cryptographically unique random salt value per row.
* **Password Managers:** Personnel must utilize the bank-provisioned, centralized Enterprise Password Manager (EPM) tool to generate, audit, and store credentials. The utilization of personal unmanaged applications or unencrypted browser credential caches is strictly forbidden.

#### 3.4. Privileged Account Management (PAM)
* **Enhanced Access Boundaries:** Accounts possessing elevated structural rights (e.g., Domain Admins, Core Database Root, Cloud Tenant Global Admins) must be isolated within a dedicated **Privileged Account Management (PAM)** vaulting environment.
* **Just-In-Time (JIT) Provisioning:** Administrative permissions must be generated dynamically on a Just-In-Time basis. Administrative credentials must rotate automatically immediately following the termination of the approved administrative maintenance window.

---

## SECTION II: TECHNICAL STANDARDS MATRIX

This matrix serves as the operational baseline that systems administrators and database engineers must programmatically configure within Identity Providers (IdP), Active Directory, and custom application database schemas.

| Target System Environment | Min Length | Complexity Phrasing Requirements | Programmatic Lockout Parameters | Idle Timeout Window | Allowed MFA Methods |
| :--- | :---: | :--- | :--- | :---: | :--- |
| **Core Banking System** | **16** | Upper, lower, numbers, symbols + dictionary block. | 3 failed attempts = Hard freeze. Human intervention required. | 5 Minutes | FIDO2 Hardware Key / App-Push Only |
| **Administrative Systems** | **16** | Upper, lower, numbers, symbols + dictionary block. | 3 failed attempts = Hard freeze. SIEM alert generation. | 5 Minutes | FIDO2 Hardware Key Only |
| **Development/CI-CD** | **14** | Upper, lower, numbers, symbols. | 5 failed attempts = 30-minute lock. | 15 Minutes | App-Push / TOTP Token |
| **Employee Workstations** | **14** | Upper, lower, numbers, symbols. | 5 failed attempts = 15-minute lock. | 10 Minutes | Biometrics / App-Push |
| **Customer Portal** | **12** | Upper, lower, numbers. No common names allowed. | 5 failed attempts = Soft lock + email warning. | 15 Minutes | App-Push / SMS *(Allowed for consumers only)* |

### Technical Controls Implementation Rules
1. **Dictionary Block Constraints:** The Identity Provider must actively cross-reference any proposed credential configuration change against a real-time global list of known breached passwords (e.g., HaveIBeenPwned API or localized threat matrix) and block match strings containing terms like `SecureBank`, `Banking`, `Password`, or current seasonal calendar markers.
2. **Concurrent Session Control:** Systems must terminate active connections if simultaneous logins are identified from conflicting geographical locations (Impossible Travel Anomalies).

---

## SECTION III: GOVERNANCE & ENFORCEMENT

### 4. Roles & Responsibilities
* **CISO Office:** Drives the governance model, manages annual framework alignment checks, and issues formal risk acceptances for legacy infrastructure constraints.
* **Systems Administration Teams:** Responsible for verifying that all active identity schemas match the length, complexity, and timeout thresholds detailed in Section II.
* **Internal Audit Teams:** Tasked with executing quarterly unannounced verification scripts to ensure that credential parameters have not drifted from the baseline policy.

### 5. Enforcement and Consequences
Adherence to this policy is absolute. Non-compliance compromises SecureBank's FFIEC standing and operational banking license. Individuals deliberately disabling, bypassing, or compromising these technical boundaries will face immediate disciplinary workflows managed by Human Resources:
* Formal written warning and immediate programmatic reset of privileges.
* Suspension or structural contract termination.
* Reporting to federal regulatory and financial oversight agencies for compliance violation auditing tracking.

---
## References
* NIST Special Publication 800-63B: Digital Identity Guidelines (Authentication and Lifecycle Management)
* PCI-DSS v4.0 Requirement 8: Identify and Authenticate Users
* OWASP Authentication Cheat Sheet Matrix
