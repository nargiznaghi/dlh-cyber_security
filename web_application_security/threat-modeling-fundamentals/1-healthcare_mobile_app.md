# Threat Modeling Report: Healthcare Mobile App

> **System/Asset:** Healthcare Mobile Application
> **Date:** June 26, 2026  
> **Version:** 1.0

---

## 1. Critical Asset Identification & CIA Triad Analysis

### Most Critical Asset: Electronic Protected Health Information (ePHI)
Within this system, **ePHI** (which encompasses medical records, diagnostic history, patient-provider messages, and prescription refill data) represents the most critical asset. 

Under regulatory frameworks such as **HIPAA**, the protection of this data is mandatory. Its criticality is best understood through the lens of the **CIA Triad**:

* **Confidentiality (High/Critical Impact):** Medical records contain highly sensitive personal and clinical history. Unauthorized disclosure can lead to severe privacy violations, identity theft, financial fraud, and catastrophic regulatory fines for the organization.
* **Integrity (Critical Impact):** If an attacker alters ePHI (e.g., modifying allergy listings, blood types, dosage amounts, or laboratory results), a physician could make an incorrect clinical decision. This directly threatens patient safety and can lead to life-threatening scenarios.
* **Availability (High Impact):** Healthcare providers must have real-time access to patient records, especially during emergencies or prescription routing. If data becomes inaccessible due to a ransomware or Denial of Service (DoS) attack, critical patient care can be dangerously delayed.

---

## 2. STRIDE Threat Analysis: "Message Healthcare Providers" Feature

The messaging component is a prime vector for social engineering, data interception, and session hijacking. Below are four distinct STRIDE threats identified for this specific workflow:

### Threat 1: Spoofing (Attacker Impersonates a Healthcare Provider)
* **Description / Attack Scenario:** An attacker manages to compromise a weak provider credential or session token. They log into the system pretending to be a licensed doctor and send fraudulent clinical advice or malicious links to a vulnerable patient.
* **Potential Impact:** Patient takes incorrect medication based on fake advice, physical harm, and complete breakdown of trust in the platform.

### Threat 2: Tampering (Message Modification in Transit)
* **Description / Attack Scenario:** An adversary performs a Man-in-the-Middle (MitM) attack on an insecure network (e.g., public Wi-Fi) used by the patient. They intercept the message payload and alter the text—changing a message like *"Take 5mg of medication"* to *"Take 50mg of medication"*.
* **Potential Impact:** Immediate physiological risk to the patient, medical malpractice liabilities, and data integrity corruption.

### Threat 3: Repudiation (Provider Denies Sending a Message / Issuing a Prescription)
* **Description / Attack Scenario:** A healthcare provider sends a message containing an incorrect prescription refill instructions or diagnosis. Following a subsequent medical complication, the provider claims they never authored or sent that specific message, exploiting a system flaw where chat logs lack cryptographic signing or immutability.
* **Potential Impact:** Legal and compliance deadlock, inability to perform forensic audits, and failure to establish accountability.

### Threat 4: Information Disclosure (Eavesdropping on Patient-Provider Chat Logs)
* **Description / Attack Scenario:** Due to inadequate backend authorization checks (e.g., Insecure Direct Object Reference - IDOR), an unauthenticated external user guesses or enumerates the API message IDs and downloads raw message histories between other patients and doctors.
* **Potential Impact:** Massive data breach involving ePHI, strict HIPAA penalty enforcement, and irreversible reputational damage.

---

## 3. Prioritized Security Controls for Patient Data Protection

To mitigate the threats identified above and safeguard ePHI, the following five architectural security controls must be prioritized and enforced in order of critical dependence:

### 1. Multi-Factor Authentication (MFA) & Secure Session Management
* **Type:** Preventive
* **Why it is Priority 1:** Identity is the perimeter. Before data can be encrypted or authorized, we must guarantee the user is who they claim to be. Enforcing MFA (e.g., TOTP or WebAuthn/Biometrics) for patients and providers prevents account takeover attacks resulting from credential stuffing or phishing. Sessions must utilize short-lived JWTs stored securely on mobile devices (e.g., iOS Keychain, Android Keystore).

### 2. End-to-End Encryption (E2EE) & Transport Layer Security (TLS 1.3)
* **Type:** Preventive
* **Why it is Priority 2:** Protects data against interception. All data in transit between the mobile client and the REST API must exclusively enforce TLS 1.3 with certificate pinning to prevent MitM attacks. Furthermore, patient-provider messages should ideally be encrypted at the application layer (E2EE) so that even a database breach does not expose the plaintext clinical conversation logs.

### 3. Role-Based Access Control (RBAC) & Attribute-Based Access Control (ABAC)
* **Type:** Preventive
* **Why it is Priority 3:** Once authenticated, users must be strictly confined to their data boundaries (Least Privilege). Providers should only see records of patients explicitly assigned to their care, and patients must only access their own profile data. Enforcing strict backend validation at the REST API level prevents IDOR vulnerabilities and vertical/horizontal privilege escalation.

### 4. Cryptographic Database Encryption (Data-at-Rest Protection)
* **Type:** Preventive / Data Protection
* **Why it is Priority 4:** If the perimeter and network controls fail and an attacker compromises the underlying cloud-hosted storage or structural backups, the data must remain unreadable. Enforcing AES-256 transparent data encryption (TDE) along with column-level encryption for highly sensitive items (e.g., SSN, medical notes) ensures robust asset protection.

### 5. Immutable Cryptographic Audit Logging & Monitoring
* **Type:** Detective / Administrative
* **Why it is Priority 5:** Compliance and forensics depend entirely on visibility. Every create, read, update, or delete (CRUD) operation involving ePHI must generate an unalterable log entry containing timestamp, User ID, and action performed. These logs must be streamed in real-time to a secured SIEM (Security Information and Event Management) system to detect anomalous access patterns and ensure non-repudiation.

---

## 4. Threat Model Architecture Diagram

```mermaid
flowchart TD
    subgraph Mobile Client Zone (Untrusted)
        P[Patient App: iOS/Android]
        D[Provider App: iOS/Android]
    end

    subgraph Corporate & Cloud Zone (Trusted Zone)
        API[REST API Backend]
        DB[(Cloud-Hosted Database: ePHI)]
        HOS[Hospital Internal Systems]
    end

    P -->|1. TLS 1.3 + MFA| API
    D -->|1. TLS 1.3 + MFA| API
    API -->|2. Parameterized / Encr.| DB
    API -->|3. HL7 / FHIR Secure Sync| HOS
    
    style DB fill:#fee2e2,stroke:#ef4444,stroke-width:2px
