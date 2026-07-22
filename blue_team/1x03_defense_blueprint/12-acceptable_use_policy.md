# Acceptable Use Policy (AUP)

**Document Control:**
* **Document Title:** MedDefense Acceptable Use Policy
* **Version:** 1.0
* **Effective Date:** October 1, 2026
* **Approved By:** Chief Executive Officer & Board of Directors
* **Applies To:** All MedDefense employees, clinical staff, contractors, vendors, and temporary personnel.

---

## 1. Purpose and Scope

### 1.1 Purpose
The purpose of this Acceptable Use Policy (AUP) is to safeguard MedDefense Health Systems' IT infrastructure, electronic protected health information (ePHI), financial systems, and clinical operations from unauthorized access, loss, or security threats[cite: 3].

### 1.2 Scope
This policy applies to all personnel who access MedDefense systems, devices, or data[cite: 3]. It covers all hardware (workstations, servers, medical devices, mobile devices), networks (wired, wireless, remote VPN), databases, cloud services, and communication systems across all MedDefense hospital sites and remote clinical facilities[cite: 3, 4].

---

## 2. Acceptable Use of Systems

Employees and authorized users are permitted to access and use MedDefense information systems for authorized clinical, administrative, and operational duties[cite: 3].
* **Clinical Operations:** Accessing patient records via the EHR system strictly on a "need-to-know" basis for direct patient care[cite: 3].
* **Incidental Personal Use:** Minimal, non-disruptive personal use (e.g., checking personal email during breaks) is permitted on non-clinical network zones, provided it does not violate security rules, consume excessive bandwidth, or interfere with work responsibilities[cite: 3].
* **System Resource Integrity:** Systems must be used responsibly to ensure continuous availability for emergency care workflows[cite: 3].

---

## 3. Prohibited Activities

To mitigate identified operational and compliance risks, the following activities are strictly forbidden on all MedDefense assets and networks[cite: 3]:

### 3.1 Network & System Violations
* Bypassing, disabling, or tampering with security controls, firewalls, network segmentation rules, or endpoint protection (EDR) agents[cite: 3].
* Connecting unauthorized network devices, access points, or consumer-grade hardware to any MedDefense network[cite: 3].
* Running port scanners, vulnerability tools, or unauthorized administrative utilities without explicit authorization from the Security Team[cite: 3].

### 3.2 Account & Credential Abuse
* Sharing user accounts, passwords, PINs, or Multi-Factor Authentication (MFA) approval prompts with any other individual[cite: 3].
* Leaving workstations unlocked and unattended in public or clinical patient-facing areas[cite: 3].
* Using MedDefense login credentials or work email addresses for non-work personal online accounts[cite: 3].

### 3.3 Unauthorized Software & Unapproved Services (Shadow IT)
* Downloading, installing, or executing unauthorized third-party software, browser extensions, or executable files[cite: 3].
* Storing, uploading, or processing patient ePHI or internal financial data on unapproved third-party cloud storage or file-sharing platforms[cite: 3].

---

## 4. Personal Devices and Removable Media

### 4.1 Removable Storage (USB Drives & External Disks)
* **Strict Restriction:** Inserting personal USB flash drives, external hard drives, or unauthorized media into MedDefense workstations or servers is prohibited[cite: 3].
* **Approved Media:** Only encrypted, IT-issued USB drives with Endpoint Loss Prevention (DLP) agents enabled may be used for authorized business transfers[cite: 3].

### 4.2 Bring Your Own Device (BYOD) & Personal Mobile Phones
* Personal smartphones, tablets, or personal laptops are forbidden from connecting to the secure internal network (`10.10.0.0/16`) or clinical subnets[cite: 3].
* Personal devices may only connect to the isolated **Guest Wi-Fi Network**[cite: 3].
* Storing, photographing, or transmitting patient ePHI on personal mobile phones or unencrypted personal devices is strictly prohibited under HIPAA regulations[cite: 3].

---

## 5. Password and Authentication Requirements

To support the MedDefense Identity & Access Control framework, all users must adhere to the following credential standards[cite: 3]:

### 5.1 Multi-Factor Authentication (MFA)
* MFA is mandatory for all remote access (VPN), webmail, cloud applications, and administrative logins[cite: 3].
* Users must approve MFA requests only when actively initiating a login session. Approving unsolicited push notifications ("MFA fatigue") is a major security policy violation[cite: 3].

### 5.2 Password Standards
* Passwords must be a minimum of **14 characters** in length, incorporating a combination of uppercase letters, lowercase letters, numbers, and symbols[cite: 3].
* Passwords must not contain dictionary words, common healthcare terms, or personal identifiers[cite: 3].
* Shared or default passwords on systems and medical equipment must be changed immediately upon installation[cite: 3].

---

## 6. Data Handling and Classification

All data generated, processed, or stored within MedDefense is categorized into three classification tiers[cite: 3]:

| Classification Tier | Data Types | Handling & Storage Requirements |
| :--- | :--- | :--- |
| **Confidential / ePHI** | Patient medical records, lab results, SSNs, financial/billing databases[cite: 3]. | Must be stored on encrypted server storage (`ehr-db-01`)[cite: 3]. Transmission requires TLS encryption[cite: 3]. Must NEVER be stored on local C: drives or unencrypted media[cite: 3]. |
| **Internal Restricted** | Operational budgets, internal policies, vendor contracts, IT system diagrams[cite: 3, 4]. | Access restricted to authorized employees on a need-to-know basis[cite: 3]. May not be distributed externally without manager approval[cite: 3]. |
| **Public** | Marketing materials, public doctor directories, official news releases[cite: 3]. | Approved for public distribution[cite: 3]. No access controls required[cite: 3]. |

---

## 7. Monitoring, Enforcement, and Compliance

### 7.1 System Monitoring
* MedDefense monitors and logs system activity, network traffic, application usage, and file access across all endpoints and networks to ensure compliance and detect threat activity[cite: 3].
* Users have **no expectation of privacy** when using MedDefense systems, devices, or networks[cite: 3].

### 7.2 Disciplinary Actions
Violations of this Acceptable Use Policy will be investigated promptly by the Security Team and IT Director[cite: 3]. Depending on the severity and intentionality of the infraction, violations may result in:
1. First Offense (Non-intentional/minor): Mandatory retraining and formal written warning[cite: 3].
2. Second Offense or Serious Negligence: Temporary account suspension, review by Department Head, and formal disciplinary notice in HR file[cite: 3].
3. Severe / Intentional Infraction (Data Theft, Deliberate Misconduct): Immediate termination of employment, revocation of clinical privileges, and potential referral to law enforcement or legal authorities[cite: 3].

---

## 8. Employee Acknowledgment and Commitment

*I acknowledge that I have read, understood, and agree to comply with the MedDefense Acceptable Use Policy (AUP). I understand that compliance with this policy is a condition of my employment or professional association with MedDefense Health Systems. I acknowledge that failure to comply with these rules may result in disciplinary action up to and including termination.*

\
**Employee Name (Printed):** _______________________________________

**Employee Signature:** _____________________________________________

**Department:** ____________________________________________________

**Date:** ______________________
