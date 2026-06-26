
# Security Policy Analysis & Policy Rewrite

## Part A: Identify Missing Components

| Missing Component | Why It's Important |
| :--- | :--- |
| **Header Information** (Version, Date, Owner, Classification) | Establishes document authority, defines who maintains the document, tells users if it is current, and dictates how the document itself should be handled based on its data classification level. |
| **Purpose Statement** | Explains the underlying operational or regulatory reasoning (*Why*) the policy exists, ensuring employee alignment with corporate security goals. |
| **Scope Definition** | Clearly delineates *Who* (employees, contractors, third parties) and *What* (systems, networks, devices) the policy applies to, eliminating ambiguity regarding coverage. |
| **Specific, Measurable Policy Statements** | Replaces vague recommendations with quantifiable technical baselines (e.g., character length, complexity) so that technical teams can implement controls and auditors can measure compliance. |
| **Roles and Responsibilities** | Explicitly defines who executes controls, who manages the infrastructure, and who oversees compliance, preventing operational gaps and finger-pointing. |
| **Enforcement Section** | Outlines the exact consequences of non-compliance (disciplinary actions), giving the policy legal weight and notifying employees of accountability. |
| **Definitions** | Standardizes technical and organizational terms (e.g., "ePHI", "MFA", "Privileged Account") to ensure non-technical staff and legal teams interpret the mandates identically. |
| **Related Documents** | References adjacent procedures, guidelines, or architectural standards that provide step-by-step instructions on how to meet the policy's mandates. |
| **Review / Revision History Table** | Logs historical changes, approvals, and review milestones, which serves as critical evidence of continuous maintenance during external security audits (e.g., ISO 27001, SOC 2). |

---

## Part B: Identify Weaknesses

| Weakness (Quote) | Problem | Impact |
| :--- | :--- | :--- |
| `"should use"` | Uses permissive language ("should") instead of mandatory terms ("must" or "shall"). | Makes compliance optional rather than compulsory, rendering the policy legally and contractually unenforceable. |
| `"good passwords"` | Highly subjective and completely undefined term. What is "good" to a non-technical employee may be "123456" or their pet's name. | Leads to weak, easily crackable or brute-forced credentials across corporate entry points. |
| `"Don't share them."` | Vague directive that lacks explicit context regarding corporate collaboration or credentials embedded in configuration files. | Employees might still share credentials via insecure channels (Slack, email) under the assumption that it is acceptable within immediate teams. |
| `"IT will handle security stuff."` | Extremely vague assignment of duty; "security stuff" does not specify roles, administration, or provisioning. | Creates complete ambiguity regarding ownership, leading to critical unpatched gaps, missing logs, and operational confusion. |
| `"Report problems to someone."` | Fails to identify an escalation pathway, a specific role, an email address, an extension, or an incident response ticketing system. | Security incidents, active data leaks, or phishing compromises will go unreported, or report delivery will be critically delayed. |
| `"Updated: Sometime last year"` | Invalid, un-versioned, and ambiguous date tracking. | The policy loses professional authority, and systems administrators cannot verify if the rules reflect current regulatory requirements. |

---

## Part C: Rewrite the Policy

# Enterprise Password and Credential Policy

* **Doc ID:** POL-SEC-004 | **Version:** 2.0 | **Effective Date:** June 26, 2026
* **Owner:** Chief Information Security Officer (CISO) | **Classification:** Internal Use Only

---

### 1. Purpose & Scope
This policy establishes mandatory technical requirements for passwords and access tokens to protect corporate networks, systems, and data from unauthorized access. It applies to all employees, contractors, third-party vendors, and all corporate-managed endpoints and cloud systems.

### 2. Policy Statements (Technical Controls)
* **Standard Accounts:** Must be a minimum of **14 characters** and include uppercase, lowercase, numbers, and special symbols.
* **Privileged Accounts:** Must be a minimum of **16 characters** and cannot match any of the last 12 passwords used.
* **Service/API Accounts:** Must use a cryptographically secure random string of at least **32 characters**.
* **MFA Mandate:** Multi-Factor Authentication (MFA) is strictly mandatory for all remote, cloud, and email access points. Only hardware tokens (FIDO2) or app-based TOTP push notifications are allowed. SMS is prohibited.
* **Prohibited Actions:** Credentials **shall not** be shared, written down, or reused on external personal websites.

### 3. Roles & Responsibilities
* **CISO:** Authorizes policy updates and reviews compliance exceptions.
* **IT Administrators:** Programmatically enforces the complexity and MFA rules across all identity providers (e.g., Active Directory, Okta).
* **All Personnel:** Responsible for using enterprise password managers (e.g., 1Password) and immediately reporting compromised credentials to `security@company.com`.

### 4. Enforcement
Compliance is mandatory and continuously monitored via automated testing and phishing simulations. Violations will result in disciplinary actions up to revocation of network access, termination of employment, or legal prosecution.
