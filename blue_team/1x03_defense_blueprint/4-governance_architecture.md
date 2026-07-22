# 4. The Governance Architecture

## Part 1 - RACI Matrix

The following RACI matrix defines responsibility (**R**esponsible), accountability (**A**ccountable), consultation (**C**onsulted), and information flow (**I**nformed) across critical security activities at MedDefense:

| Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads (e.g., Dr. Patel) | Security Analyst (You) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Security budget approval** | **A** | **R** | C | I | I |
| **Vulnerability remediation** | I | **A** | **R** | I | **R** |
| **Incident response execution** | I | **A** | C | I | **R** |
| **Security policy approval** | **A** | **R** | C | C | I |
| **Risk acceptance decisions** | **A** | **R** | C | C | I |
| **Security awareness training** | I | **A** | I | C | **R** |
| **Vendor risk assessment** | I | **A** | C | C | **R** |
| **Audit coordination** | I | **A** | C | I | **R** |

*Definitions: **R** = Responsible (does the work), **A** = Accountable (approves/owns the final outcome), **C** = Consulted (provides input), **I** = Informed (kept updated).*

---

## Part 2 - Role Definitions

MedDefense assigns data governance roles according to industry standard terminology to eliminate ambiguity regarding data ownership, protection, and operational handling:

### 1. Data Controller: MedDefense Board of Directors / Executive Leadership
* **Definition:** The legal entity or governing body that determines the overall purposes and legal/regulatory compliance means of processing personal and health data (ePHI).
* **Assignment Justification:** As a healthcare organization, MedDefense is legally accountable under HIPAA and relevant privacy regulations for how patient health data is collected, stored, and protected across the institution.

### 2. Data Owner: Department Heads (e.g., Dr. Patel in Cardiology)
* **Definition:** The business or clinical manager responsible for specific datasets, determining data classification, defining access permissions, and establishing data retention requirements based on clinical needs.
* **Assignment Justification:** Department heads understand the business/clinical context of their data (e.g., patient records in Cardiology). They decide *who* should have access to perform clinical duties, but must operate within overall organizational security policies rather than creating independent rules.

### 3. Data Custodian / Steward: IT Director (Sarah) & IT Systems Team
* **Definition:** The operational role responsible for technical safeguards, maintaining systems housing data, implementing access control rules defined by Data Owners, managing backups, and ensuring database availability/integrity.
* **Assignment Justification:** The IT department manages the infrastructure, servers, and databases where data resides. Sarah's team enforces the technical controls (e.g., access rights, database encryption, server maintenance) required by Data Owners and the CISO team.

### 4. Data Processor: Third-Party Healthcare Vendors & Cloud Service Providers
* **Definition:** External organizations, contractors, or SaaS platforms that process patient data or manage electronic health records (EHR) on behalf of MedDefense.
* **Assignment Justification:** Vendor platforms hosting ePHI or third-party diagnostics process data under strict Business Associate Agreements (BAAs) and must adhere to MedDefense's security standards.

---

## Part 3 - The CISO Question

### Consequences of a Vacant CISO Position
Operating with a vacant CISO position leaves MedDefense vulnerable to strategic drift, unmanaged executive risks, and regulatory compliance gaps. Without an empowered executive dedicated solely to cybersecurity governance, security decisions risk being subordinated to operational IT priorities or departmental convenience. This results in unclear accountability, uncoordinated incident response, delayed risk treatment, and friction between security, IT, and clinical leadership.

### Strategic Recommendation: Outsource via Virtual CISO (vCISO)
MedDefense should retain a **Virtual CISO (vCISO)** in the near term while empowering James (Deputy CISO) to handle internal execution. Hiring a full-time, seasoned CISO in healthcare commands significant executive compensation (typically exceeding $250k–$300k+ annually), which exceeds MedDefense's current budget and headcount constraints (1 Analyst, 1 Deputy). A vCISO model provides executive-level governance, strategic board engagement, policy approval, and audit readiness at a fraction of the cost. This arrangement allows the small 2-person security team to execute tactical protections (CIS Controls IG1) while receiving senior-level guidance without overextending the operational budget.
