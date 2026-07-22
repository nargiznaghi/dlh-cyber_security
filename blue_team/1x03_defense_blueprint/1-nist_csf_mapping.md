# 1. NIST CSF 2.0 Current & Target Profile (MedDefense)

## Function: GOVERN (GV)
* **Current Level:** Partial
* **Evidence:** Security leadership exists with a newly appointed Deputy CISO and 1 Security Analyst, but formal cybersecurity strategies, governance policies, supply chain risk management, and formal security oversight are largely absent or unwritten.
* **Key Gaps:** Lack of approved cybersecurity policies (e.g., Acceptable Use Policy, formal Incident Response Policy) and absence of a structured risk governance model for executive and board-level reporting.
* **Target Level:** Managed
* **Justification:** Over the next 6 months, MedDefense must establish basic governance by formalizing core policies, defining roles, and establishing risk management expectations so that security operations are repeatable, documented, and aligned with hospital management.

---

## Function: IDENTIFY (ID)
* **Current Level:** Partial
* **Evidence:** Prior to Project 1x00, MedDefense lacked a comprehensive asset inventory. While Project 1x00 successfully mapped hardware, software, and critical network assets, and Project 1x02 identified key vulnerabilities, the overall risk assessment and mapping process remains informal and was not historically maintained by the organization.
* **Key Gaps:** Asset and vulnerability tracking are not yet integrated into an ongoing, automated process; dynamic data flows and supply chain risks remain unmapped.
* **Target Level:** Managed
* **Justification:** MedDefense needs to institutionalize the asset and risk management processes established in Projects 1x00–1x02, ensuring that asset tracking, threat modeling, and risk registers are routinely updated rather than treated as one-off exercises.

---

## Function: PROTECT (PR)
* **Current Level:** Partial
* **Evidence:** Vulnerability scanning in Project 1x02 revealed unpatched legacy systems, missing security baselines, inconsistent endpoint protection, and a lack of proper network segmentation across clinical and administrative environments. Identity controls like MFA are inconsistently applied.
* **Key Gaps:** Unpatched high-severity vulnerabilities, unhardened systems, and inadequate network segmentation separating critical medical/EHR infrastructure from standard user traffic.
* **Target Level:** Managed
* **Justification:** Given the high risk to patient care and regulatory liability (HIPAA), MedDefense must deploy fundamental technical safeguards, enforce MFA, establish hardening baselines, and implement network segmentation within 6 months.

---

## Function: DETECT (DE)
* **Current Level:** Not Implemented
* **Evidence:** Notes from internal operational reviews explicitly highlight zero continuous monitoring capability. MedDefense lacks centralized logging (SIEM), automated alert correlation, network intrusion detection, or 24/7 monitoring capabilities.
* **Key Gaps:** Complete absence of centralized logging and real-time security detection mechanisms, leaving the organization blind to active breaches or malicious activity.
* **Target Level:** Partial
* **Justification:** Achieving "Managed" status in 6 months is unrealistic for a 2-person team without an external Managed Detection and Response (MDR) or SOC service. Aiming for "Partial" by deploying centralized syslog, basic endpoint detection, and critical system alerts provides baseline detection capabilities without overwhelming current resources.

---

## Function: RESPOND (RS)
* **Current Level:** Partial
* **Evidence:** While the small security team can perform ad-hoc triage and manual mitigation when alerted to issues, there is no formal, documented Incident Response (IR) plan, no defined containment procedures, and no tested playbook for regulatory/breach notification.
* **Key Gaps:** Lack of a formalized, tested Incident Response Plan with defined roles, escalation pathways, and legal/regulatory notification workflows.
* **Target Level:** Managed
* **Justification:** MedDefense must formalize its Incident Response Plan and establish clear triage/containment playbooks to ensure rapid, compliant, and repeatable response during a ransomware or data breach event.

---

## Function: RECOVER (RC)
* **Current Level:** Partial
* **Evidence:** Basic backup mechanisms exist for operational continuity, but backup integrity is not routinely tested against ransomware scenarios, backups are not strictly isolated (immutable/air-gapped) from production networks, and formal Business Continuity / Disaster Recovery (BC/DR) timelines (RTO/RPO) are not defined.
* **Key Gaps:** Unvalidated backup recovery procedures and lack of isolated/immutable backup architecture to prevent destruction during an attack.
* **Target Level:** Managed
* **Justification:** Healthcare operations require high availability. MedDefense must establish isolated backup storage and perform regular recovery drills to guarantee meeting recovery time objectives (RTO) in the event of system compromise.
