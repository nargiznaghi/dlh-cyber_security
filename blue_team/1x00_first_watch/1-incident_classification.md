# Incident Classification Report: MedDefense Health Systems

This report classifies the security events recorded over the past 6 months using the CIA Triad (Confidentiality, Integrity, and Availability) framework to evaluate their operational and security impact.

---

## Incident Classification Table

| Incident | Date | Primary Pillar | Primary Justification | Secondary Pillar | Secondary Justification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Incident A** | Jan 15 | **Availability** | The billing server encryption completely denied the finance team access to process insurance claims for four days. | **Integrity** | The server's data was modified without authorization via the ransomware's encryption payload. |
| **Incident B** | Feb 2 | **Confidentiality** | Broken access control allowed unauthorized patients to view private lab results belonging to other individuals. | **None** | No data was modified or deleted, and the portal service itself remained accessible. |
| **Incident C** | Mar 18 | **Integrity** | A buggy database update script unauthorizedly modified and corrupted critical medication dosage values across the system. | **Availability** | Accurate and trusted dosage data was unavailable to clinical staff across all three sites for six hours. |
| **Incident D** | Apr 5 | **Integrity** | Unauthorized actors modified the public website's integrity by replacing the legitimate homepage with a political message. | **Availability** | The authorized, authentic website content was inaccessible to users for a duration of two hours. |
| **Incident E** | May 22 | **Availability** | A failed database migration and lack of tested rollback procedures caused a 9-hour outage, rendering the EHR system inaccessible. | **None** | The incident was an operational failure that did not involve unauthorized data access or data corruption. |
| **Incident F** | Jun 10 | **Confidentiality** | An unmanaged personal device gained unauthorized access to the internal network segment, exposing sensitive HR file shares for three weeks. | **Integrity** | The logical boundaries and control policies of the corporate network were compromised by the connection of an unauthorized rogue asset. |

---

## Analytical Insights

### 1. Multi-Pillar Impacts
Incidents are rarely isolated to a single failure point. As seen in **Incident A, C, and D**, an attack that alters data (Integrity) frequently triggers a downstream operational denial of service (Availability). 

### 2. Operational Vulnerabilities
The reliance on paper records during the EHR outage (**Incident E**) and the use of printed references during the pharmacy system corruption (**Incident C**) highlight a severe lack of formal Business Continuity (BC) and Disaster Recovery (DR) planning, validating the gaps noted in Marcus's original security observations.
