# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** November 5, 2026  
**Report date:** November 6, 2026  
**Facilitator:** Nargiz Naghiyeva  
**Participants:** James Chen (SOC Lead / IR Lead), Sarah Park (Legal Counsel), Marcus Webb (IT Operations), Helena Reyes (Communications / PR), Robert Kim (Compliance), Dr. Patricia Morales (Executive Sponsor), Clinical Director representative  
**Classification:** Internal — Incident Response & Security Operations Use Only  

---

## Executive summary

On November 5, 2026, MedDefense conducted a tabletop exercise simulating a supply chain compromise of Nexus Patient Scheduling (Nexus Health Technologies, Inc.), a SaaS platform handling approximately 3,500 patient interactions weekly across Main Campus, West Campus, and North Site. The scenario tested organizational capabilities across technical detection, vendor escalation, business continuity isolation decisions, HIPAA regulatory compliance, FHIR data integrity, media relations, and executive crisis management.

While technical containment and initial BAA outreach were executed swiftly, the exercise exposed two significant P1 operational gaps: a lack of pre-defined decision authority for emergency isolation of critical vendor integrations during active clinical care, and the absence of a structured data integrity validation protocol for inbound HL7 FHIR scheduling feeds. Addressing these gaps is essential to ensure patient safety and maintain HIPAA regulatory compliance during third-party security events. The single most important recommended action is to establish a joint IT/Clinical Emergency Isolation SOP that defines clear decision rights and offline fallback workflows for vendor system disconnects.

---

## Findings table

| ID | Inject | Capability | Gap | Severity | Recommended Action | Owner | Deadline | Validation |
|---|---|---|---|---|---|---|---|---|
| F-001 | INJ-02 | CAP-03 | No pre-defined joint authority framework for immediate emergency isolation of a business-critical clinical SaaS integration. | P1 | Publish a Vendor System Emergency Isolation SOP establishing clear decision rights between IT, IR Lead, and Clinical Operations. | IT Director | 21 days | Playbook sign-off + executive tabletop re-test |
| F-002 | INJ-03 | CAP-06 | No formal data integrity verification checklist for inbound HL7 FHIR records following evidence of vendor service principal compromise. | P1 | Develop an EHR Ingest Data Integrity Checklist and manual reconciliation protocol for patient scheduling updates. | Lead DFIR Analyst | 30 days | SOP document review + joint clinical audit test |
| F-003 | INJ-00 | CAP-01 | Incident severity matrix lacks explicit Tier 2 escalation triggers for EDR anomalies originating from vendor-managed agent processes. | P2 | Update incident intake playbooks to add mandatory Tier 2 escalation for signed vendor process network anomalies. | SOC Lead | 14 days | IR Playbook revision review |
| F-004 | INJ-04 | CAP-05 | Compliance tracking workflows lack distinct tracking clocks for Covered Entity HIPAA reporting vs. vendor BAA notification windows. | P2 | Incorporate dual-clock tracking templates into the legal crisis checklist for third-party Business Associate breaches. | Legal Counsel | 30 days | Checklist review by Legal/Privacy Officer |
| F-005 | INJ-05 | CAP-07 | Crisis communication templates focus on perimeter breaches and lack pre-approved holding language for vendor supply chain outages. | P3 | Draft and pre-approve media and patient banner templates specifically for third-party SaaS integration disruptions. | Communications Lead | 30 days | Draft template sign-off by PR & Legal |

---

## P1 Finding narratives

### F-001: Lack of defined authority and workflow for emergency vendor isolation

During INJ-02, the incident team identified the need to sever the IPsec tunnel and disable the `svc-nexus-prod` service principal to contain ongoing ePHI exfiltration. However, the decision stalled due to ambiguity over whether technical IR, IT Operations, or Clinical Leadership held final authority to disconnect an integration affecting 3,500 weekly appointments. This lack of pre-defined decision authority creates dangerous delays during an active breach or risks unilateral technical action that could compromise patient safety across all three sites. To resolve this, MedDefense must publish a Vendor System Emergency Isolation SOP defining clear authorization hierarchies (Executive Sponsor + Clinical Director sign-off) and mandatory paper-fallback activation steps (owner: IT Director; deadline: 21 days; validation: playbook sign-off and executive tabletop re-test).

### F-002: Missing FHIR data integrity verification protocol following API compromise

During INJ-03, telemetry indicated that unauthorized inbound HL7 FHIR modify requests were executed via `https://ehr-ingest.meddefense.local/nexus-inbound/` during the compromise window. The team struggled to rapidly verify whether active patient rosters in Epic had been tampered with, relying on ad-hoc roster checks. Failing to systematically validate data integrity following an ingest pipeline compromise exposes clinics to altered appointment times, missing check-in data, and potential patient care misdirection. MedDefense must establish a formal EHR Ingest Data Integrity Checklist that details step-by-step forensic log cross-referencing between Epic core ingest backups and FHIR transaction logs during suspected service principal compromises (owner: Lead DFIR Analyst; deadline: 30 days; validation: SOP review and joint clinical audit test).

---

## What worked

1. **Rapid Technical Escalation to Formal BAA Channels:** During INJ-01, the IR Lead and Legal Counsel immediately bypassed routine sales account contacts and engaged Nexus SecOps directly via verified 24x7 emergency channels (+1 512 555 0184 / `soc@nexushealth.io`), leveraging prior vendor risk context effectively.
2. **Independent Regulatory Posture:** In INJ-04, Legal Counsel and Compliance correctly rejected the vendor's request to delay public and regulatory notifications by 72 hours, recognizing MedDefense's independent obligations as a covered entity under the HIPAA Breach Notification Rule.
3. **Structured Board Communication:** During INJ-06, the executive briefing effectively articulated technical containment state, clinical fallback status, and regulatory posture while correctly identifying unresolved vendor SaaS persistence in AWS `us-east-1` as the primary blocker to reconnection.

---

## Exercise design feedback

- **DF-01 (Sequence Adjustment):** Shifted inbound FHIR record modification indicators from INJ-03 into INJ-02 so participants evaluate clinical data integrity risks alongside exfiltration threats when making the initial isolation decision.
- **DF-02 (Evaluation Criteria Refinement):** Updated INJ-04 pass criteria in `evaluation_criteria.yaml` to explicitly require legal evaluation of Covered Entity HIPAA notification clocks (45 CFR § 164.404) independent of BAA contract terms.
- **DF-03 (Crisis Comms Deliverable Scope):** Expanded INJ-05 deliverables to require simultaneous drafting of a public press holding statement and an internal patient-facing clinic web banner.
