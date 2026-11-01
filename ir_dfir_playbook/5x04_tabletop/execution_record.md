# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** 2026-11-05  
**Simulated by:** Nargiz Naghiyeva  

---

## INJ-00 (T+0 min)

**Inject delivered:**  
"The SOC has flagged unusual outbound traffic from the Nexus scheduling server (SCHED-SVR-01) at the Main campus to 193.42.100.77, a host associated with bulletproof hosting infrastructure in Eastern Europe. The alert fired 45 minutes ago. The Nexus system is currently operational. Patient scheduling is running normally across all three sites. No other anomalies have been detected."

**Participant responses:**
- **James Chen (SOC Lead / IR Lead):** Declares a SEV2 incident immediately; initiates non-disruptive network PCAP and log harvesting on SCHED-SVR-01 without severing connections.
- **Sarah Park (Legal Counsel):** Asks if any ePHI exfiltration is confirmed yet and requests to be kept on the preliminary incident loop.
- **Marcus Webb (IT Operations):** Checks host configuration for SCHED-SVR-01 and notes that the outbound traffic originates from the `nexus-agent` process path.
- **Dr. Patricia Morales (Executive Sponsor):** Stays informed on baseline assessment; defers technical decisions to James pending initial forensics.
- **Helena Reyes (Communications / PR):** Monitored on standby; no external release required at this stage.
- **Robert Kim (Compliance):** Begins reviewing data mapping for `svc-nexus-prod` scope.
- **Clinical Director Representative:** Not yet engaged.

**Evaluation:**
- **Criterion 1 (incident declared within 5 min):** PASS — James declares SEV2 at T+3 min with explicit reasoning regarding outbound connection to bulletproof hosting infrastructure.
- **Criterion 2 (two roles notified):** PASS — IR Commander and Legal Counsel notified by name within 4 minutes.
- **Criterion 3 (evidence before containment):** PASS — SOC collects log dumps and network PCAP preserving host state before discussing isolation.

**Facilitator note:** Asked "Has anyone cross-referenced whether the outbound process path is tied to the automated Nexus update service?" Marcus noted the process name, but the team did not immediately suspect the vendor supply chain pipeline itself until INJ-01.

---

## INJ-01 (T+20 min)

**Inject delivered:**  
"Nexus Patient Scheduling has published a security advisory. Their AWS build pipeline was compromised by a threat actor with access to their code-signing certificate ('Nexus Health Technologies, Inc.'). All software agent updates distributed in the last 21 days—including the payload deployed to SCHED-SVR-01—contain a backdoor allowing unauthorized ePHI access. Nexus advises customers to take immediate action, but they do not yet have a clean patch or SBOM breakdown."

**Participant responses:**
- **James Chen (IR Lead):** Immediately initiates direct outreach to Nexus SecOps 24x7 escalation (+1 512 555 0184) to request binary hash confirmation and payload analysis.
- **Sarah Park (Legal Counsel):** Notes BAA emergency provisions and advises technical team to document all communications directly with Nexus CISO Marcus Oduya.
- **Marcus Webb (IT Operations):** Highlights that SCHED-SVR-01 update cert passed initial validation because client-side hash pinning was not implemented per the November 2025 security review finding.
- **Dr. Patricia Morales (Executive Sponsor):** Requests immediate risk evaluation on isolating the vendor tunnel versus maintaining operations.

**Evaluation:**
- **Criterion 1 (formal BAA channels invoked):** PASS — James contacts Nexus SecOps 24x7 phone/email directly rather than sales account representatives.
- **Criterion 2 (references audit findings):** PASS — Marcus references the missing client-side hash pin vulnerability from the 2025 security review.
- **Criterion 3 (binary hash requested):** PASS — Technical team asks Nexus SecOps for official SHA-256 hash validation for the update package.

**Facilitator note:** Asked "Would you contact Priya Natarajan (Account Exec) or Marcus Oduya / SecOps first?" Team correctly chose the 24x7 emergency SecOps channel specified in the vendor profile.

---

## INJ-02 (T+40 min)

**Inject delivered:**  
"EDR logs confirm the backdoor on SCHED-SVR-01 has executed shell commands using the service principal `svc-nexus-prod`, querying Epic HL7 FHIR endpoints (`https://ehr-ingest.meddefense.local/nexus-inbound/`). The IR team recommends severing the IPsec tunnel and disabling `svc-nexus-prod` immediately. However, doing so will instantly freeze outpatient pre-registration and appointment processing across all three sites (3,500 patient interactions weekly)."

**Participant responses:**
- **James Chen (IR Lead):** Recommends immediate network isolation of the IPsec tunnel and disabling service principal `svc-nexus-prod`.
- **Clinical Director Representative:** Pushes back strongly, stating that severing integration without fallback will stall 3,500 weekly appointments and create severe clinic delays.
- **Marcus Webb (IT Operations):** Proposes activating emergency paper check-in sheets and offline scheduling procedures across all three sites.
- **Dr. Patricia Morales (Executive Sponsor):** Formally authorizes network tunnel isolation after Clinical Operations confirms paper fallback procedures are actively deployed.

**Evaluation:**
- **Criterion 1 (authorized system isolation):** PASS — Executive Sponsor and IT Director explicitly authorize isolation after reviewing clinical trade-offs.
- **Criterion 2 (manual fallback activated):** PASS — Clinical Operations formally initiates manual paper scheduling workflows prior to severing connections.
- **Criterion 3 (patient safety documented):** PASS — Clinical disruption across Main, West, and North sites is documented in the decision summary.

**Facilitator note:** Asked "Who holds the final authority to disconnect a clinical integration during an active cyber event?" Team engaged in strong discussion before reaching consensus on joint sign-off between the Executive Sponsor and Clinical Director.

---

## INJ-03 (T+60 min)

**Inject delivered:**  
"Forensic analysis reveals that exfiltrated packets contained demographic records, insurance eligibility details, and appointment schedules for 12,000 patients across Main Campus, West Campus, and North Site. Crucially, log traces indicate inbound appointment modify requests were processed by Epic during the compromise window, suggesting appointment times or provider assignments may have been altered."

**Participant responses:**
- **Clinical Director Representative:** Halts reliance on digital check-in screens across all clinics and requests immediate roster cross-checks.
- **James Chen (IR Lead):** Orders forensic log audit comparing local Epic ingest logs against raw FHIR inbound transactions from `https://ehr-ingest.meddefense.local/nexus-inbound/`.
- **Marcus Webb (IT Operations):** Establishes a manual patient verification desk at clinic reception entry points for next-day appointments.
- **Robert Kim (Compliance):** Flags potential patient safety and regulatory liability if corrupted appointments lead to missed care delivery.

**Evaluation:**
- **Criterion 1 (halts unverified rosters):** PASS — Clinical Operations stops relying on active digital scheduling screens.
- **Criterion 2 (forensic FHIR audit):** PASS — IR team initiates log reconciliation between Epic raw ingest backups and FHIR transaction logs.
- **Criterion 3 (check-in verification workflow):** PASS — Entry point verification desks established for clinic check-ins across all three sites.

**Facilitator note:** Asked "How do you handle a patient who arrives for a procedure but does not appear on the restored manual schedule?" Clinical rep outlined a supervisor override workflow to prevent turning away urgent patients.

---

## INJ-04 (T+75 min)

**Inject delivered:**  
"Nexus SecOps states via email that they are still investigating and request MedDefense delay any public or regulatory reporting for 72 hours while they assess subprocessor impact (AWS, Twilio, SendGrid). However, MedDefense Legal Counsel notes that ePHI exfiltration is confirmed, and HIPAA Breach Notification clocks for covered entities operate independently of vendor requests."

**Participant responses:**
- **Sarah Park (Legal Counsel):** Rejects the vendor's 72-hour delay request, advising that MedDefense's covered entity HIPAA 60-day notification clock started upon confirmation of exfiltration.
- **Robert Kim (Compliance):** Begins scoping breach size (12,000 affected individual records containing demographic and insurance data) for HHS OCR notification.
- **Dr. Patricia Morales (Executive Sponsor):** Approves Legal's plan to proceed with formal breach assessment independent of Nexus's timeline.

**Evaluation:**
- **Criterion 1 (independent legal clock):** PASS — Legal Counsel independently starts HIPAA breach assessment immediately upon confirmation of exfiltration.
- **Criterion 2 (rejects vendor delay):** PASS — Team formally declines Nexus's request to pause reporting.
- **Criterion 3 (scopes ePHI exposure):** PASS — Compliance correctly scopes exposure based on demographic and insurance data for 12,000 individuals.

**Facilitator note:** Asked "Does the lack of clinical charting exfiltration exempt this incident from HIPAA Breach Notification?" Sarah Park correctly answered that demographic and insurance data constitute ePHI under HIPAA regardless of chart access.

---

## INJ-05 (T+90 min)

**Inject delivered:**  
"A reporter from a regional news outlet calls MedDefense PR stating they received a tip that patient scheduling is down across all three sites due to a ransomware attack. Simultaneously, patients on social media report cancelled appointments and missing check-in data. The reporter gives MedDefense 30 minutes to provide a statement before publishing."

**Participant responses:**
- **Helena Reyes (Communications / PR):** Drafts a holding statement confirming scheduled maintenance and operational security reviews, refuting unverified ransomware claims.
- **Sarah Park (Legal Counsel):** Vets the holding statement to ensure no unconfirmed numbers or vendor liability admissions are released.
- **Dr. Patricia Morales (Executive Sponsor):** Sign-off on holding statement and approves setting up a dedicated patient helpline.

**Evaluation:**
- **Criterion 1 (holding statement within window):** PASS — Statement drafted and approved within 22 minutes.
- **Criterion 2 (refutes ransomware, avoids oversharing):** PASS — Statement refutes ransomware rumors while avoiding premature statements on total breach numbers.
- **Criterion 3 (legal/executive sign-off):** PASS — Mandatory joint sign-off completed prior to media distribution.

**Facilitator note:** Asked "Will you name Nexus Patient Scheduling directly in the initial public statement?" Comms and Legal correctly chose to reference 'third-party platform operational adjustments' pending formal notification to avoid breach of contract claims while investigating.

---

## INJ-06 (T+110 min)

**Inject delivered:**  
"The Board of Directors requests an emergency status briefing in 10 minutes. While containment steps are underway, the team cannot determine whether the threat actor retains persistence within Nexus's multi-tenant SaaS environment (`us-east-1`), nor when it will be safe to re-establish FHIR API integration."

**Participant responses:**
- **Dr. Patricia Morales (Executive Sponsor):** Delivers board briefing covering incident timeline, immediate network containment, clinical fallback status, and legal notification posture.
- **James Chen (IR Lead):** Explicitly highlights unresolved vendor persistence in AWS `us-east-1` as an ongoing operational blocker.
- **Sarah Park (Legal Counsel):** Outlines next steps for regulatory notifications and ongoing vendor BAA compliance monitoring.
- **Marcus Webb (IT Operations):** Defines technical re-connection prerequisites: verified vendor patch, independent clean SOC 2/penetration report, and client-side hash pinning implementation.

**Evaluation:**
- **Criterion 1 (structured executive brief):** PASS — Briefing covers timeline, containment, clinical impact, and legal posture clearly.
- **Criterion 2 (acknowledges vendor persistence risk):** PASS — Unresolved SaaS multi-tenant persistence in `us-east-1` explicitly communicated to the board.
- **Criterion 3 (defines reconnect prerequisites):** PASS — Technical and vendor risk criteria established prior to approving future FHIR integration restore.

**Facilitator note:** Asked "If the board demands an exact time for restoring the Nexus integration, what is your answer?" Dr. Morales correctly responded that restoration is condition-based (verification of clean build + hash pinning), not calendar-based.

---

## Design feedback

### DF-01: INJ-03 appointment integrity details should be introduced earlier
During simulation, the decision to isolate the Nexus IPsec tunnel occurred at INJ-02 (T+40 min), but the evidence of inbound FHIR record modification was introduced at INJ-03 (T+60 min). Knowing that appointment schedules were actively modified creates a much stronger clinical imperative for isolation.  
**Change:** Move the inbound FHIR record modification indicator into INJ-02 as a secondary telemetry finding so clinical operations faces both exfiltration and data integrity pressure simultaneously when making the isolation decision.

### DF-02: INJ-04 compliance scoping criteria needed clearer distinction between HIPAA rules
During INJ-04, participants initially debated whether a Business Associate's delay request legally bound the Covered Entity. While Sarah Park correctly identified MedDefense's independent duty, the pass criteria in `evaluation_criteria.yaml` did not explicitly require participants to document the specific 60-day Covered Entity reporting window vs. the vendor 24-hour BAA clause.  
**Change:** Update `evaluation_criteria.yaml` under INJ-04 to mandate that the written legal finding explicitly distinguishes between Covered Entity HIPAA Breach Notification Rule obligations (45 CFR § 164.404) and BAA contractual notification clauses.

### DF-03: INJ-05 media deadline created gap in patient communications protocol
The 30-minute media deadline in INJ-05 forced rapid PR statement drafting, but highlighted that MedDefense lacked a pre-approved patient advisory template for clinic delays. The team successfully produced a media statement but struggled to simultaneously publish patient check-in guidance on the website.  
**Change:** Add a second explicit expected deliverable to INJ-05 requiring Comms to publish a pre-drafted patient website banner alongside the press holding statement.
