# HIPAA Breach Risk Assessment: IR-2026-0420-01

Assessment date: 2026-04-20
Conducted by: Nargiz Naghiyeva, IR Lead
Reviewed by: Helena Reyes, General Counsel (pending)
PHI involved: 1,847 patient files - lab results and clinical notes - accessed from FILE-SVR-01

## Factor 1: Nature and extent of PHI involved
Evidence: Forensic finding FS-001 confirms that exactly 1,847 patient records (including diagnostic notes, lab test results, and clinical notes) located on `FILE-SVR-01` were accessed and read during the attack window on Sunday evening.
Conclusion: The data involved includes direct patient identifiers combined with sensitive clinical diagnostic information, representing high-sensitivity health records.
Confidence: confirmed

## Factor 2: Unauthorized person who used or received PHI
Evidence: Forensic finding MEM-002, PROXY-002, and SYSMON-001 establish that an external adversary operating through Cobalt Strike command and control infrastructure (`193.42.100.77`) gained unauthorized remote access via compromised clinical credentials (`ClinicalCoord`).
Conclusion: The recipient is an unauthorized external threat actor with no permissible relationship to MedDefense.
Confidence: confirmed

## Factor 3: Whether PHI was actually acquired or viewed
Evidence: File server access event logs (FS-001) demonstrate 1,847 successful file read operations (Event ID 4663), and proxy exfiltration telemetry (PROXY-003) confirms a 15.4 MB data egress burst following the file access events.
Conclusion: The patient records were actively viewed, accessed, and exfiltrated by the attacker.
Confidence: confirmed

## Factor 4: Extent to which risk has been mitigated
Evidence: Containment execution records show that while active C2 channels were severed and ransomware staging was intercepted before execution, the data exfiltrated to external infrastructure cannot be recovered or cryptographically recalled (Containment Execution Record, Steps 1–7).
Conclusion: Risk mitigation is partial; the exfiltrated data remains in the control of an external unauthorized party.
Confidence: confirmed

## Determination
Based on the four-factor evaluation, the assessment fails to support a conclusion of low probability of compromise. Therefore, the incident constitutes a **reportable HIPAA breach** affecting 1,847 individuals. 
- **Final Determination Maker:** Helena Reyes, General Counsel, in coordination with Executive Leadership.
- **Timeline:** Formal notification to HHS OCR, affected individuals, and media must be completed within 60 calendar days (by June 19, 2026).
