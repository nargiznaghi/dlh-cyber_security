# IR Activation: IR-2026-0420-01

- **Incident ID:** IR-2026-0420-01
- **Declared At:** 2026-04-20T19:52Z
- **Declared By:** Nargiz Naghiyeva, On-Call Incident Response Lead
- **Initial Severity:** SEV1
- **Reasoning:** Multiple clinical workstations (`CS-WS-101`, `CS-WS-104`, `CS-WS-107`, `CS-WS-112`) exhibit active C2 beaconing via non-standard service binaries (`WinHealthSvc` at `C:\ProgramData\Microsoft\svchost32.exe`), accompanied by severe disk hammering on scheduling server `SCHED-SVR-01` and user reports of altered desktop files. Given the multi-host lateral movement, potential ePHI exposure, and risk of imminent ransomware deployment across clinical environments, this constitutes a severe enterprise-impacting security incident.
- **Playbook Activated:** Advanced Threat / Ransomware & C2 Beaconing Response Playbook (combining host isolation, malware eradication, forensic preservation, and executive escalation protocols).
- **Notifications (First 15 Minutes):**
  - `19:52Z` — Mike Torres (Network Engineer / Evidence Acquirer) notified to join emergency IR bridge and maintain evidence chain for `cs-ws-101.mem`.
  - `19:54Z` — James Chen (SOC Lead) notified and briefed on SIEM alert `wz-edr-200214` across `CS-WS-104`, `CS-WS-107`, and `CS-WS-112`.
  - `19:56Z` — Dr. Patricia Morales (Executive Sponsor / CISO) and Sarah Park (Legal Counsel) notified via urgent executive pager regarding SEV1 incident activation.
- **First Communication:**
  > "MedDefense Incident Response has formally declared SEV1 incident IR-2026-0420-01 following the detection of unauthorized C2 beaconing, service persistence (`WinHealthSvc`), and potential ePHI compromise across multiple clinical workstations at Main Campus. Core technical response teams have been mobilized to execute containment, forensic acquisition, and infrastructure isolation under active-threat conditions. Executive and legal leadership will receive continuous updates as triage and evidence correlation progress."
