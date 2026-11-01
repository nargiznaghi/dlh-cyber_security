# Incident Timeline: IR-2026-0420-01

| Timestamp (UTC) | Type | Actor | Description | Source | Certainty |
|---|---|---|---|---|---|
| `2026-04-20T19:38Z` | EVIDENCE | Mike Torres | Captured volatile memory dump (`cs-ws-101.mem`) of compromised workstation `CS-WS-101` using WinPmem prior to isolation. | Host telemetry / Torres | High |
| `2026-04-20T19:43Z` | OBSERVATION | Clinical Nurse / Mike Torres | On-call nurse at Main Campus reports extremely slow workstation performance and altered/renamed desktop files on `CS-WS-101`. Network engineer observes disk queue saturation on scheduling server `SCHED-SVR-01` lasting ~90 minutes. | Signal Call Transcript | High |
| `2026-04-20T19:44Z` | OBSERVATION | Mike Torres | SIEM alert `wz-edr-200214` fires across three unmonitored clinical workstations (`CS-WS-104`, `CS-WS-107`, `CS-WS-112`) indicating service installation of `WinHealthSvc` (`C:\ProgramData\Microsoft\svchost32.exe`) within a 12-minute window. | SIEM / EDR Telemetry | Confirmed |
| `2026-04-20T19:52Z` | DECISION / ACTION | Nargiz Naghiyeva (IR Lead) | Formally declared incident `IR-2026-0420-01` as SEV1, activated the Malware C2 & Lateral Movement Response Playbook, and initiated emergency notifications to Executive Sponsor, Legal, and SOC Lead. | IR Activation Record | Confirmed |
