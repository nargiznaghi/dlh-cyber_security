# Incident Timeline: IR-2026-0420-01

| Timestamp (UTC) | Type | Actor | Description | Source | Certainty |
|---|---|---|---|---|---|
| `2026-04-20T19:38Z` | EVIDENCE | Mike Torres | Captured volatile memory dump (`cs-ws-101.mem`) of compromised workstation `CS-WS-101` using WinPmem prior to isolation. | Host telemetry / Torres | High |
| `2026-04-20T19:43Z` | OBSERVATION | Clinical Nurse / Mike Torres | On-call nurse at Main Campus reports extremely slow workstation performance and altered/renamed desktop files on `CS-WS-101`. Network engineer observes disk queue saturation on scheduling server `SCHED-SVR-01` lasting ~90 minutes. | Signal Call Transcript | High |
| `2026-04-20T19:44Z` | OBSERVATION | Mike Torres | SIEM alert `wz-edr-200214` fires across three unmonitored clinical workstations (`CS-WS-104`, `CS-WS-107`, `CS-WS-112`) indicating service installation of `WinHealthSvc` (`C:\ProgramData\Microsoft\svchost32.exe`) within a 12-minute window. | SIEM / EDR Telemetry | Confirmed |
| `2026-04-20T19:52Z` | DECISION / ACTION | Nargiz Naghiyeva (IR Lead) | Formally declared incident `IR-2026-0420-01` as SEV1, activated the Malware C2 & Lateral Movement Response Playbook, and initiated emergency notifications to Executive Sponsor, Legal, and SOC Lead. | IR Activation Record | Confirmed |
| `2026-04-20T21:30Z` | ACTION | Nargiz Naghiyeva (IR Lead) | Completed attack chain reconstruction, mapping proxy, Sysmon, and file server logs to MITRE ATT&CK tactics in `attack_chain.md`. | Telemetry Correlation / Attack Chain | Confirmed |
| `2026-04-20T20:02Z` | ACTION | Mike Torres | Applied perimeter firewall egress block for C2 IP `193.42.100.77` and DNS sinkhole. | Containment Execution | Confirmed |
| `2026-04-20T20:08Z` | ACTION | Nargiz Naghiyeva | Executed EDR network isolation on `CS-WS-101`. | Containment Execution | Confirmed |
| `2026-04-20T20:15Z` | ACTION | Nargiz Naghiyeva | Executed parallel EDR network isolation on `CS-WS-104` and `CS-WS-107`. | Containment Execution | Confirmed |
| `2026-04-20T20:20Z` | ACTION | Nargiz Naghiyeva | Executed EDR network isolation on `CS-WS-112`. | Containment Execution | Confirmed |
| `2026-04-20T20:24Z` | ACTION | Mike Torres | Restricted SMB share ACLs on `FILE-SVR-01` and terminated compromised workstation sessions. | Containment Execution | Confirmed |
| `2026-04-20T20:28Z` | ACTION | James Chen | Revoked compromised AD account credentials and initiated KRBTGT password reset. | Containment Execution | Confirmed |
| `2026-04-20T20:30Z` | ACTION | Nargiz Naghiyeva | Completed NetFlow and EDR verification confirming 100% C2 severance across all hosts. | Containment Execution | Confirmed |
