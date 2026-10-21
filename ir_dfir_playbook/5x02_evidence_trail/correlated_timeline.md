# Correlated Incident Timeline: LH-2026-0414-01

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-04-13T18:10:22Z | proxy_log.jsonl | Credential phishing link clicked by dmarsh | T1566.002 | Confirmed | proxy_log.jsonl line 12 |
| 2026-04-13T18:12:05Z | proxy_log.jsonl | Credentials submitted to typosquat domain | T1598.003 | Confirmed | proxy_log.jsonl line 15 |
| 2026-04-13T18:14:10Z | ad_auth_log.jsonl | Attacker VPN access using dmarsh credentials | T1078.003 | Confirmed | ad_auth_log.jsonl line 42 |
| 2026-04-14T02:45:12Z | wst-ws-031.dd | Malicious files dropped to AppData\Local\Temp | T1105 | Confirmed | ART-001-F01 |
| 2026-04-14T02:47:55Z | wst-ws-031.mem | powershell.exe execution with encoded payload | T1059.001 | Confirmed | ART-002-M01 |
| 2026-04-14T02:48:02Z | wst-ws-031.mem | msbuild.exe spawned by PowerShell (C2 beacon starts) | T1127.001 | Confirmed | ART-002-M01, ART-002-M02 |
| 2026-04-14T02:48:10Z | wst-ws-031.dd | Scheduled task and Run key persistence installed | T1053.005 | Confirmed | ART-001-R01, ART-001-R02 |
| 2026-04-14T02:50:00Z | wst-ws-031.mem | NTLM hash and Kerberos ticket material accessible in lsass.exe | T1003.001 | Probable | ART-002-M04 |
| 2026-04-14T03:15:00Z | ad_auth_log.jsonl | Kerberos TGS request for cifs/WST-WS-017 | T1558.003 | Confirmed | ad_auth_log.jsonl line 104 |
| 2026-04-14T03:18:22Z | ad_auth_log.jsonl | Lateral movement logon to WST-WS-017 | T1021.002 | Confirmed | ad_auth_log.jsonl line 110 |
| 2026-04-14T03:38:00Z | wst-ws-017.mem | Second C2 beacon from WST-WS-017 | T1071.001 | Confirmed | ART-003-M01 |
| 2026-04-14T04:10:15Z | ad_auth_log.jsonl | Kerberos TGS request for cifs/LIS-WSIDE-01 | T1558.003 | Confirmed | ad_auth_log.jsonl line 145 |
| 2026-04-14T04:12:40Z | ad_auth_log.jsonl | Logon to LIS-WSIDE-01 | T1021.002 | Confirmed | ad_auth_log.jsonl line 152 |
| 2026-04-14T04:20:00Z | proxy_log.jsonl | 14 patient lab report PDFs read on LIS-WSIDE-01 | T1114 | Confirmed | proxy_log.jsonl line 210 |
