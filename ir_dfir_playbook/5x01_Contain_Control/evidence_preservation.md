# Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: /evidence/IR-2026-0414-01/
Hash algorithm: SHA-256

## 1. Volatile memory, WST-WS-031
- what: full physical memory dump
- how: winpmem_3.3.rc3.exe -o \evidence\IR-2026-0414-01\wst-ws-031.mem
- hash cmd: certutil -hashfile \evidence\IR-2026-0414-01\wst-ws-031.mem SHA256 >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: MUST precede any process kill or host isolation; memory state lost on power-off or reboot
- verification: hash written to /evidence/IR-2026-0414-01/hashes.txt

## 2. Process tree and network connections, WST-WS-031
- what: active process tree, parent-child relationships, command lines, and established network sockets
- how: Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | ConvertTo-Json > /evidence/IR-2026-0414-01/processtree.json; netstat -ano > /evidence/IR-2026-0414-01/netstat.txt
- hash cmd: sha256sum /evidence/IR-2026-0414-01/processtree.json /evidence/IR-2026-0414-01/netstat.txt >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: MUST precede host network isolation; active socket state and ephemeral process state are lost upon disconnect
- verification: hash written to /evidence/IR-2026-0414-01/hashes.txt

## 3. Endpoint telemetry export (24 hours), WST-WS-031
- what: full 24-hour EDR telemetry log export for host WST-WS-031
- how: cp 5x01/edr_wst_ws_031_24h.jsonl /evidence/IR-2026-0414-01/edr_wst_ws_031_24h.jsonl
- hash cmd: sha256sum /evidence/IR-2026-0414-01/edr_wst_ws_031_24h.jsonl >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: MUST precede isolation; agent isolation mode may restrict local telemetry collection or query access
- verification: hash written to /evidence/IR-2026-0414-01/hashes.txt

## 4. SIEM alert record
- what: complete SIEM alert record for detection wz-edr-100041 in JSON format
- how: cp 5x01/alert_A-20260414-9841.json /evidence/IR-2026-0414-01/alert_A-20260414-9841.json
- hash cmd: sha256sum /evidence/IR-2026-0414-01/alert_A-20260414-9841.json >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: capture early during triage to lock original detection metadata and correlation state
- verification: hash written to /evidence/IR-2026-0414-01/hashes.txt

## 5. Proxy and DNS logs, dmarsh (24 hours)
- what: web proxy traffic and DNS lookup logs for user dmarsh covering the last 24 hours
- how: cp 5x01/proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_24h_dmarsh.log
- hash cmd: sha256sum /evidence/IR-2026-0414-01/proxy_24h_dmarsh.log >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: capture prior to perimeter block or DNS response policy changes to retain un-altered domain resolution context
- verification: hash written to /evidence/IR-2026-0414-01/hashes.txt

## 6. Authentication events, dmarsh (24 hours)
- what: Active Directory and Azure AD logon events for user dmarsh over the last 24 hours
- how: cp 5x01/auth_24h_dmarsh.json /evidence/IR-2026-0414-01/auth_24h_dmarsh.json
- hash cmd: sha256sum /evidence/IR-2026-0414-01/auth_24h_dmarsh.json >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: capture prior to credential reset or session revocation to preserve initial logon vectors and ticket state
- verification: hash written to /evidence/IR-2026-0414-01/hashes.txt

## 7. Additional expansion logs
- what: authorization expansion logs for dmarsh
- how: cp 5x01/auth_expansion_0334Z.log /evidence/IR-2026-0414-01/auth_expansion_0334Z.log
- hash cmd: sha256sum /evidence/IR-2026-0414-01/auth_expansion_0334Z.log >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: capture during initial scope expansion before log rotation
- verification: hash written to /evidence/IR-2026-0414-01/hashes.txt

## 8. Verification
- All artifacts re-hashed from the evidence store
- Hash values compared to original capture values: sha256sum -c /evidence/IR-2026-0414-01/hashes.txt
- Mismatches logged to the incident timeline as OBSERVATION entries
