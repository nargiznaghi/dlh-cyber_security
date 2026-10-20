# Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: `/evidence/IR-2026-0414-01/`
Hash algorithm: SHA-256
Hash manifest: `/evidence/IR-2026-0414-01/hashes.txt`

---

## 1. Volatile memory, WST-WS-031
- **what**: Full physical memory dump of host WST-WS-031
- **how**: `winpmem_3.3.rc3.exe -o \evidence\IR-2026-0414-01\memory\wst-ws-031.raw`
- **hash cmd**: `sha256sum /evidence/IR-2026-0414-01/memory/wst-ws-031.raw >> /evidence/IR-2026-0414-01/hashes.txt`
- **ordering**: MUST precede any process kill, reboot, or host network isolation; volatile RAM state is permanently lost upon power-off
- **verification**: Hash appended and verified via manifest

## 2. Process tree and network connections, WST-WS-031
- **what**: Active process tree, PIDs, parent PIDs, command lines, and active network connections
- **how**: `Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | ConvertTo-Json > C:\temp\processtree.json; netstat -ano > C:\temp\netstat.txt`
- **hash cmd**: `sha256sum /evidence/IR-2026-0414-01/process_tree/processtree.json /evidence/IR-2026-0414-01/network/netstat.txt >> /evidence/IR-2026-0414-01/hashes.txt`
- **ordering**: MUST precede host network isolation; active socket mappings and ephemeral process states are lost upon disconnect
- **verification**: Hash appended and verified via manifest

## 3. Endpoint telemetry export (24 hours), WST-WS-031
- **what**: Full 24-hour EDR telemetry log export for host WST-WS-031
- **how**: `cp 5x01/edr_wst_ws_031_24h.jsonl /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl`
- **hash cmd**: `sha256sum /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl >> /evidence/IR-2026-0414-01/hashes.txt`
- **ordering**: Must be captured prior to EDR isolation mode enforcement which may restrict local log queries
- **verification**: Hash appended and verified via manifest

## 4. SIEM alert record
- **what**: Complete SIEM alert record for detection `wz-edr-100041` in JSON format
- **how**: `cp 5x01/alert_A-20260414-9841.json /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json`
- **hash cmd**: `sha256sum /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json >> /evidence/IR-2026-0414-01/hashes.txt`
- **ordering**: Capture early during triage to lock original detection metadata and correlation state
- **verification**: Hash appended and verified via manifest

## 5. Proxy and DNS logs, dmarsh (24 hours)
- **what**: Web proxy traffic and DNS lookup logs for user `MEDDEFENSE\dmarsh` covering the last 24 hours
- **how**: `cp 5x01/proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log`
- **hash cmd**: `sha256sum /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log >> /evidence/IR-2026-0414-01/hashes.txt`
- **ordering**: Capture prior to perimeter block or DNS response policy changes to retain un-altered domain resolution context
- **verification**: Hash appended and verified via manifest

## 6. Authentication events, dmarsh (24 hours)
- **what**: Active Directory and Azure AD logon events for user `MEDDEFENSE\dmarsh` over the last 24 hours
- **how**: `cp 5x01/auth_24h_dmarsh.json /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json`
- **hash cmd**: `sha256sum /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json >> /evidence/IR-2026-0414-01/hashes.txt`
- **ordering**: Capture prior to credential reset or session revocation to preserve initial logon vectors and ticket state
- **verification**: Hash appended and verified via manifest

## 7. Additional expansion logs
- **what**: Authorization expansion logs for user dmarsh
- **how**: `cp 5x01/auth_expansion_0334Z.log /evidence/IR-2026-0414-01/authentication/auth_expansion_0334Z.log`
- **hash cmd**: `sha256sum /evidence/IR-2026-0414-01/authentication/auth_expansion_0334Z.log >> /evidence/IR-2026-0414-01/hashes.txt`
- **ordering**: Capture during initial scope expansion before log rotation
- **verification**: Hash appended and verified via manifest

## 8. Verification
- All artifacts re-hashed from the evidence store
- Hash values compared to original capture values via command: `sha256sum -c /evidence/IR-2026-0414-01/hashes.txt`
- Mismatches logged to the incident timeline as OBSERVATION entries
