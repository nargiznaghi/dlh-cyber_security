# Incident Timeline

## Header Block
- **incident_id**: INC-20260414-9841
- **declared_at**: 2026-04-14T02:50:00Z
- **declared_by**: nargiz
- **initial_severity**: SEV2
- **current_severity**: SEV2
- **ir_commander**: nargiz
- **scribe**: nargiz

---

## Legend
- **OBSERVATION**: Primary data observed, telemetry received, or findings identified.
- **DECISION**: Management or operational choices made regarding the incident lifecycle.
- **ACTION**: Active response, technical intervention, or task execution performed.
- **COMMUNICATION**: Notifications, updates, or alerts sent to stakeholders/team members.
- **EVIDENCE**: Artifacts, logs, or memory dumps captured and saved for analysis.

---

## Chronological Entries

- **timestamp**: 2026-04-13T18:14:02Z
  - **type**: OBSERVATION
  - **actor**: dmarsh
  - **description**: User visited phishing domain ms0365-support.login-verification.click/auth.
  - **source**: proxy_24h_dmarsh.log
  - **certainty**: confirmed

- **timestamp**: 2026-04-13T18:14:43Z
  - **type**: OBSERVATION
  - **actor**: dmarsh
  - **description**: User downloaded update.zip from phishing domain to C:\Users\dmarsh\Downloads\update.zip.
  - **source**: edr_wst_ws_031_24h.jsonl
  - **certainty**: confirmed

- **timestamp**: 2026-04-13T18:15:05Z
  - **type**: OBSERVATION
  - **actor**: dmarsh
  - **description**: Executable update.exe created in Temp directory C:\Users\dmarsh\AppData\Local\Temp\update.exe.
  - **source**: edr_wst_ws_031_24h.jsonl
  - **certainty**: confirmed

- **timestamp**: 2026-04-13T18:15:14Z
  - **type**: OBSERVATION
  - **actor**: update.exe
  - **description**: Persistence established via Scheduled Task {7B4F2D81-19E2-4A8C-9E67-A1F0DE2C7B3A} pointing to update.exe.
  - **source**: edr_wst_ws_031_24h.jsonl
  - **certainty**: confirmed

- **timestamp**: 2026-04-14T02:44:05Z
  - **type**: OBSERVATION
  - **actor**: SYSTEM (Scheduled Task)
  - **description**: update.exe executed on user logon (PID 7204).
  - **source**: edr_wst_ws_031_24h.jsonl
  - **certainty**: confirmed

- **timestamp**: 2026-04-14T02:46:41Z
  - **type**: OBSERVATION
  - **actor**: update.exe
  - **description**: PowerShell (PID 7812) spawned with encoded command by update.exe.
  - **source**: alert_A-20260414-9841.json / edr_wst_ws_031_24h.jsonl
  - **certainty**: confirmed

- **timestamp**: 2026-04-14T02:46:57Z
  - **type**: OBSERVATION
  - **actor**: powershell.exe
  - **description**: MSBuild.exe (PID 8104) spawned with C:\Users\dmarsh\AppData\Local\Temp\update.xml.
  - **source**: alert_A-20260414-9841.json / edr_wst_ws_031_24h.jsonl
  - **certainty**: confirmed

- **timestamp**: 2026-04-14T02:47:02Z
  - **type**: OBSERVATION
  - **actor**: MSBuild.exe
  - **description**: Outbound network connection established from MSBuild.exe (PID 8104) to Tor exit relay 185.220.101.47:443.
  - **source**: alert_A-20260414-9841.json / edr_wst_ws_031_24h.jsonl
  - **certainty**: confirmed

- **timestamp**: 2026-04-14T02:47:11Z
  - **type**: OBSERVATION
  - **actor**: EDR System
  - **description**: Alert A-20260414-9841 (wz-edr-100041) fired for suspicious process tree PowerShell -> MSBuild on host WST-WS-031.
  - **source**: alert_A-20260414-9841.json
  - **certainty**: confirmed

- **timestamp**: 2026-04-14T02:50:00Z
  - **type**: DECISION
  - **actor**: nargiz
  - **description**: Formal incident declaration (INC-20260414-9841) initiated following EDR alert triage.
  - **source**: Manual Entry
  - **certainty**: confirmed

- **timestamp**: 2026-04-14T02:52:00Z
  - **type**: DECISION
  - **actor**: nargiz
  - **description**: Severity set to SEV2 due to active outbound C2 traffic to a known Tor exit node following credential harvesting and execution on a high-criticality clinical host.
  - **source**: Manual Entry
  - **certainty**: confirmed
