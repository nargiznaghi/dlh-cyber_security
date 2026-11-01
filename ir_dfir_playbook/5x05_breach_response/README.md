# The Breach

> "We don't rise to the level of our expectations; we fall to the level of our training." — Archilochus

## Overview

*The Breach* is a capstone incident response exercise for MedDefense. Starting Sunday at 19:43, you own the complete incident lifecycle—triage, evidence collection, forensic analysis, containment, eradication, HIPAA regulatory risk assessment, and board briefing.

## Scenario Context

- **Initial Vector:** Spearphishing email with a malicious Word macro executed on Thursday by the on-call clinical coordinator.
- **Dwell Time:** 72 hours.
- **Attacker Activity:** 
  - Cobalt Strike beacon deployed via PowerShell from a squatted Microsoft CDN domain.
  - Lateral movement across 3 additional workstations via NTLM credential dumping.
  - 1,847 patient files accessed on the clinical documentation file server.
  - Staged ransomware scripts discovered in system directories on 4 workstations.

## Provided Artifacts

- `cs-ws-101.dd` — Forensics disk image of initial compromised workstation.
- `cs-ws-101.mem` — Volatile memory dump acquired at 19:38Z.
- `proxy_72h.jsonl` — 72-hour proxy network traffic logs.
- `sysmon_multihost.jsonl` — Sysmon process creation and network event logs across affected hosts.
- `fileserver_access.evtx` — Windows Security Event Log from the file server.

## Key Objectives

- Analyze memory, disk, proxy, and Sysmon telemetry to reconstruct the 72-hour attack chain.
- Contain active Cobalt Strike implants and prevent ransomware execution across all 4 hosts.
- Complete a HIPAA four-factor breach assessment for the 1,847 compromised patient records.
- Deliver a board-quality executive incident brief under time pressure.
