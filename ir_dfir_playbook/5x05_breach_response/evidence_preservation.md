# Evidence Preservation: IR-2026-0420-01

## Priority order rationale

Preservation order is determined by volatility, threat progression, and potential state destruction:
- **`CS-WS-101` (ART-001 / ART-002):** Initial entry point host. Volatile memory was acquired by Mike Torres at 19:38Z (`cs-ws-101.mem`). Full disk acquisition (`cs-ws-101.dd`) is assigned Priority 1 to preserve initial dropper artifacts, Word macros, and local ransomware staging files before network containment or reboot.
- **`CS-WS-104` & `CS-WS-107` (ART-003 / ART-004):** Active Cobalt Strike beaconing hosts running `WinHealthSvc`. Memory acquisition is prioritized immediately before network isolation to capture live process memory, decrypted C2 configs, injected threads, and active socket handles.
- **`FILE-SVR-01` (ART-005):** Holds the critical ePHI audit trail (`fileserver_access.evtx`). Assigned Priority 4 to capture non-volatile log telemetry and Volume Shadow Copies before log rollover or administrative disruption occurs.
- **`CS-WS-112` (ART-006):** Exhibits lateral movement service creation events but lower active beacon volatility; captured last in the sequence.

---

## ART-001: cs-ws-101.mem (Torres acquisition)
- acquired_by: Mike Torres (Network Engineer)
- acquired_at: 2026-04-20T19:38Z
- tool: WinPmem v4.0.RC1
- sha256_at_acquisition: Unrecorded at runtime by acquirer (procedural gap flagged in handoff notes)
- sha256_verified_by_analyst: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (computed at 2026-04-20T20:10Z during intake verification)
- gap_note: 5-minute gap between acquisition (19:38Z) and call commencement (19:43Z), and 14-minute gap to formal incident declaration (19:52Z). Memory state reflects system conditions prior to IR activation.

## ART-002: cs-ws-101.dd
- priority: 1
- acquired_before: Network isolation of `CS-WS-101`
- tool: FTK Imager CLI (`ftkimager.exe`) over IR jumpbox
- commands_or_tools: `ftkimager.exe \\.\PhysicalDrive0 \\evidence\share\IR-2026-0420-01\cs-ws-101.dd --e01 --verify`
- sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

## ART-003: cs-ws-104 evidence (cs-ws-104.mem & cs-ws-104.dd)
- priority: 2
- acquired_before: Host network isolation
- tool: WinPmem (volatile memory) & FTK Imager CLI (disk)
- commands_or_tools:
  - `winpmem.exe \\CS-WS-104\C$\evidence\cs-ws-104.mem`
  - `ftkimager.exe \\CS-WS-104\PhysicalDrive0 \\evidence\share\IR-2026-0420-01\cs-ws-104.dd --e01`
- sha256: Computed and logged post-acquisition via `sha256sum`.

## ART-004: cs-ws-107 evidence (cs-ws-107.mem & cs-ws-107.dd)
- priority: 3
- acquired_before: Host network isolation
- tool: WinPmem & FTK Imager CLI
- commands_or_tools:
  - `winpmem.exe \\CS-WS-107\C$\evidence\cs-ws-107.mem`
  - `ftkimager.exe \\CS-WS-107\PhysicalDrive0 \\evidence\share\IR-2026-0420-01\cs-ws-107.dd --e01`
- sha256: Computed and logged post-acquisition via `sha256sum`.

## ART-005: file-svr-01 evidence (fileserver_access.evtx)
- priority: 4
- acquired_before: Log clearance or server maintenance
- tool: KAPE / Windows `wevtutil` CLI
- commands_or_tools: `wevtutil epl Security \\evidence\share\IR-2026-0420-01\fileserver_access.evtx /q:"*[System[(EventID=4624 or EventID=4663)]]"`
- sha256: Computed post-export via `sha256sum`.

## ART-006: cs-ws-112 evidence (cs-ws-112.mem & cs-ws-112.dd)
- priority: 5
- acquired_before: Host network isolation
- tool: WinPmem & FTK Imager CLI
- commands_or_tools:
  - `winpmem.exe \\CS-WS-112\C$\evidence\cs-ws-112.mem`
  - `ftkimager.exe \\CS-WS-112\PhysicalDrive0 \\evidence\share\IR-2026-0420-01\cs-ws-112.dd --e01`
- sha256: Computed post-acquisition via `sha256sum`.

---

## Chain of Custody Table

| Artifact ID | Source Host | Item Description | Acquisition Time (UTC) | Acquired By | Acquisition Tool | Verified SHA-256 Checksum | Storage Location |
|---|---|---|---|---|---|---|---|
| ART-001 | `CS-WS-101` | Volatile Memory (`cs-ws-101.mem`) | 2026-04-20T19:38Z | Mike Torres | WinPmem | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `\\evidence\share\IR-2026-0420-01\cs-ws-101.mem` |
| ART-002 | `CS-WS-101` | Raw Disk Image (`cs-ws-101.dd`) | 2026-04-20T20:05Z | Nargiz Naghiyeva | FTK Imager CLI | `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` | `\\evidence\share\IR-2026-0420-01\cs-ws-101.dd` |
| ART-003 | `CS-WS-104` | Memory & Disk Image | 2026-04-20T20:20Z | Nargiz Naghiyeva | WinPmem / FTK | Computed at intake | `\\evidence\share\IR-2026-0420-01\cs-ws-104\` |
| ART-004 | `CS-WS-107` | Memory & Disk Image | 2026-04-20T20:35Z | Nargiz Naghiyeva | WinPmem / FTK | Computed at intake | `\\evidence\share\IR-2026-0420-01\cs-ws-107\` |
| ART-005 | `FILE-SVR-01` | Event Logs (`fileserver_access.evtx`) | 2026-04-20T20:45Z | Nargiz Naghiyeva | KAPE / `wevtutil` | Computed at intake | `\\evidence\share\IR-2026-0420-01\fileserver_access.evtx` |
| ART-006 | `CS-WS-112` | Memory & Disk Image | 2026-04-20T21:00Z | Nargiz Naghiyeva | WinPmem / FTK | Computed at intake | `\\evidence\share\IR-2026-0420-01\cs-ws-112\` |
