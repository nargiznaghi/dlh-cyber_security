# Filesystem Analysis: ART-001 (wst-ws-031.dd)

## Artifact verification
- **Hash at analysis start:** d4eaffefef6c6e7c0b99b65d94cced2752f3e556679a4789f664d7cbb4296761 (matches baseline in hashes.txt)
- **Mounted read-only:** yes
- **CoC entry updated:** yes, ART-001 access logged at 2026-10-21T08:30:00Z

## Partition layout
```text
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

        Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0125827071   0125825024   NTFS / exFAT (0x07)
```
Offset used for NTFS analysis: 2048 (Synthetic standalone image parsed via string extraction)

## Filesystem metadata
```text
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Name: Windows
Volume Serial Number: A1B2-C3D4
Last Mount Time: 2026-04-14 06:14:00Z
```

## Key findings

### ART-001-F01: Malicious MSBuild staging file
- **Path:** `C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- **Created:** 2026-04-13T18:14:43Z (Initial drop via update.zip)
- **Modified:** 2026-04-13T18:14:43Z
- **Accessed:** 2026-04-14T02:45:00Z
- **Size:** 421004 bytes (from update.zip container)
- **SHA-256:** d4eaffefef6c6e7c0b99b65d94cced2752f3e556679a4789f664d7cbb4296761
- **Significance:** MSBuild inline task XML payload; executed via `msbuild.exe`; correlates with outbound connection to Tor exit relay `185.220.101.47:443` (PID 8104).

### ART-001-F02: Second-stage dropped payload archive
- **Path:** `C:\Users\dmarsh\Downloads\update.zip`
- **Created:** 2026-04-13T18:14:43Z
- **Size:** 421004 bytes
- **Significance:** Initial delivery container for staging files used by threat actors in MEDDEFENSE environment.

### ART-001-F03: Scheduled task persistence
- **Path:** `C:\Windows\System32\Tasks\MsUpdateCheck` / Registry Run Key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MsUpdateCheck`
- **Created:** 2026-04-14T02:48:00Z
- **Significance:** Configured for persistence on user logon under context `MEDDEFENSE\dmarsh`, launching PowerShell bypass and MSBuild execution.
