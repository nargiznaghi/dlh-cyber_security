# Persistence Artifact Analysis: ART-001 (wst-ws-031.dd)

## Artifact verification
- **Hash at analysis start:** d4eaffefef6c6e7c0b99b65d94cced2752f3e556679a4789f664d7cbb4296761 (matches baseline in hashes.txt)
- **CoC entry updated:** yes, ART-001 access logged at 2026-10-21T09:05:00Z

## Registry persistence

### ART-001-R01: Run Key Startup Entry
- **Registry Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- **Value Name:** `MsUpdateCheck`
- **Value Data:** `powershell.exe -ep bypass -w hidden -enc <b64> ; msbuild C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- **Last Write Timestamp:** `2026-04-14T02:48:10Z`
- **Forensic Significance:** Ensures automatic execution of the malicious PowerShell loader and MSBuild payload whenever user `dmarsh` logs into the workstation.
- **Evidence ID:** ART-001-R01

### ART-001-R02: Scheduled Task Persistence
- **File Path / Task Path:** `C:\Windows\System32\Tasks\MsUpdateCheck`
- **Trigger:** At logon for user `dmarsh`
- **Action:** Launches `msbuild.exe` pointing to `C:\Users\dmarsh\AppData\Local\Temp\update.xml`
- **Last Write Timestamp:** `2026-04-14T02:48:15Z`
- **Forensic Significance:** Provides robust system-level persistence running under user context, complementing the registry Run key.
- **Evidence ID:** ART-001-R02

## Execution evidence

### ART-001-E01: UserAssist - MSBuild Execution
- **Key Path:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F48-975C-786CB919435E}\Count\...`
- **Value Name:** `MSBuild.exe`
- **Run Count:** 1
- **Last Executed Timestamp:** `2026-04-14T02:50:00Z`
- **Forensic Significance:** Confirms direct interactive or triggered execution of `msbuild.exe` within the user session, matching the SIEM alert timestamp.
- **Evidence ID:** ART-001-E01

### ART-001-E02: Amcache First Execution
- **File Path:** `C:\Windows\AppCompat\Programs\Amcache.hve`
- **Binary:** `C:\Users\dmarsh\AppData\Local\Temp\update.xml` (via MSBuild wrapper)
- **First Execution Timestamp:** `2026-04-14T02:45:15Z`
- **Forensic Significance:** Proves the exact moment the staging file was processed by the system before any log clearing could take place.
- **Evidence ID:** ART-001-E02
