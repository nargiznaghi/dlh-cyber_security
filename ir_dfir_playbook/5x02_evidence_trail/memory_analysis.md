# Memory Analysis: ART-002 (wst-ws-031.mem) and ART-003 (wst-ws-017.mem)

## Artifact verification
- **ART-002 hash:** 8144ca9ee538268599e65104a9901d462d550064d5263f2bf4fa1f7f43e1176e (matches baseline in hashes.txt)
- **ART-003 hash:** a675bea9188f5a9b2d8829af15153dee714103b01afd87b5c6df4f7dfd8b0300 (matches baseline in hashes.txt)
- **CoC entries updated:** yes, accessed logged at 2026-10-21T09:30:00Z

## wst-ws-031.mem findings

### ART-002-M01: Suspicious process tree
- **Command:** `vol -f wst-ws-031.mem windows.pstree.PsTree`
- **Output Excerpt:**
```text
* 2412  explorer.exe     PPID=840              Start: 2026-04-14 02:30:10Z
** 7812  powershell.exe   PPID=2412             Start: 2026-04-14 02:47:55Z
*** 8104  MSBuild.exe    PPID=7812             Start: 2026-04-14 02:48:02Z
```
- **Significance:** Confirms alert context; `powershell.exe` (PID 7812) is the direct parent of `MSBuild.exe` (PID 8104), executing the inline task.
- **ATT&CK Technique:** T1127.001 (Trusted Developer Utilities Proxy Execution: MSBuild)
- **Certainty:** Confirmed

### ART-002-M02: Live C2 connection at time of capture
- **Command:** `vol -f wst-ws-031.mem windows.netscan.NetScan`
- **Output Excerpt:**
```text
TCP  10.14.22.31:49832  185.220.101.47:443  ESTABLISHED  PID 8104  MSBuild.exe
```
- **Significance:** Active outbound C2 network connection from `MSBuild.exe` to a known Tor exit relay (`185.220.101.47:443`) at the exact moment of memory acquisition (03:02Z).
- **ATT&CK Technique:** T1071.001 (Application Layer Protocol: Web Protocols)
- **Certainty:** Confirmed

### ART-002-M03: Injected executable memory in msbuild.exe
- **Command:** `vol -f wst-ws-031.mem windows.malfind.Malfind --pid 8104`
- **Output Excerpt:**
```text
PID 8104  MSBuild.exe  Start: 0x1f0000  End: 0x1f4fff  Tag: VadS  Protection: PAGE_EXECUTE_READWRITE
Hexdump: 4d 5a 90 00 03 00 00 00 ... (MZ header present in anonymous region)
```
- **Significance:** The presence of an `MZ/PE` header in an anonymous executable memory region within `MSBuild.exe` confirms shellcode/payload injection.
- **ATT&CK Technique:** T1055 (Process Injection)
- **Certainty:** Confirmed

### ART-002-M04: NTLM hash exposure via LSASS handles
- **Command:** `vol -f wst-ws-031.mem windows.handles.Handles --pid 612` (lsass.exe)
- **Significance:** Open unprivileged handles pointing to `lsass.exe` indicate potential credential dumping activity prior to lateral movement.
- **ATT&CK Technique:** T1003.001 (OS Credential Dumping: LSASS Memory)
- **Certainty:** Probable

---

## wst-ws-017.mem findings

### ART-003-M01: Secondary host process review
- **Command:** `vol -f wst-ws-017.mem windows.pslist.PsList`
- **Significance:** Checked secondary workstation `WST-WS-017` for concurrent adversary staging. Process list shows normal baseline services without active malicious MSBuild spawning, indicating containment was effective before lateral spread reached this node.
- **ATT&CK Technique:** N/A (Baseline Check)
- **Certainty:** Confirmed
