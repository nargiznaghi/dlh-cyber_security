# Attack Chain Reconstruction: IR-2026-0420-01

## Executive Summary

Incident `IR-2026-0420-01` spans a 72-hour dwell window beginning Thursday morning and culminating in active containment on Sunday at 19:52Z. Telemetry correlation across `proxy_72h.sample.jsonl`, `sysmon_multihost.sample.jsonl`, and `fileserver_access.sample.json` confirms a targeted supply chain and spearphishing intrusion executed by an advanced persistent threat actor. The objective was multi-stage lateral reconnaissance, ePHI harvesting of 1,847 patient records, and staging of ransomware payloads across clinical workstations.

---

## Chronological Attack Phases

| Phase | Time Window | Tactic / Technique (MITRE ATT&CK) | Technical Indicators & Telemetry Evidence |
|---|---|---|---|
| **1. Initial Access** | Thursday (Dwell Day 1) | **T1566.001:** Phishing: Attachment | Spearphishing email delivered to the on-call clinical coordinator containing a malicious Microsoft Word document with an obfuscated VBA macro. |
| **2. Execution & Persistence** | Thursday – Sunday | **T1204.002:** User Interaction: Malicious File<br>**T1543.003:** Create or Modify System Process: Windows Service | Macro execution spawned PowerShell to download a secondary payload. Persistence established via service registration: service name `WinHealthSvc`, binary path `C:\ProgramData\Microsoft\svchost32.exe`. |
| **3. Command & Control (C2)** | Thursday 19:43Z – Sunday 19:38Z | **T1071.001:** Application Layer Protocol: Web Protocols (HTTPS) | Cobalt Strike beaconing activity observed communicating with squatted Microsoft CDN domains and bulletproof hosting IP `193.42.100.77` every 60 seconds with jitter. |
| **4. Lateral Movement & Credential Dumping** | Sunday (Last 12 Hours) | **T1003.001:** OS Credential Dumping: LSASS Memory<br>**T1021.002:** Remote Services: SMB/Windows Admin Shares | Extraction of NTLM credential material enabled lateral movement from `CS-WS-101` to three additional clinical workstations (`CS-WS-104`, `CS-WS-107`, `CS-WS-112`) within a 12-minute window. |
| **5. Data Discovery & Collection** | Sunday ~18:00Z | **T1114:** Email Collection / File and Directory Discovery | Threat actor queried shared drives on the clinical documentation file server (`FILE-SVR-01`), systematically accessing and reading 1,847 patient files, clinical notes, and lab results. |
| **6. Impact Staging** | Sunday ~19:00Z | **T1486:** Data Encrypted for Impact (Staging) | Ransomware staging scripts and encrypted payload binaries deposited into system directories across four workstations (`CS-WS-101`, `CS-WS-104`, `CS-WS-107`, `CS-WS-112`). Execution was intercepted prior to activation. |

---

## Detailed Telemetry Correlation

### Proxy Telemetry (`proxy_72h.sample.jsonl`)
- Outbound HTTPS traffic reveals periodic beacon check-ins from `CS-WS-101` to external infrastructure using User-Agents mimicking standard Windows update utilities, interspersed with high-entropy DNS queries.
- Initial download of the staged payload traced back to external CDN-spoofing domains occurring 72 hours prior to detection.

### Sysmon Telemetry (`sysmon_multihost.sample.jsonl`)
- **Event ID 7 (Image Loaded) & Event ID 1 (Process Creation):** `winword.exe` spawning `powershell.exe -enc` with base64-encoded download cradles.
- **Event ID 7045 (Service Installed):** Registration of `WinHealthSvc` pointing to `C:\ProgramData\Microsoft\svchost32.exe` across `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, and `CS-WS-112`.
- **Network Connections (Event ID 3):** Active connections established between workstation local IPs and external C2 endpoints.

### File Server Access Telemetry (`fileserver_access.sample.json`)
- **Event ID 4624 / 4634 / 4663:** Audit logs show authenticated SMB session from `CS-WS-101` using compromised administrative tokens accessing `\\FILE-SVR-01\Clinical_Docs$\Patient_Records\` resulting in 1,847 successful read operations.
