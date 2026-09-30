# MITRE ATT&CK Campaign Mapping & Navigator Summary

## 1. Campaign Techniques by Tactic

### Resource Development
- **Technique ID**: T1583.001
- **Technique Name**: Acquire Infrastructure: Domains
- **Classification**: OBSERVED
- **Evidence / Reasoning**: Registration and deployment of lookalike domains (`meddefense-portal.com`, `outlook-protection.com`, `medequip-supplies.net`).
- **Source**: HC3 Advisory, Researcher Blog, Commercial Feed
- **Attack Phase**: Stage 1 Credential Harvesting

### Initial Access
- **Technique ID**: T1566.002
- **Technique Name**: Phishing: Spearphishing Link
- **Classification**: OBSERVED
- **Evidence / Reasoning**: Targeted email sent to Diane Marsh (`WS-NURSE-04`) containing a credential harvesting URL (`auth-meddefense.com`).
- **Source**: MedDefense 4x00 Findings, Commercial Feed
- **Attack Phase**: Stage 1 Credential Harvesting

- **Technique ID**: T1566.001
- **Technique Name**: Phishing: Spearphishing Attachment
- **Classification**: OBSERVED
- **Evidence / Reasoning**: Macro-enabled Word documents (`.docm`) delivered via reply-chain phishing emails.
- **Source**: HC3 Advisory, Commercial Feed, Researcher Blog
- **Attack Phase**: Stage 2 Malware Delivery

### Execution
- **Technique ID**: T1204.002
- **Technique Name**: User Execution: Malicious File
- **Classification**: INFERRED
- **Evidence / Reasoning**: Execution of Stage 2 payloads requires victim opening the attached malicious document and enabling macros.
- **Source**: Researcher Blog
- **Attack Phase**: Stage 2 Malware Delivery

- **Technique ID**: T1059.001
- **Technique Name**: Command and Scripting Interpreter: PowerShell
- **Classification**: OBSERVED
- **Evidence / Reasoning**: Obfuscated PowerShell scripts executed during Stage 2 loader execution.
- **Source**: Researcher Blog, HC3 Advisory
- **Attack Phase**: Stage 2 Malware Delivery

### Persistence
- **Technique ID**: T1547.001
- **Technique Name**: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **Classification**: OBSERVED
- **Evidence / Reasoning**: Persistence established via registry modifications under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- **Source**: Researcher Blog
- **Attack Phase**: Stage 2 Malware Delivery

- **Technique ID**: T1053.005
- **Technique Name**: Scheduled Task/Job: Scheduled Task
- **Classification**: INFERRED
- **Evidence / Reasoning**: Persistence mechanisms in similar HEALTHBANE payloads leverage scheduled tasks for elevated execution.
- **Source**: Researcher Blog, HC3 Advisory
- **Attack Phase**: Stage 2 Malware Delivery

### Credential Access
- **Technique ID**: T1556
- **Technique Name**: Modify Authentication Process
- **Classification**: OBSERVED
- **Evidence / Reasoning**: Credential harvesting phishing portals collecting user credentials via fake OAuth / login pages.
- **Source**: MedDefense 4x00 Findings, Researcher Blog
- **Attack Phase**: Stage 1 Credential Harvesting

### Command and Control
- **Technique ID**: T1071.001
- **Technique Name**: Application Layer Protocol: Web Protocols (HTTP/HTTPS)
- **Classification**: OBSERVED
- **Evidence / Reasoning**: Outbound HTTP/HTTPS traffic logged to C2 server IP `91.234.99.107` and domain `healthbane-portal.org`.
- **Source**: HC3 Advisory, Commercial Feed, MedDefense 4x00
- **Attack Phase**: Stage 1 & Stage 2

- **Technique ID**: T1071.004
- **Technique Name**: Application Layer Protocol: DNS
- **Classification**: OBSERVED
- **Evidence / Reasoning**: Tunneling DNS queries sent to domain `login-medical-portal.net` for data staging and C2 fallback.
- **Source**: HC3 Advisory, Commercial Feed
- **Attack Phase**: Stage 3 Data Exfiltration

### Exfiltration
- **Technique ID**: T1048.003
- **Technique Name**: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Encrypted Non-Application Layer Protocol
- **Classification**: OBSERVED
- **Evidence / Reasoning**: DNS tunneling utilized to exfiltrate encoded data payloads outside the network perimeter.
- **Source**: HC3 Advisory, Commercial Feed
- **Attack Phase**: Stage 3 Data Exfiltration

- **Technique ID**: T1020
- **Technique Name**: Automated Exfiltration
- **Classification**: INFERRED
- **Evidence / Reasoning**: Automated staging scripts gather systemic data and transmit at recurring intervals without analyst intervention.
- **Source**: Researcher Blog
- **Attack Phase**: Stage 3 Data Exfiltration

---

## 2. ATT&CK Navigator Mapping Summary

1. **Total Techniques Identified**: 11 techniques across 7 tactics.
2. **Observed vs Inferred Ratio**: 8 OBSERVED : 3 INFERRED (72.7% Observed, 27.3% Inferred).
3. **Tactics with Most Coverage**: Initial Access (2 techniques), Command and Control (2 techniques), Execution (2 techniques), Persistence (2 techniques).
4. **Tactics with Least Coverage**: Privilege Escalation (0 techniques), Defense Evasion (0 techniques confirmed), Lateral Movement (0 techniques confirmed).
5. **Key Techniques for Detection Planning**:
   - **T1566.002 / T1566.001 (Phishing)**: Implement strict email gateway filtering and lookalike domain detection.
   - **T1071.004 / T1048.003 (DNS Tunneling & C2)**: Monitor high-entropy / abnormal TXT record DNS queries to unexpected external endpoints (`login-medical-portal.net`).
   - **T1059.001 (PowerShell Execution)**: Enforce Script Block Logging (Event ID 4104) and monitor suspicious child processes spawned from Office applications.
