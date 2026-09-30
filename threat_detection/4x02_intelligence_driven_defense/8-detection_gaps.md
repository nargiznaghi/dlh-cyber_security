# Detection Gap Analysis - HEALTHBANE Campaign

## 1. Overview & Capability Assessment Methodology

This analysis compares the HEALTHBANE ATT&CK technique mapping against MedDefense's documented SOC detection capabilities, local YARA rules, Suricata/packet signatures, and SIEM telemetry.

Detection statuses are categorized as:
- **DETECTED**: Direct detection via IOC rules, YARA signatures, or automated SIEM alerts.
- **PARTIALLY DETECTED**: Partial coverage via network/endpoint telemetry, requiring analyst manual correlation or lacking contextual alerts.
- **NOT DETECTED**: No automated alert, YARA signature, or reliable telemetry coverage.

---

## 2. Technique Detection Capability Mapping

| ATT&CK ID | Technique Name | Campaign Status | Detection Status | Evidence / Current Coverage | Gap Explanation | Recommendation to Close Gap |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T1583.001** | Acquire Infrastructure: Domains | OBSERVED | **PARTIALLY DETECTED** | Domain IOCs triaged in Task 5 / DNS logs | External domain registration occurs outside perimeter; only visible upon initial lookup | Implement domain reputation monitoring and new domain registration feeds |
| **T1566.002** | Spearphishing Link | OBSERVED | **DETECTED** | Email gateway logs & MedDefense 4x00 IOC rules | Known phishing URLs blocked, but unknown links bypass static filters | Deploy URL rewriting, dynamic sandboxing, and user email reporting buttons |
| **T1566.001** | Spearphishing Attachment | OBSERVED | **DETECTED** | YARA rules (Task 9/10) & attachment filters | Macro attachments flagged; zero-day variants without macros may bypass | Implement attachment sandboxing and restrict `.docm`/macro execution via GPO |
| **T1204.002** | User Execution: Malicious File | INFERRED | **PARTIALLY DETECTED** | Endpoint process creation telemetry (`WS-NURSE-04`) | Execution logged but no proactive automated alert triggered upon macro execution | Deploy EDR rule detecting Office applications spawning interpreter shells |
| **T1059.001** | PowerShell Execution | OBSERVED | **NOT DETECTED** | Standard Windows Event Logs | PowerShell Script Block Logging (Event ID 4104) and AMSI alerts not ingested | Enable PowerShell Script Block Logging and enforce Constrained Language Mode |
| **T1547.001** | Registry Run Keys | OBSERVED | **NOT DETECTED** | Endpoint registry telemetry | No automated alert or YARA rule monitoring `HKCU\...\Run` key modifications | Configure Sysmon Event ID 13 alerts for autostart registry modifications |
| **T1053.005** | Scheduled Task | INFERRED | **NOT DETECTED** | Windows Task Scheduler logs | Task creation (Event ID 4698) logged locally but not forwarded or correlated in SIEM | Ingest Task Scheduler logs (Event 4698) into SIEM with alerts on non-standard paths |
| **T1556** | Modify Authentication Process | OBSERVED | **DETECTED** | MedDefense credential reset logs & 4x00 findings | Phishing portal traffic flagged after initial credential entry report | Enable Mandatory MFA / FIDO2 security keys to neutralize stolen credentials |
| **T1071.001** | Web Protocols (HTTP/HTTPS) | OBSERVED | **DETECTED** | Suricata signatures & perimeter firewall blocks | Known C2 IPs blocked; encrypted traffic without TLS inspection creates potential gaps | Deploy SSL/TLS interception proxies for outbound HTTP traffic inspection |
| **T1071.004** | DNS Protocols | OBSERVED | **NOT DETECTED** | Standard DNS query logs | High-frequency TXT query tunneling to `login-medical-portal.net` not alerted | Deploy SIEM analytics for DNS entropy, TXT record size, and query velocity |
| **T1048.003** | Exfiltration Over Alternative Protocol (DNS) | OBSERVED | **NOT DETECTED** | Perimeter network logs | DNS tunneling bytes/payloads egress without volume-based threshold triggers | Implement DNS firewall with automated rate-limiting and tunneling detection rules |
| **T1020** | Automated Exfiltration | INFERRED | **NOT DETECTED** | Egress traffic logs | Staged automated data transfers blend in with regular outbound background traffic | Enforce outbound data loss prevention (DLP) and anomaly detection on network egress |

---

## 3. Prioritized Gap Analysis

### Priority 1: OBSERVED and NOT DETECTED (Critical Priority)

1. **T1071.004 / T1048.003 - DNS Tunneling & Exfiltration**
   - **Why It Matters**: Threat actors actively use DNS tunneling (`login-medical-portal.net`) to exfiltrate PHI/PII data without triggering standard firewall alerts.
   - **Detection Idea**: Monitor for unusual DNS TXT query volume, long hostname lengths, and high entropy queries per domain.
   - **Required Data Source**: DNS Server Query Logs / Egress PCAP (Sysmon Event ID 22 or Bind/Infoblox DNS logs).
   - **Suggested Owner / Implementation Path**: Network Security Team / SIEM Engineering Team.

2. **T1059.001 - PowerShell Command Execution**
   - **Why It Matters**: Obfuscated PowerShell scripts are used in Stage 2 to decode and execute malicious payloads in memory.
   - **Detection Idea**: Flag PowerShell processes spawned by Microsoft Office products (`winword.exe`, `excel.exe`) or executing with encoded commands (`-Enc`).
   - **Required Data Source**: Windows Event Log 4104 (Script Block Logging) & EDR process logs.
   - **Suggested Owner / Implementation Path**: Endpoint Security / SOC Engineering.

3. **T1547.001 - Registry Run Key Persistence**
   - **Why It Matters**: Attacker maintains persistent access across reboots via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` modifications.
   - **Detection Idea**: Real-time alerts on registry write events targeting Run/RunOnce keys from unassigned processes.
   - **Required Data Source**: Sysmon Event ID 13 (RegistryEvent) or EDR Registry Telemetry.
   - **Suggested Owner / Implementation Path**: SOC Detection Team / Windows Sysadmin.

---

### Priority 2: INFERRED and NOT DETECTED (High Priority)

1. **T1053.005 - Scheduled Task Creation**
   - **Why It Matters**: Secondary persistence and scheduled execution of exfiltration scripts.
   - **Detection Idea**: Alert on Windows Event ID 4698 (A scheduled task was created) where `TaskContent` contains PowerShell or hidden execution flags.
   - **Required Data Source**: Windows Security Event Log (Event ID 4698).
   - **Suggested Owner / Implementation Path**: SIEM Team / SOC Engineering.

2. **T1020 - Automated Data Exfiltration**
   - **Why It Matters**: Automated background data transfer routines risk undetected, massive data loss.
   - **Detection Idea**: Network egress volume anomaly detection for non-standard ports or uncommon external IP destinations.
   - **Required Data Source**: NetFlow / Firewall Egress Telemetry.
   - **Suggested Owner / Implementation Path**: Network Infrastructure & Security Operations.

---

### Priority 3: PARTIALLY DETECTED (Medium Priority)

1. **T1583.001 - Infrastructure Acquisition (Domains)**
   - **Why It Matters**: Early detection of lookalike domains allows proactive blocking before phishing campaigns land.
   - **Detection Idea**: Ingest daily newly registered domain (NRD) feeds and match against company brand keywords (`meddefense`).
   - **Required Data Source**: CTI Domain Feeds / DNS Resolution Telemetry.
   - **Suggested Owner / Implementation Path**: Threat Intelligence Team.

2. **T1204.002 - User Execution (Malicious Files)**
   - **Why It Matters**: Prevent malicious macro execution at the point of user interaction.
   - **Detection Idea**: Correlate user attachment downloads with process execution events.
   - **Required Data Source**: Email Gateway Logs + EDR Process Execution.
   - **Suggested Owner / Implementation Path**: Endpoint Security Team.
