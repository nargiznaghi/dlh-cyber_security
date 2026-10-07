# HEALTHBANE Attack Reconstruction Report
**Author:** Nargiz Naghiyeva  
**Date:** 2026-10-08  
**Target Organization:** MedDefense  
**Repository:** dlh-cyber_security / threat_detection / 4x05_attack_reconstruction  

---

## 1. Executive Summary
The HEALTHBANE incident represents a sophisticated, low-and-slow targeted multi-stage attack against MedDefense, originating with spearphishing on March 12, 2026, and culminating in data staging and exfiltration across May 2026. The attacker gained an initial foothold via a credential-harvesting phishing link clicked by employee Diane on workstation `WS-RECV-03`, established a persistent C2 channel (`203.0.113.47`), moved laterally via PsExec (`T1021.002`) to the database server `SRV-HEALTH-DB`, staged patient health records, and successfully exfiltrated 26.0 MB of sensitive data across two distinct batches (`staging_export_001.zip` and `staging_export_002.zip`).

The operation was interrupted on May 12, 2026, when an active threat hunt (`4x04`) detected anomalous administrative share activity, prompting immediate Incident Response isolation of `WS-RECV-03` and full memory/disk forensics. 

* **Key Metrics:**
  * **Total Dwell Time:** 61 days (First access on March 12 to containment on May 12).
  * **Breakout Time:** ~50 days to lateral movement.
  * **Time to Data Staging:** ~56 days.
  * **Time from Detection to Containment:** ~2.25 hours.
  * **ATT&CK Matrix Coverage Improvement:** 40% (Intelligence baseline) $\rightarrow$ 55% (Malware) $\rightarrow$ 80% (Threat Hunt) $\rightarrow$ **95.5% (Final IR Reconstruction)**.

---

## 2. Methodology
* **Evidence Sources:** Integrated across T0 (Evidence Index), T1 (Memory Forensics), T2 (Disk Forensics & $MFT$), T3 (Firewall Logs), T4 (Correlation Matrix), and previous phase summaries (`previous_findings/`).
* **Analytical Approach:** Cross-evidence correlation, rigorous timestamp normalization (UTC), clock-skew adjustments (+4s delta between firewall and host logs), and confidence level assignment (CONFIRMED / PROBABLE / POSSIBLE / CONVERGED).
* **Limitations & Assumptions:** PCAP collection windows were limited to 48 hours, requiring 14-day firewall log correlation to capture exfiltration bursts occurring outside the initial packet capture window.

---

## 3. Attack Reconstruction (Stages 1–4)
* **Stage 1: Initial Access (Phishing):** Spearphishing email delivered on March 12, 2026 (`T1566.001`). Credential harvesting link clicked by Diane on `WS-RECV-03`, leading to credential compromise (`T1078 Valid Accounts`).
* **Stage 2: C2 Establishment:** First HTTPS C2 beacon initiated on May 02, 2026, to `203.0.113.47:443` at 5-minute intervals (`T1071.001`, `T1573.001`). Secondary C2 IP (`198.51.100.89:8443`) appeared later on May 06, indicating backup infrastructure deployment.
* **Stage 3: Malware Deployment:** Deployment of persistence via scheduled task (`HealthSync`, `T1053.005`) executing `C:\Windows\Temp\svchost_update.exe`, alongside credential dumping via debug tools (`T1003.001 LSASS Memory`).
* **Stage 4: Lateral Movement & Data Staging:** Pivot from `WS-RECV-03` to `SRV-HEALTH-DB` via PsExec using compromised service account `svc_healthsync`. Query execution generated `query_results.csv` (8.4 MB), subsequently compressed into `staging_export_001.zip` (14.2 MB) and `staging_export_002.zip` (11.8 MB) on `WS-RECV-03`.

---

## 4. Unified Timeline
* **2026-03-12 09:14:22 UTC:** Phishing email delivered (`T1566.001`, Confirmed).
* **2026-03-12 09:41:05 UTC:** Credential input on lookalike portal (`T1566.001`, Confirmed).
* **2026-05-02 08:14:08 UTC:** First C2 beacon from `WS-RECV-03` (`T1071.001`, Converged).
* **2026-05-05 03:22:14 UTC:** LSASS memory dump execution (`T1003.001`, High).
* **2026-05-06 02:11:42 UTC:** Lateral movement via PsExec (`T1021.002`, High).
* **2026-05-07 01:47:33 UTC:** Scheduled task persistence created (`T1053.005`, High).
* **2026-05-08 02:35:59 UTC:** Staging Exfiltration Batch 1 (14.2 MB) transmitted (`T1041`, High).
* **2026-05-09 03:01:42 UTC:** Security event log cleared (`T1070.001`, Medium).
* **2026-05-11 03:15:09 UTC:** Staging Exfiltration Batch 2 (11.8 MB) transmitted (`T1041`, High).
* **2026-05-12 10:00:00 UTC:** 4x04 Hunt detected anomalous PsExec activity (Confirmed).
* **2026-05-12 12:15:00 UTC:** Incident Response team isolated `WS-RECV-03` (Confirmed).

---

## 5. MITRE ATT&CK Analysis
* **Final Technique Inventory:**
  * `T1566.001` (Spearphishing Link) - Initial Access [Confirmed]
  * `T1078` (Valid Accounts) - Initial Access [Upgraded]
  * `T1003.001` (LSASS Memory) - Credential Access [Converged]
  * `T1021.002` (Admin Shares / PsExec) - Lateral Movement [Confirmed]
  * `T1071.001` (Web Protocols) - Command & Control [Confirmed]
  * `T1053.005` (Scheduled Task) - Persistence [New - T1]
  * `T1074.001` (Local Data Staging) - Collection [New - T2]
  * `T1560.001` (Archive Collected Data) - Collection [New - T2]
  * `T1070.001` (Clear Event Logs) - Defense Evasion [Corrected - T2]
  * `T1005` (Data from Local System) - Collection [New - T7]
  * `T1041` (Exfiltration Over C2) - Exfiltration [Upgraded]

---

## 6. Data Exposure & Regulatory Assessment
* **Data Exposure Summary:** 
  * Patient health records and billing data: **Confirmed Exposed & Exfiltrated** (26.0 MB total across two batches).
  * Employee records: **Potentially Exposed** (`WS-RECV-04` pivot).
* **Regulatory Implications:** Incident meets the mandatory threshold for the HIPAA Breach Notification Rule due to confirmed exfiltration of Protected Health Information (PHI). Estimated scope: ~1,500 - 2,500 patient records.

---

## 7. Defensive Posture & Remediation Plan
* **What Worked:** Proactive threat hunting (`4x04`), memory dumping forensics, and rapid IR isolation within 2.25 hours of detection.
* **What Failed:** Delayed visibility into internal SMB share usage and lack of real-time EDR behavioral blocking on credential dumping tools (`debug_tool.exe`).
* **Remediation Actions:**
  * *Immediate:* Revoke compromised credentials (`svc_healthsync`, `records03`), block C2 IPs (`203.0.113.47`, `198.51.100.89`), and isolate affected endpoints.
  * *Short-term:* Enforce Multi-Factor Authentication (MFA) across all administrative accounts, restrict PsExec execution via AppLocker / WDAC.
  * *Medium-term:* Implement centralized EDR telemetry ingestion and automated network segmentation between workstations and database zones.

---

## 8. Appendices
### Appendix A: IOC Summary Table
| Indicator (IOC) | Type | Evidence Sources | Status |
| :--- | :--- | :--- | :--- |
| `203.0.113.47` | IP (C2) | PCAP, FW, Memory, Wazuh | CONVERGED |
| `198.51.100.89` | IP (Backup C2) | FW Logs | SINGLE-SOURCE |
| `10.10.3.21` | IP (Host) | FW, Disk, Mem, Topology | CONVERGED |
| `debug_tool.exe` | Process | Disk, Prefetch, Memory | CONVERGED |
| `PsExec64.exe` | Process | Prefetch, Evtx, $MFT | CONVERGED |
| `svchost_update.exe` | Process | Registry, $MFT | CONVERGED |
| `hb_cfg.json` | File | Disk ($MFT, Recov) | SINGLE-SOURCE |
| `staging_export_001.zip` | File | $MFT, FW (14.2 MB) | CONVERGED |
| `staging_export_002.zip` | File | $MFT, FW (11.8 MB) | CONVERGED |

### Appendix B: Evidence Citation Index
* `T0`: Evidence Index (`0-evidence_index.sh`)
* `T1`: Memory Analysis (`1-memory_analysis.sh`)
* `T2`: Disk Analysis (`2-disk_analysis.sh`)
* `T3`: Firewall Analysis (`3-firewall_analysis.sh`)
* `T4`: Correlation Matrix (`4-correlation_matrix.sh`)
