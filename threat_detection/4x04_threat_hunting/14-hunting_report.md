# Threat Hunting Report: HEALTHBANE Stage 4 Operations
**Author:** Nargiz Naghiyeva  
**Date:** 2026-10-07  
**Repository:** dlh-cyber_security  
**Directory:** threat_detection/4x04_threat_hunting  
**Target Audience:** SOC Technical Team & Dr. Morales (CISO / Executive Board)

---

## 1. Executive Summary
This comprehensive threat hunting report addresses the MedDefense Healthcare Systems security investigation regarding **HEALTHBane Stage 4 Threat Hunting**. 

* **What was hunted and why:** Following HC3 advisories regarding HEALTHBane campaign activities, a proactive threat hunt was initiated to uncover undetected lateral movement, credential dumping, and service account exploitation within the `meddefense.local` domain.
* **Key Finding:** **YES, HEALTHBANE STAGE 4 HAPPENED.** The investigation confirmed unauthorized lateral movement, LSASS memory scraping via `debug_tool.exe`, and severe service account (`svc_healthsync`) abuse originating from workstation endpoints.
* **Impact Assessment:** The adversary successfully reached workstation pivot points (`WS-FINANCE-04`) and targeted internal database and domain infrastructure (`DC-01`, `SRV-HEALTH-DB`), creating a high-risk exposure vector for HIPAA-protected Patient Health Records (PHI).
* **Remediation Status:** New Wazuh and network detection rules were successfully drafted and deployed. Overall ATT&CK framework detection coverage improved from **55% to 80%**.

---

## 2. Hunt Methodology
The investigation followed a rigorous hypothesis-driven threat hunting framework:
1. **Intelligence & Advisory Integration:** Leveraged HC3 threat intelligence and ATT&CK matrix mappings to construct specific hunt hypotheses (H1 through H5).
2. **Telemetry & Data Sources:** Analyzed 14 days of normalized SIEM exports (`wazuh_alerts_14d.json`), raw Sysmon logs (`wazuh_raw_sysmon_14d.json`), and baseline activity profiles (`robert_kim_activity.json`).
3. **Baseline Establishment:** Utilized Robert Kim’s legitimate IT administrative schedule (`08:00 - 18:00`, Monday–Saturday, `WS-ADMIN-01`) and the Service Account Authorization Matrix (`reference/service_accounts.txt`) to isolate deviations as absolute anomalies.

---

## 3. Findings per Hypothesis (H1 through H5)

| Hypothesis | Description | Status | Evidence Summary | Confidence |
| :--- | :--- | :--- | :--- | :--- |
| **H1** | PsExec Lateral Movement | **CONFIRMED** | `psexesvc.exe` execution from `WS-FINANCE-04` during off-hours targeting DC infrastructure. | **HIGH** |
| **H2** | Credential Access (LSASS) | **CONFIRMED** | `C:\Windows\Temp\debug_tool.exe` targeting `lsass.exe` (Sysmon Event ID 10). | **HIGH** |
| **H3** | WMI Remote Execution | **CONFIRMED** | Unauthorized process creation spawned via `WmiPrvSE.exe` outside maintenance windows. | **HIGH** |
| **H4** | PowerShell Remoting | **CONFIRMED** | WinRM lateral sessions leveraged from standard workstation subnets. | **HIGH** |
| **H5** | Service Account Abuse | **CONFIRMED** | 6 workstation-originated logons for `svc_healthsync` violating Matrix Rule 1 + NTLM use. | **HIGH** |

---

## 4. Reconstructed Attack Timeline
* **[2026-05-04T00:05:30Z]** Dataset telemetry window opens; initial reconnaissance and environment mapping.
* **[2026-05-10T02:14:33Z]** **Credential Access:** Execution of `C:\Windows\Temp\debug_tool.exe` scraping `lsass.exe` memory on `WS-FINANCE-04` (Sysmon EID 10).
* **[2026-05-10T02:30:00Z]** **Service Account Abuse:** Compromised high-risk service account `svc_healthsync` authenticates from workstation `WS-FINANCE-04` (6 events violating authorization boundaries).
* **[2026-05-10T02:45:00Z]** **Lateral Movement:** PsExec service execution (`psexesvc.exe`, PID 4212) initiated toward internal domain controllers and database targets.
* **[2026-05-18T14:11:06Z]** Dataset collection window concludes; containment protocols initiated.

---

## 5. ATT&CK Update & Visualization
* **Coverage Improvement:** Increased from **55%** (reactive baseline) to **80%** (proactive detection coverage).
* **Newly Covered Techniques:**
  * `T1003.001` (OS Credential Dumping: LSASS Memory)
  * `T1569.002` (System Services: PsExec)
  * `T1078.002` (Valid Accounts: Domain Accounts)
  * `T1047` (Windows Management Instrumentation)

---

## 6. Detection Improvements & Gap Closure
New local Wazuh and network rules deployed to close identified gaps:
* **Rule 100201 (PsExec Alert):** Detects PsExec execution originating from workstation endpoints.
* **Rule 100202 (LSASS Access):** Flags memory access to `lsass.exe` from non-system binaries.
* **Rule 100203 (Service Account Matrix Enforcement):** Alerts on `svc_*` accounts authenticating from `WS-*` hosts.
* **Rule 100204 (WMI Child Process):** Identifies anomalous child processes spawned by `WmiPrvSE.exe`.
* **Suricata SMB Rule 900101:** Detects `PSEXESVC` binary transmission over network shares.

---

## 7. Remaining Gaps and Recommendations
* **Remaining 20% Gap:** Advanced encrypted PowerShell obfuscation and deep kernel-level driver tampering.
* **Immediate Actions:** Execute incident response playbooks for workstation endpoint `WS-RECV-03` (Module 5 bridge connection).
* **Short-Term Actions:** Rotate all service account passwords (especially `svc_healthsync`), enforce gMSA where applicable, and conduct a full privileged access review.
* **Medium-Term Actions:** Implement enterprise-wide Sysmon deployment paired with behavioral UEBA (User and Entity Behavior Analytics).

---

## 8. Lessons Learned
1. **False Sense of Security:** Relying solely on a 55% reactive ATT&CK coverage model allowed sophisticated LOLBin (Living off the Land) attacks to pass completely unalerted.
2. **Failure of Reactive-Only Detection:** Signature-based alerts failed because attackers utilized custom binaries (`debug_tool.exe`) and legitimate administrative tools (`PsExec`, `WMI`) against their intended design.
3. **The Necessity of Threat Hunting:** Proactive threat hunting must be institutionalized as a recurring operational discipline to catch compromises that bypass perimeter controls.

---
**REPORT SIGN-OFF:**  
*Nargiz Naghiyeva (Threat Hunter)*  
*Dr. Morales (CISO - Approved)*
