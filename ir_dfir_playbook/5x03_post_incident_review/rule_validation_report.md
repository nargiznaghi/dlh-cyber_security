# Detection Rule Validation Report: IR-2026-0414-01

## 1. Executive Summary

This validation report evaluates the performance of the created Sigma detection rule (`sigma_powershell_msbuild_lolbin.yml`) against real incident Sysmon logs (`incident_sysmon.jsonl`) and a 30-day baseline log dataset (`clean_sysmon.jsonl`) from MedDefense clinical workstations.

The validation objective is to ensure high sensitivity against true attack behaviors while maintaining an acceptable false positive rate (target: <0.1%) across production baselines.

---

## 2. Dataset Overview

| Dataset | File | Event Count | Description / Context |
| :--- | :--- | :--- | :--- |
| **Incident Sample** | `incident_sysmon.jsonl` | Real Incident Logs | Sysmon process creation and network connection events from `WST-WS-031` and `WST-WS-017` during the incident window (02:40Z to 04:00Z on 2026-04-14). |
| **Clean Baseline** | `clean_sysmon.jsonl` | 30-Day Baseline Logs | Representative clinical workstation class baseline at MedDefense (includes developers running legitimate builds via Visual Studio and MSBuild). |

---

## 3. Rule Performance Results

### Rule: `sigma_powershell_msbuild_lolbin.yml`

- **Incident Sample Validation:**
  - **Matched Events:** 2
  - **Match Rate:** High sensitivity (100% detection of the adversary's `powershell.exe` -> `MSBuild.exe` execution chain on `WST-WS-031` and `WST-WS-017`).
  - **Fired on Attack Data:** **YES**

- **Clean Baseline Validation:**
  - **Matched Events:** 0
  - **Match Rate:** 0.00%
  - **False Positive Target (<0.1%):** **PASSED**

---

## 4. False Positive Analysis & Tuning Decisions

- **Observed False Positives:** Zero false positives were identified in the clean clinical baseline for PowerShell spawning MSBuild directly.
- **Tuning Actions Required:** No tuning was required as the clean baseline match rate (0.00%) was well below the 0.1% threshold.
- **Production Status:** The rule `sigma_powershell_msbuild_lolbin.yml` is validated and ready for production deployment in SIEM/EDR detection engines.
