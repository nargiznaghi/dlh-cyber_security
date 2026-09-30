# Threat Intelligence Briefing: Campaign HEALTHBANE

**Author**: Nargiz Naghiyeva  
**Target Audience**: MedDefense Leadership (Dr. Morales & Board of Directors) & Healthcare-Sector Partners  
**Classification**: TLP:AMBER (Internal SOC & Trusted Partner Sharing)  
**Date**: September 30, 2026  

---

## 1. Executive Summary

HEALTHBANE is an active, highly targeted cyber threat campaign operating against the healthcare sector to breach Electronic Health Record (EHR) networks and exfiltrate Protected Health Information (PHI). MedDefense experienced a Stage 1 credential harvesting attack targeting endpoint `WS-NURSE-04` (Diane Marsh), where credentials were submitted to a malicious lookalike portal (`auth-meddefense.com`). Across broader healthcare organizations, HEALTHBANE leveraged compromised employee email mailboxes to execute Stage 2 reply-chain phishing with macro-enabled Word documents and Stage 3 DNS tunneling exfiltration. Following immediate incident response actions, MedDefense has successfully contained the initial endpoint exposure, revoked compromised credentials, and deployed targeted YARA and C2 blocking signatures. Our current detection posture is strong against known initial access vectors but requires immediate strengthening around egress DNS tunneling and script execution. We recommend three immediate priority actions: (1) Enforcement of mandatory FIDO2 hardware MFA across all clinical endpoints, (2) Deployment of automated DNS entropy and TXT query length alerting in SIEM, and (3) Full deployment of the newly validated YARA detection arsenal across endpoint EDR nodes.

---

## 2. Adversary Profile

- **Threat Cluster Identifier**: HEALTHBANE (HC3 / Government Primary Standard)
- **Associated Vendor Taxonomies**: `VITALSCORE` (Commercial Vendor), `APT-MEDAGENT` (Researcher Community)
- **Primary Motivation**: Healthcare Sector Reconnaissance, Protected Health Information (PHI) Exfiltration, & Potential Secondary Extortion.
- **Estimated Sophistication**: **Medium-High**. Demonstrates disciplined infrastructure rotation, custom DNS tunneling protocols, lookalike domain typosquatting, and authentic reply-chain phishing tactics.
- **Targeting Scope**: Healthcare infrastructure providers, hospital systems, medical equipment suppliers, and regional clinical networks across North America.

---

## 3. Campaign Analysis

### Three-Stage Campaign Breakdown

1. **Stage 1: Credential Harvesting**
   - **Tactics**: Spear-phishing emails delivering customized links to typosquatting portals (`auth-meddefense.com`, `meddefense-portal.com`).
   - **Local Impact**: Targeted user Diane Marsh (`WS-NURSE-04` / `10.10.2.15`). Credentials submitted to external C2 `91.234.99.107`.
2. **Stage 2: Malware Delivery & Staging**
   - **Tactics**: Accessing compromised mailboxes to inject macro-enabled Word documents (`.docm`) into active internal email threads.
   - **Payload**: Obfuscated VBScript and PowerShell scripts establishing autostart registry keys (`HKCU\...\Run`).
3. **Stage 3: Data Exfiltration**
   - **Tactics**: Automated staging of PHI/PII databases followed by encoded transmission via custom DNS query tunneling.
   - **C2 Infrastructure**: DNS listener domain `login-medical-portal.net` and C2 IP `203.0.113.88`.

### Campaign Timeline
- **Feb 10, 2026**: Infrastructure domain registration (`meddefense-portal.com`).
- **Feb 18, 2026**: MedDefense Stage 1 credential harvest event on `WS-NURSE-04`.
- **Feb 22 – Mar 01, 2026**: HC3 sector-wide advisory published.
- **Feb 24 – Mar 03, 2026**: Stage 2 malicious document campaign observed across regional health partners.
- **Mar 02 – Mar 08, 2026**: Stage 3 DNS exfiltration active across compromised partner networks.

### Evidence Confidence Summary
- **High Confidence**: MedDefense local telemetry (`meddefense_4x00_findings.txt`) and HC3 official advisory (`HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt`).
- **Medium Confidence**: Commercial feed extracts (`commercial_feed_extract.json`) and independent researcher analysis (`researcher_blog_analysis.txt`).

---

## 4. ATT&CK Mapping

The campaign leverages 11 core MITRE ATT&CK techniques categorized by evidence quality:

### Key Techniques
- **Resource Development**: `T1583.001` (Acquire Infrastructure: Domains) — **OBSERVED**
- **Initial Access**: `T1566.002` (Spearphishing Link) — **OBSERVED**; `T1566.001` (Spearphishing Attachment) — **OBSERVED**
- **Execution**: `T1059.001` (PowerShell Execution) — **OBSERVED**; `T1204.002` (User Execution) — **INFERRED**
- **Persistence**: `T1547.001` (Registry Run Keys) — **OBSERVED**; `T1053.005` (Scheduled Task) — **INFERRED**
- **Credential Access**: `T1556` (Modify Authentication Process) — **OBSERVED**
- **Command & Control**: `T1071.001` (Web Protocols) — **OBSERVED**; `T1071.004` (DNS Protocols) — **OBSERVED**
- **Exfiltration**: `T1048.003` (Exfiltration Over DNS) — **OBSERVED**; `T1020` (Automated Exfiltration) — **INFERRED**

### Detection Relevance
Prioritizing detection on **T1071.004** (DNS C2) and **T1059.001** (PowerShell) provides the highest defensive leverage to interrupt the kill chain before data exfiltration completes.

---

## 5. Detection Gap Assessment

Based on our gap analysis (Task 8), MedDefense has identified the following prioritized gaps:

### Priority 1: OBSERVED and NOT DETECTED (Critical Gaps)
1. **T1071.004 / T1048.003 (DNS Tunneling & Data Exfiltration)**
   - *Gap*: Standard DNS query logging lacks automated anomaly detection for payload volume and high-entropy TXT records.
2. **T1059.001 (PowerShell Script Execution)**
   - *Gap*: Windows Event Log 4104 (Script Block Logging) is not ingested into SIEM with automated parent-child process alerts.
3. **T1547.001 (Registry Run Key Modification)**
   - *Gap*: Persistence changes under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` are logged locally but lack real-time SIEM alerts.

### Priority 2: INFERRED and NOT DETECTED (High Priority Gaps)
1. **T1053.005 (Scheduled Task Creation)**
   - *Gap*: Event ID 4698 logging is unindexed in SIEM analytics.
2. **T1020 (Automated Exfiltration Routines)**
   - *Gap*: Network egress thresholds for non-standard protocols lack automated baseline profiling.

---

## 6. Indicator of Compromise (IOC) Table

| Attack Phase | Indicator / Artifact | Type | Confidence | Recommended Action |
| :--- | :--- | :--- | :---: | :--- |
| **Stage 1** | `auth-meddefense.com` | Domain | **HIGH** | Block at DNS / Proxy firewall immediately |
| **Stage 1** | `91.234.99.107` | IPv4 Address | **HIGH** | Ingress & egress firewall drop rule |
| **Stage 1** | `hxxps://auth-meddefense.com/login.php` | URL | **HIGH** | Add to Secure Email Gateway blocklist |
| **Stage 2** | `healthbane-portal.org` | Domain | **HIGH** | DNS sinkhole and perimeter block |
| **Stage 2** | `51.38.42.17` | IPv4 Address | **MEDIUM** | Perimeter firewall drop rule |
| **Stage 2** | `a1b2c3d4e5f...` (SHA256) | File Hash | **HIGH** | Deploy to EDR / Endpoint Antivirus blocklist |
| **Stage 3** | `login-medical-portal.net` | Domain | **HIGH** | Block all DNS resolution & alert SOC |
| **Stage 3** | `203.0.113.88` | IPv4 Address | **HIGH** | Immediate egress firewall block |

---

## 7. YARA Rule Summary

The YARA detection arsenal was systematically validated during Task 11 tests:

| Rule Name | Target Artifact | Test Results (TP/TN/FP/FN) | Precision / Det. Rate | Deployment Status |
| :--- | :--- | :---: | :---: | :---: |
| **`HEALTHBANE_Phishing_PDF`** | PDF lures generated by `wkhtmltopdf` | TP: 2 \| TN: 2 \| FP: 0 \| FN: 0 | 100% / 100% | **DEPLOY** |
| **`HEALTHBANE_Email_Headers`** | Phishing headers & boundary markers | TP: 3 \| TN: 1 \| FP: 0 \| FN: 0 | 100% / 100% | **DEPLOY** |
| **`HEALTHBANE_Campaign_Composite`** | Multi-stage composite script payloads | TP: 3 \| TN: 2 \| FP: 0 \| FN: 0 | 100% / 100% | **DEPLOY** |

---

## 8. Strategic & Tactical Recommendations

### Immediate Actions (Next 48 Hours)
1. Enforce global password reset for user Diane Marsh and audit all clinical accounts connected to `WS-NURSE-04`.
2. Push YARA rules (`9-yara_phishing_pdf.yar` and `10-yara_arsenal.yar`) to all EDR nodes and email security gateways.
3. Block all IOC network indicators (IPs: `91.234.99.107`, `51.38.42.17`, `203.0.113.88`; Domains: `auth-meddefense.com`, `login-medical-portal.net`).

### Short-Term Actions (Next 2 Weeks)
1. Configure SIEM correlation rules for DNS entropy and TXT query length anomalies to detect Stage 3 tunneling.
2. Ingest Windows Script Block Logging (Event ID 4104) and Sysmon Registry Events (Event ID 13) into central SIEM.
3. Conduct targeted spear-phishing refresher training for all clinical and nursing staff.

### Medium-Term Actions (Next 30 Days)
1. Mandate FIDO2 hardware security keys for all staff accessing Electronic Health Records (EHR) to neutralize credential harvesting.
2. Implement egress TLS interception and DLP monitoring on hospital network boundaries.
3. Establish automated threat intelligence feed ingestion with automated vendor-confidence weighting.

---

## 9. Intelligence Gaps & Collection Priorities

1. **Volume of Data Exfiltrated**:
   - *Unknown*: Exact volume and individual patient PHI records staged or transferred via DNS tunneling.
   - *Collection Needed*: Full DNS server query logs and egress firewall PCAP analysis from March 2–8, 2026.
2. **Threat Actor Identity & Attribution**:
   - *Unknown*: Final actor identity (reconciling `HEALTHBANE`, `VITALSCORE`, and `APT-MEDAGENT`).
   - *Collection Needed*: ISP-level sinkhole telemetry and cross-agency intelligence sharing with HC3 / FBI CyWatch.
3. **Secondary Endpoint Infection Scope**:
   - *Unknown*: Potential undetected Stage 2 macro execution on secondary clinical workstations.
   - *Collection Needed*: Enterprise-wide EDR scan utilizing the deployed YARA composite arsenal across all host memory and disk paths.
