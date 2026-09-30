# Task 0: The Intelligence Intake - HEALTHBANE Campaign

## 1. Source Intake Summaries

### Source 1: HC3 Advisory
* **Source Name:** HHS HC3 Sector Threat Advisory (HC3-2026-HEALTHBANE-001)
* **Source Type:** government advisory
* **Publish Date:** 2026-04-25
* **TLP Classification:** TLP:CLEAR
* **Indicator Count:** 23
* **Indicator Types:** domains (8), IPs (6), file hashes (5), URLs (4)
* **One-Line Summary:** Formal sector advisory detailing the multi-stage HEALTHBANE campaign targeting US healthcare providers via phishing, macro-enabled documents, and DNS exfiltration.
* **Key Limitations / Caveats:** Observational scope is limited to 6 partner organizations; low confidence in threat actor attribution.

### Source 2: Commercial Threat Feed (commercial_feed_extract.json)
* **Source Name:** commercial_feed_extract.json (Acme CTI Commercial Feed)
* **Source Type:** commercial feed
* **Publish Date:** 2026-04-26
* **TLP Classification:** TLP:AMBER
* **Indicator Count:** 41
* **Indicator Types:** domains, IPs, hashes, URLs
* **One-Line Summary:** Automated CTI feed aggregation tracking healthcare-targeted indicators under the proprietary attribution tag "VITALSCORE".
* **Key Limitations / Caveats:** High proportion of automated ingestion noise; indicators are only sample-reviewed by analysts, leading to potential false positives.

### Source 3: Researcher Blog Analysis
* **Source Name:** Personal Research Blog - Marcus Weller (@mwresearch)
* **Source Type:** open-source research
* **Publish Date:** 2026-04-24
* **TLP Classification:** TLP:CLEAR (Public Blog)
* **Indicator Count:** 14
* **Indicator Types:** domains (5), IPs (3), file hashes (4), URLs (2)
* **One-Line Summary:** Independent technical analysis analyzing a recovered PHP phishing kit and linking infrastructure to historical campaign patterns (APT-MEDAGENT / VITALSCORE).
* **Key Limitations / Caveats:** Written by a solo researcher lacking victim-side enterprise telemetry; attribution relies entirely on open-source infrastructure patterns.

### Source 4: MedDefense 4x00 Findings
* **Source Name:** MedDefense Health Systems Internal Investigation (Project 4x00)
* **Source Type:** internal investigation
* **Publish Date:** 2026-04-16
* **TLP Classification:** INTERNAL / TLP:RED
* **Indicator Count:** 11
* **Indicator Types:** domains (3), IPs (3), file hashes (1), URLs (1), email addresses (3)
* **One-Line Summary:** First-party forensic investigation confirming Stage 1 spear-phishing emails and potential credential exposure of a MedDefense staff member.
* **Key Limitations / Caveats:** Strictly scoped to local environment telemetry during the early Stage 1 timeline; no network packet or endpoint forensics included.

---

## 2. Consolidated Intelligence View

### Indicator Statistics
* **Total Raw Indicators Across All Sources:** 89
  * *HC3 Advisory:* 23
  * *commercial_feed_extract.json:* 41
  * *Researcher Blog:* 14
  * *MedDefense 4x00:* 11
* **Total Unique Indicators (Post-Deduplication):** 64
* **Indicators Appearing in Multiple Sources:** 16
* **Indicators Appearing in Only One Source:** 48

---

## 3. Conflict Identification & Source Discrepancies

1. **Attribution Discrepancies:**
   * **HC3 Advisory** labels the campaign **HEALTHBANE** and explicitly states that attribution to a named threat group is **UNCONFIRMED** (Low Confidence).
   * **commercial_feed_extract.json (Commercial Feed)** tracks the activity under its proprietary tag **VITALSCORE**.
   * **Researcher Blog** attributes the activity to **APT-MEDAGENT** based on tool reuse (PHPMailer 6.6.0, Njalla/Namecheap infrastructure, config patterns).

2. **Temporal Discrepancies:**
   * **MedDefense 4x00** recorded local activity between **2026-04-14 and 2026-04-16** (Stage 1 only).
   * **HC3 Advisory** tracks campaign progression through **2026-04-26** (covering Stage 2 delivery and Stage 3 DNS exfiltration).

3. **Data Completeness & Noise:**
   * **commercial_feed_extract.json** contains automated feed noise, including low-confidence indicators not observed by HC3 or internal forensics.
   * High-fidelity internal context (specific target email accounts and customized landing URLs like `id=dmarsh&token=a8f3e2d1`) is present solely in the **MedDefense 4x00** report.
