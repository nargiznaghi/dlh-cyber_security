#!/bin/bash
# Task 1: Indicator Triage - HEALTHBANE Campaign

echo "================================================================================"
echo " HEALTHBANE CAMPAIGN - INDICATOR TRIAGE REPORT (TASK 1)"
echo "================================================================================"
echo ""

cat << 'DETAILS'
--------------------------------------------------------------------------------
TRIAGED INDICATORS BREAKDOWN
--------------------------------------------------------------------------------

[1] TYPE: Domain
VALUE: meddefense-portal.com
SOURCES: HC3, Commercial Feed, Researcher Blog, MedDefense 4x00
CATEGORY: ACTIONABLE
JUSTIFICATION: Primary phishing infrastructure targeting MedDefense staff. Active across all 4 intelligence sources.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[2] TYPE: Domain
VALUE: medequip-supplies.net
SOURCES: HC3, Commercial Feed, Researcher Blog, MedDefense 4x00
CATEGORY: ACTIONABLE
JUSTIFICATION: Lookalike domain used in credential phishing campaign and verified across all sources.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[3] TYPE: Domain
VALUE: meddefense-benefits.org
SOURCES: HC3, Commercial Feed, Researcher Blog, MedDefense 4x00
CATEGORY: ACTIONABLE
JUSTIFICATION: Phishing infrastructure impersonating benefits portal. Verified across all sources.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[4] TYPE: Domain
VALUE: outlook-protection.com
SOURCES: HC3, Commercial Feed, Researcher Blog, MedDefense 4x00
CATEGORY: ACTIONABLE
JUSTIFICATION: Sophisticated lookalike domain used to visually impersonate Microsoft Outlook authentication.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[5] TYPE: Domain
VALUE: healthbane-c2.net
SOURCES: HC3, Commercial Feed, Researcher Blog
CATEGORY: ACTIONABLE
JUSTIFICATION: Core Command and Control (C2) server domain associated with HEALTHBANE actor.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[6] TYPE: Domain
VALUE: portal-secure-meddefense.com
SOURCES: HC3, Researcher Blog
CATEGORY: ACTIONABLE
JUSTIFICATION: Secondary phishing infrastructure registered for credential theft.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[7] TYPE: IP Address
VALUE: 91.234.99.107
SOURCES: HC3, Commercial Feed, Researcher Blog, MedDefense 4x00
CATEGORY: ACTIONABLE
JUSTIFICATION: Primary C2 / hosting IP address linked with meddefense-portal.com.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[8] TYPE: IP Address
VALUE: 185.176.43.22
SOURCES: HC3, Commercial Feed, Researcher Blog, MedDefense 4x00
CATEGORY: ACTIONABLE
JUSTIFICATION: Attacker infrastructure hosting phishing endpoints.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[9] TYPE: IP Address
VALUE: 164.90.218.73
SOURCES: HC3, Commercial Feed, Researcher Blog, MedDefense 4x00
CATEGORY: ACTIONABLE
JUSTIFICATION: Malicious IP address tied to campaign infrastructure.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[10] TYPE: IP Address
VALUE: 51.38.42.17
SOURCES: HC3, Commercial Feed, Researcher Blog
CATEGORY: ACTIONABLE
JUSTIFICATION: C2 server infrastructure associated with HEALTHBANE operations.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[11] TYPE: IP Address
VALUE: 51.38.42.191
SOURCES: HC3, Commercial Feed, Researcher Blog
CATEGORY: ACTIONABLE
JUSTIFICATION: Secondary C2 / data staging IP address.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[12] TYPE: Hash (SHA256)
VALUE: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
SOURCES: HC3, Commercial Feed, Researcher Blog
CATEGORY: ACTIONABLE
JUSTIFICATION: Malicious Stage 1 payload/dropper binary hash.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[13] TYPE: Hash (SHA256)
VALUE: c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
SOURCES: HC3, Commercial Feed, Researcher Blog
CATEGORY: ACTIONABLE
JUSTIFICATION: Stage 2 payload hash observed in campaign reports.
CONFIDENCE: HIGH
UNCERTAINTY: FALSE

[14] TYPE: Hash (SHA256)
VALUE: 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f
SOURCES: MedDefense 4x00
CATEGORY: ACTIONABLE
JUSTIFICATION: Malicious lure PDF attachment hash (INV-2026-04891.pdf).
CONFIDENCE: MEDIUM
UNCERTAINTY: FALSE

[15] TYPE: Domain (Non-Malicious / Excluded)
VALUE: hhs.gov
SOURCES: HC3
CATEGORY: NON-ACTIONABLE
JUSTIFICATION: Legitimate US Department of Health and Human Services government domain. False positive risk.
CONFIDENCE: LOW
UNCERTAINTY: TRUE

[16] TYPE: Domain (Non-Malicious / Excluded)
VALUE: Outlook.com
SOURCES: Commercial Feed
CATEGORY: NON-ACTIONABLE
JUSTIFICATION: Legitimate Microsoft webmail domain. Blocking would disrupt legitimate mail services.
CONFIDENCE: LOW
UNCERTAINTY: TRUE

--------------------------------------------------------------------------------
SUMMARY
--------------------------------------------------------------------------------
Total Indicators Triaged: 16
Actionable Indicators: 14
Excluded / Non-Actionable: 2
DETAILS
