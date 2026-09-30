# HEALTHBANE Campaign - Cyber Kill Chain Reconstruction

## 1. Campaign Timeline

- **Earliest Known Activity**: February 10, 2026 — Initial registration of threat infrastructure domains (e.g., `meddefense-portal.com`, `outlook-protection.com`).
- **MedDefense Stage 1 Event**: February 18, 2026 — Target employee Diane Marsh (`WS-NURSE-04` / `10.10.2.15`) targeted via credential phishing email; compromised credentials entered at `hxxps://auth-meddefense.com/login.php?id=dmarsh&token=a8f3e2d1`.
- **HC3 Reporting Window**: February 22 – March 1, 2026 — Sector-wide advisory published regarding HEALTHBANE activity across healthcare organizations.
- **Stage 2 Malware Delivery Window**: February 24 – March 3, 2026 — Follow-up phishing campaign leveraging compromised email accounts to distribute malicious Word documents (`.docm`).
- **Stage 3 Exfiltration Window**: March 2 – March 8, 2026 — Execution of DNS tunneling and staging scripts for data exfiltration across victim networks.
- **Most Recent Reported Event**: March 12, 2026 — Last observed operational telemetry and C2 interaction logged before actor rotated domain infrastructure.

---

## 2. Detailed Attack Phases

### Stage 1: Credential Harvesting
- **Phishing Operation**: Spear-phishing emails containing personalized login links disguised as routine HR / IT credential verification prompts.
- **Targeting Pattern**: High-value healthcare personnel, nursing staff, and administrative accounts with access to electronic health record (EHR) systems.
- **Infrastructure Used**: Domains including `meddefense-portal.com`, `medequip-supplies.net`, `verify-med-identity.com`, and `secure-portal-update.com` hosted on `91.234.99.107` and `185.176.43.22`.
- **Known Victims**: MedDefense staff (Diane Marsh / `WS-NURSE-04`) and multiple regional health centers noted in HC3 and researcher reports.
- **MedDefense Evidence**: Endpoint logs from `WS-NURSE-04` showing outbound HTTP connection to phishing landing URL and subsequent account failure alerts.
- **Success Rate**: High (~15-20% click-through rate across targeted organizations based on researcher analysis).

### Stage 2: Malware Delivery
- **Transition Mechanism**: Threat actors accessed compromised internal email mailboxes to send authentic-looking internal reply-chain emails containing malicious attachments.
- **Document Type**: Macro-enabled Microsoft Word documents (`.docm`) disguised as medical invoice updates or policy forms (`INV-2026-04891.pdf` / `.docm`).
- **Malware / Script Artifacts**: VBScript/PowerShell loaders staging execution, decoding payloads, and establishing scheduled tasks.
- **Download Infrastructure**: Domains `healthbane-portal.org` and `healthbane-c2.net` resolving to IP `51.38.42.17`.
- **Persistence Mechanisms**: Registry run keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) and scheduled system tasks running obfuscated PowerShell scripts.
- **Evidence Source**: HC3 Advisory, Researcher Blog, and Commercial Feed payload hash correlations (`a1b2c3d4e5f...`).

### Stage 3: Data Exfiltration
- **Data Targeted**: Protected Health Information (PHI), Personally Identifiable Information (PII), employee credentials, and active directory infrastructure maps.
- **Protocol / Tool Used**: Custom DNS exfiltration binaries using encoded TXT record queries, supplemented by HTTPS POST requests to C2 endpoints.
- **Exfiltration Infrastructure**: Listener IP `203.0.113.88` / `51.38.42.191` and C2 domain `login-medical-portal.net`.
- **Evidence Source**: Commercial Feed threat telemetry and HC3 sector advisory.
- **Confirmed vs Unclear**: Confirmed DNS query tunneling traffic to `login-medical-portal.net`; unclear total volume of PHI exfiltrated prior to containment.

---

## 3. Evidence Quality Assessment

| Attack Phase | Confirmed Evidence | Corroborated Evidence | Inferred Evidence | Unknowns |
| :--- | :--- | :--- | :--- | :--- |
| **Stage 1: Credential Harvesting** | `WS-NURSE-04` network logs, phishing URL, local IP `10.10.2.15` | Lookalike domains (`meddefense-portal.com`), C2 IPs (`91.234.99.107`) across all 4 sources | Initial delivery vector for other regional healthcare victims | Total number of compromised user accounts outside MedDefense |
| **Stage 2: Malware Delivery** | Malicious file SHA256 hashes (`a1b2c3d4e5f...`), macro scripts in researcher analysis | Delivery domain `healthbane-portal.org` present in HC3 & Commercial feed | Lateral movement techniques post-execution | Specific endpoint infection count at non-MedDefense facilities |
| **Stage 3: Data Exfiltration** | C2 listener IPs (`203.0.113.88`), exfiltration domain `login-medical-portal.net` | DNS exfiltration protocol mechanics documented by HC3 & Researcher | Precise staging directories on compromised endpoints | Exact quantity and records of exfiltrated EHR / PHI data |

---

## 4. What Is Not Known & Intelligence Gaps

1. **Attribution Gaps**: 
   - State-sponsored vs Cybercrime motive is unconfirmed. Discrepancies between HC3 (`HEALTHBANE`), Commercial Feed (`VITALSCORE`), and Researcher (`APT-MEDAGENT`) highlight a lack of definitive attribution.
2. **Missing Victim Telemetry**:
   - Visibility is limited beyond MedDefense internal network (`WS-NURSE-04`). Total scope of compromised healthcare facilities nationwide remains unknown.
3. **Incomplete Stage 3 Visibility**:
   - Internal SOC logs lack full packet captures of DNS tunneling sessions, preventing precise inventory of stolen data records.
4. **Commercial Feed Uncertainty**:
   - Commercial feed includes noisy CDN IPs (`172.67.192.40`, `104.21.35.7`) and legitimate domains (`Outlook.com`), creating uncertainty regarding secondary infrastructure.
5. **Collection Needed to Fill Gaps**:
   - Full PCAP / DNS logging on egress firewalls.
   - Forensic disk images from Stage 2 infected endpoints.
   - Cross-agency coordination and ISP-level sinkholing telemetry for C2 listener IPs.
