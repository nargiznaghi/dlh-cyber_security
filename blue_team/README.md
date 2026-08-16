# Blue Team

Cybersecurity defensive operations and blue team study materials. Covers threat intelligence, vulnerability management, cryptography, security frameworks, regulatory compliance, and practical defense tooling through a scenario-driven case study approach centered on MedDefense, a fictional healthcare organization.

> **Parent repository:** [`dlh-cyber_security`](https://github.com/nargiznaghi/dlh-cyber_security) · **This directory:** [`blue_team`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team)

---

## Repository Structure

### Scenario Modules

The curriculum follows a progressive learning path through ten modules across two series, each building on the previous:

#### Part 1 — Foundations (Modules 1–6)

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 1 | [`1x00_first_watch`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/1x00_first_watch) | SOC fundamentals, incident classification, asset discovery, control gap analysis, and security posture assessment | 18 |
| 2 | [`1x01_know_your_enemy`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/1x01_know_your_enemy) | Threat intelligence, ransomware (RaaS) analysis, insider threats, social engineering, supply chain risks, and MITRE ATT&CK mapping | 19 |
| 3 | [`1x02_the_weak_links`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/1x02_the_weak_links) | Vulnerability management, CVE/CVSS/CWE analysis, exploit hunting, misconfiguration discovery, Lynis auditing, OSINT reconnaissance, and remediation prioritization | 24 |
| 4 | [`1x03_defense_blueprint`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/1x03_defense_blueprint) | Security architecture planning, defense-in-depth strategies, ALE/risk quantification, control evaluation, budget allocation, network segmentation design, and adversarial red-team validation | 11 |
| 5 | [`1x04_crypto_foundation`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/1x04_crypto_foundation) | Symmetric/asymmetric encryption (AES, RSA, ECC, ChaCha20-Poly1305), hashing, digital signatures, PKI/certificate management, TLS hardening, disk encryption (LUKS), steganography as a threat vector, and key management (TPM/HSM) | 14 |
| 6 | [`1x05_board_briefing`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/1x05_board_briefing) | Executive synthesis: Crimson Tide attack chain overlay, control interception mapping, gap analysis, crypto emergency assessment, budget ROI analysis, and technical proficiency demonstration | 6 |

#### Part 2 — Applied Hardening (Modules 7–10)

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 7 | [`2x00_locking_the_gates`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/2x00_locking_the_gates) | Linux infrastructure hardening: baseline security snapshots, CIS control profiling, Lynis audit integration, evidence-based remediation queuing, SSH hardening, PAM fortress configuration, auditd deployment, log management (rsyslog), and host firewall baselines | 14 |
| 8 | [`2x01_windows_fortress`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/2x01_windows_fortress) | Windows endpoint hardening: security posture assessment, domain reconnaissance, GPO deployment for password/lockout policies, advanced audit policy, PowerShell security logging, Kerberos/authentication hardening, Sysmon, AppLocker, Windows Firewall lockdown, RDP security, and service account control | 15 |
| 9 | [`2x02_eyes_on_endpoint`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/2x02_eyes_on_endpoint) | EDR deployment, Sysmon configuration and telemetry validation, ATT&CK coverage matrix, PowerShell logging validation, and auditd rule refinement | 16 |
| 10 | [`2x03_patch_equation`](https://github.com/nargiznaghi/dlh-cyber_security/tree/main/blue_team/2x03_patch_equation) | Vulnerability management lifecycle, patch prioritization, deployment strategies, and compliance scanning | 16 |

---

## 📚 Study Hub & Reference Resources

All learning objectives, cheat sheets, frameworks, and reference materials are systematically maintained in the Study Hub:

🔗 🔗 **[Access the Defensive Security Study Hub](https://nishtman-k.github.io/cyber-study-hub/?tab=defensive)**

> 📌 **Maintainer Note:** The **Defensive Security** section within the Study Hub is managed and regularly updated by **[@nargiznaghi](https://github.com/nargiznaghi)**.

| Resource Category | Description & Focus |
|-------------------|---------------------|
| **Learning Objectives** | Weekly structured competency goals and evaluation criteria for each module. |
| **Cheat Sheets & Guides** | Quick-reference command recipes, configurations, and syntax breakdowns. |
| **Framework Guidance** | Strategic mapping to NIST CSF 2.0, CIS Controls v8, and MITRE ATT&CK. |
| **System Baselines** | Hardening benchmarks and audit policy references for Linux and Windows infrastructure. |

---

## Case Study: MedDefense

The scenario modules are built around MedDefense, a healthcare organization facing realistic security challenges. Learners take on the role of a security analyst working through incremental security incidents and defense implementations.

Supporting characters (e.g., James Chen, Marcus) and realistic artifacts (network scans, diagnostic outputs, breach summaries, CFO pushback documents) create an immersive, hands-on learning environment.

---

## Alignment with Certifications & Frameworks

This repository supports preparation for:

- **CompTIA Security+ (SY0-701)** — Core security fundamentals and defensive operations
- **CompTIA CySA+ (CS0-003)** — Threat detection, analysis, and response
- **NIST Cybersecurity Framework (CSF 2.0)** — Implementation and alignment guidance
- **HIPAA Security Rule** — Healthcare regulatory compliance fundamentals
- **CIS Controls v8** — Prioritized security best practices
- **MITRE ATT&CK Framework** — Adversary tactics, techniques, and procedures mapping
