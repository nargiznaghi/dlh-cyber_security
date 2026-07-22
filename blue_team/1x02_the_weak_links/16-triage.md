# 16. The Noise Filter — Vulnerability Triage

## Full Scan Triage (31 Findings)

Finding 001 | 9.8 (Critical) | `billing-srv-01` (10.10.2.15) | Category: AC | Reason: Unauthenticated remote code execution vulnerability in Apache `mod_lua` on a critical billing server processing financial data.
Finding 002 | 7.8 (High) | `billing-srv-01` (10.10.2.15) | Category: AC | Reason: Kernel-level local privilege escalation on EOL Ubuntu 18.04 provides a direct path to root access following remote initial compromise.
Finding 003 | High (Misconfig) | `ehr-db-01` (10.10.2.11) | Category: AC | Reason: PostgreSQL misconfiguration exposes patient records directly to any host on the flat `10.10.0.0/16` network without access controls.
Finding 004 | 8.1 (High) | `WS-RAD-01` (10.10.1.70) | Category: AC | Reason: Unsupported Windows XP workstation running an MRI scanner exposes unpatched EternalBlue (SMBv1) and RDP vulnerabilities to the internal network.
Finding 005 | 7.5 (High) | `web-gateway-01` (10.10.1.10) | Category: AS | Reason: Outdated TLS library implementation on internet-facing patient portal permits fallback to weak ciphers.
Finding 006 | 9.8 (Critical) | `billing-srv-01` (10.10.2.15) | Category: AS | Reason: MySQL database management port is listening on all interfaces with weak default configuration.
Finding 007 | High (Misconfig) | `ad-dc-01` (10.10.2.20) | Category: AC | Reason: Active Directory DC missing LDAP signing enforcement and running SMBv1 allows unauthenticated credential relay and domain compromise.
Finding 008 | Medium (Misconfig) | `WS-RAD-01` (10.10.1.70) | Category: AS | Reason: Legacy SMBv1 protocol enabled on clinical workstation increases susceptibility to lateral movement and wormable exploits.
Finding 009 | 5.3 (Medium) | `billing-srv-01` (10.10.2.15) | Category: I | Reason: Informational version banner disclosure for OpenSSH that requires monitoring but exhibits no active exploit vector.
Finding 010 | 7.5 (High) | BD Alaris PCU (10.10.1.85) | Category: AC | Reason: Vulnerable infusion pump firmware (v12.1.2) lacks dataset integrity validation, posing direct physical risks to patient safety.
Finding 011 | Critical (EOL) | `billing-srv-01` (10.10.2.15) | Category: AS | Reason: Unsupported Ubuntu 18.04 LTS OS requires scheduled migration or enrollment in Extended Security Maintenance (ESM).
Finding 012 | Critical (EOL) | `print-srv-01` (10.10.2.31) | Category: AS | Reason: Windows Server 2012 R2 is past end-of-life and needs planned migration or isolation.
Finding 013 | 5.3 (Medium) | `web-gateway-01` (10.10.1.10) | Category: I | Reason: Server banner reveals specific web server software version to unauthenticated clients.
Finding 014 | Low (Misconfig) | `web-gateway-01` (10.10.1.10) | Category: AS | Reason: Missing security headers (HSTS, CSP, X-Frame-Options) on internet-facing web gateway exposes portal users to client-side attacks.
Finding 015 | 5.3 (Medium) | `web-gateway-01` (10.10.1.10) | Category: I | Reason: HTTP TRACE method enabled, low risk due to modern browser XST mitigations and secure cookie attributes.
Finding 016 | 7.3 (High) | Philips IntelliVue (10.10.1.90) | Category: AC | Reason: Unauthenticated web interface and unencrypted HL7 telemetry streams allow unauthorized monitoring and data tampering on bedside monitors.
Finding 017 | 5.0 (Medium) | `ehr-srv-01` (10.10.2.10) | Category: I | Reason: Apache Tomcat version and directory disclosure, useful for manual investigation but not directly exploitable on its own.
Finding 018 | 6.5 (Medium) | `WS-RAD-01` (10.10.1.70) | Category: AS | Reason: Weak Remote Desktop (RDP) encryption settings permit potential session eavesdropping on internal subnets.
Finding 019 | 7.8 (High) | `print-srv-01` (10.10.2.31) | Category: AS | Reason: Active Print Spooler service running on legacy server core exposes the asset to remote privilege escalation vectors.
Finding 020 | 7.5 (High) | `backup-srv-01` (10.10.3.50) | Category: FP | Reason: OpenSSH CVE-2023-38408 requires SSH-agent forwarding and specific PKCS#11 conditions not active in this host configuration.
Finding 021 | 5.3 (Medium) | `backup-nas-01` (10.10.3.50) | Category: AS | Reason: Weak SSL/TLS ciphers enabled on internal management console require re-configuration to prevent MitM attacks.
Finding 022 | Medium (Warning) | `backup-nas-01` (10.10.3.50) | Category: I | Reason: Untrusted SSL certificate warning caused by internal Enterprise CA missing from scanner trust store.
Finding 023 | Low (Info) | `ad-dc-01` (10.10.2.20) | Category: I | Reason: Standard domain time synchronization service behavior exposed over NTP.
Finding 024 | 5.3 (Medium) | Philips IntelliVue (10.10.1.90) | Category: AS | Reason: Default administrative credentials or cleartext access enabled on device configuration web portal.
Finding 025 | 5.3 (Medium) | `ad-dc-01` (10.10.2.20) | Category: AS | Reason: Outdated NetBIOS name resolution and LLMNR enabled allow internal credential poisoning and relay.
Finding 026 | Low (Info) | `ehr-srv-01` (10.10.2.10) | Category: I | Reason: ICMP timestamp responses enabled on internal application host.
Finding 027 | Low (Info) | `billing-srv-01` (10.10.2.15) | Category: I | Reason: TCP/IP sequence number predictability check passed; low operational risk.
Finding 028 | Low (Info) | `ehr-db-01` (10.10.2.11) | Category: I | Reason: Standard database uptime and version query response.
Finding 029 | 4.3 (Medium) | `print-srv-01` (10.10.2.31) | Category: I | Reason: SMB signing recommended but not enforced on non-critical print asset.
Finding 030 | Medium (Warning) | `ehr-srv-01` (10.10.2.10) | Category: FP | Reason: TLS certificate hostname mismatch is a client IP access issue; certificate is valid for `ehr.meddefense.local`.
Finding 031 | 9.8 (Critical) | `ehr-srv-01` (10.10.2.10) | Category: AC | Reason: Tomcat AJP connector misconfiguration (Ghostcat / CVE-2020-1938) allows unauthenticated remote file read and credential extraction.

---

## Triage Summary

| Category | Count | Action Required |
| :--- | :---: | :--- |
| **Actionable Critical (AC)** | **8** | Immediate remediation (24-48 hours) |
| **Actionable Standard (AS)** | **10** | Scheduled remediation (7-30 days) |
| **Informational (I)** | **11** | Document and monitor |
| **False Positive (FP)** | **2** | Document and dismiss |
| **Total** | **31** | — |

---

## Actionable Findings List (Sorted by Priority)

### Actionable Critical (Immediate Remediation: 24–48 Hours)

1. **Finding 001** (`10.10.2.15` - `billing-srv-01`): Apache `mod_lua` Remote Code Execution (CVE-2021-44790).
2. **Finding 031** (`10.10.2.10` - `ehr-srv-01`): Apache Tomcat AJP Connector Ghostcat File Disclosure (CVE-2020-1938).
3. **Finding 007** (`10.10.2.20` - `ad-dc-01`): Missing LDAP Signing & SMBv1 Enabled on Primary Domain Controller.
4. **Finding 003** (`10.10.2.11` - `ehr-db-01`): Unrestricted PostgreSQL Access from Entire `/16` Subnet.
5. **Finding 004** (`10.10.1.70` - `WS-RAD-01`): Windows XP EternalBlue (CVE-2017-0144) & RDP Vulnerabilities on MRI Scanner Host.
6. **Finding 010** (`10.10.1.85` - BD Alaris PCU): Unpatched Infusion Pump Firmware (v12.1.2) Lacking Guardrails Integrity Validation.
7. **Finding 016** (`10.10.1.90` - Philips IntelliVue): Unauthenticated Monitoring Web Console & Unencrypted HL7 Data Stream.
8. **Finding 002** (`10.10.2.15` - `billing-srv-01`): Linux Kernel Local Privilege Escalation on Billing Host.

### Actionable Standard (Scheduled Remediation: 7–30 Days)

1. **Finding 006** (`10.10.2.15` - `billing-srv-01`): Remote MySQL Database Port Exposed on All Interfaces.
2. **Finding 011** (`10.10.2.15` - `billing-srv-01`): Unsupported Ubuntu 18.04 LTS OS Migration / ESM Bridge.
3. **Finding 012** (`10.10.2.31` - `print-srv-01`): Windows Server 2012 R2 EOL Lifecycle Upgrade Plan.
4. **Finding 019** (`10.10.2.31` - `print-srv-01`): Active Print Spooler Service Enabled on Legacy Domain Member.
5. **Finding 005** (`10.10.1.10` - `web-gateway-01`): Outdated TLS Suite Configuration on External Portal.
6. **Finding 014** (`10.10.1.10` - `web-gateway-01`): Missing HTTP Security Headers (HSTS, CSP, X-Frame-Options).
7. **Finding 025** (`10.10.2.20` - `ad-dc-01`): LLMNR and NetBIOS Legacy Resolution Enabled on DC.
8. **Finding 024** (`10.10.1.90` - Philips IntelliVue): Administrative Credentials Default / Cleartext Access on Monitor.
9. **Finding 008** (`10.10.1.70` - `WS-RAD-01`): Unnecessary SMBv1 Protocol Enabled on Clinical Station.
10. **Finding 021** (`10.10.3.50` - `backup-nas-01`): Weak SSL/TLS Ciphers on Internal Management Portal.
