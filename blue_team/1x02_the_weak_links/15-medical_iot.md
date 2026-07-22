# 15. Medical IoT Analysis

## 1. BD Alaris Assessment

* **Vulnerability Description:** 
  The BD Alaris System (PCU Model 8015 v12.1.3 and prior; Guardrails Editor v12.1.2 and prior) contains multiple disclosed vulnerabilities. Notable flaws include **CVE-2023-30562** (Lack of Dataset Integrity Checking in Guardrails Editor), **CVE-2023-30560** (Unauthenticated PCU Configuration Modification via physical interface), and **CVE-2023-30563** (Stored XSS in Systems Manager). Exploitation can allow unauthorized modification of Guardrails drug library datasets, system configuration tampering, or session hijacking.

* **Vendor Recommendations & Mitigations:**
  * **Software Update:** Upgrade PCU firmware to version 12.1.4+ and Guardrails Editor to version 12.1.3+.
  * **Network Isolation:** Segregate BD Alaris PCUs and Systems Manager servers onto an isolated, dedicated Virtual LAN (VLAN) with strict ingress/egress filtering.
  * **Operational Controls:** Physically secure PCUs to prevent unauthorized USB/serial access and mandate manual dataset integrity confirmation on the PCU display prior to infusion activation.

* **MedDefense Implementation Status:**
  **Not Implemented.** MedDefense continues to run vulnerable firmware (v12.1.2) across its infusion pump fleet on a shared, flat network (`10.10.0.0/16`). No VLAN isolation or dataset verification controls have been established.

---

## 2. Philips IntelliVue Assessment

* **Exposed Data & Protocols:**
  * **Unauthenticated Web Interface (HTTP/80):** Exposes device status, system logs, network settings, and hardware telemetry to any unauthenticated client on the internal network.
  * **Unencrypted HL7 / Patient Monitoring Ports (TCP/2575 & Custom Ports):** Transmits raw, unencrypted Health Level 7 (HL7) data feeds containing Protected Health Information (PHI) and Real-Time Vital Signs (e.g., patient name, medical record number, ECG, SpO2, blood pressure streams).

* **Attacker Capabilities:**
  An attacker with network-level access inside the flat network can:
  * **Eavesdrop / Intercept (Eavesdropping & Privacy Breach):** Sniff unencrypted HL7 feeds to steal PHI and real-time patient physiological data.
  * **Tamper with Patient Telemetry (Data Manipulation):** Perform Man-in-the-Middle (MitM) or spoofing attacks to inject false vital sign data (e.g., faking cardiac arrest or normal vitals) into Central Monitoring Stations or EHR systems (`ehr-srv-01`).
  * **Denial of Service (Operational Disruption):** Send malformed requests to crash the embedded monitoring interface, blinding clinical staff to patient physiological distress.

---

## 3. Patient Safety Dimension

Medical IoT vulnerabilities reside in a fundamentally different risk category than standard IT system vulnerabilities because exploitation directly threatens physical human life rather than digital assets or financial data. While compromising a corporate workstation leads to data confidentiality loss or business interruption, compromising a connected medical device directly impairs physiological care. In a worst-case scenario, an IT workstation breach results in stolen credentials or ransomware encryption; conversely, a compromised infusion pump or bedside monitor allows an adversary to alter drug dosage rates, delay critical alarms, or trigger lethal overdoses, directly causing patient mortality.

---

## 4. Remediation Challenges

Patching medical devices presents unique operational and regulatory complexities compared to standard enterprise IT patching:

1. **Regulatory Re-Certification Requirements:**
   Modifying medical device software or operating environments often requires rigorous validation to comply with FDA (or equivalent international) regulatory clearances. Unapproved patches can void vendor warranties, invalidate medical certifications, or create legal liability for the healthcare provider.

2. **Continuous Availability & Operational Dependencies:**
   Medical devices are actively integrated into clinical workflows 24/7/365. Taking devices offline for updates requires complex clinical scheduling, device rotation, and manual physical maintenance, as over-the-air (OTA) patching is rarely supported on embedded clinical hardware.

3. **Heavy Vendor Dependency & Legacy Embedded Systems:**
   Hospitals are entirely reliant on original equipment manufacturers (OEMs) to develop and release patches for proprietary firmware. Many medical devices run end-of-life embedded operating systems (e.g., Windows CE, embedded Linux) for which vendors no longer supply security updates, forcing healthcare organizations to rely exclusively on compensating network controls.
