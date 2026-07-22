# 14. The Network Posture Analysis

## CVE 1: CVE-2021-44790 (Apache `mod_lua` RCE)

* **CVE:** CVE-2021-44790
* **Host:** `billing-srv-01` (`10.10.2.15`)
* **CVSS Base Score:** 9.8 (Critical)

### Scenario A: Current (Flat Network)
* **Who can reach this vulnerability:** Any host inside the `10.10.0.0/16` network, as well as external traffic hitting port 80.
* **What the attacker can reach AFTER exploitation:** Direct lateral access to all internal workstations, the Active Directory Domain Controller (`10.10.2.20`), the EHR database (`10.10.2.11`), and medical devices (`10.10.1.70`).
* **Effective Risk:** **Critical.**

### Scenario B: Hypothetical (Segmented Network)
* **Who can reach this vulnerability:** Only hosts explicitly permitted within the Finance/DMZ VLAN via internal firewall policy.
* **What the attacker can reach AFTER exploitation:** Strictly confined to the Finance VLAN. Pivoting to Clinical or Database VLANs is blocked by micro-segmentation firewalls.
* **Effective Risk:** **Medium / High** (Contained breach).

* **Risk Amplification Factor:** **High (3x to 5x).** The flat network turns an application-level breach on a billing server into a full internal network compromise.

---

## CVE 2: CVE-2017-0144 (EternalBlue SMBv1 Remote Code Execution)

* **CVE:** CVE-2017-0144
* **Host:** `WS-RAD-01` (`10.10.1.70` - MRI Workstation)
* **CVSS Base Score:** 8.1 (High) / 10.0 (Exploit Context)

### Scenario A: Current (Flat Network)
* **Who can reach this vulnerability:** Every workstation, server, printer, and Wi-Fi client across the entire `10.10.0.0/16` subnet over port 445.
* **What the attacker can reach AFTER exploitation:** The attacker uses the compromised MRI workstation as a launching pad to spread wormable ransomware (e.g., WannaCry) to all connected corporate systems.
* **Effective Risk:** **Critical.**

### Scenario B: Hypothetical (Segmented Network)
* **Who can reach this vulnerability:** Restricted strictly to necessary DICOM/PACS workstations on the Medical Devices VLAN.
* **What the attacker can reach AFTER exploitation:** Isolated strictly within the legacy medical device VLAN. Cannot reach corporate domain controllers, EHR databases, or user workstations.
* **Effective Risk:** **Medium** (Localized operational disruption).

* **Risk Amplification Factor:** **Extreme (10x).** Without isolation, a legacy medical device becomes a network-wide malware broadcaster.

---

## CVE 3: CVE-2020-1938 (Apache Tomcat Ghostcat)

* **CVE:** CVE-2020-1938
* **Host:** `ehr-srv-01` (`10.10.2.10`)
* **CVSS Base Score:** 9.8 (Critical)

### Scenario A: Current (Flat Network)
* **Who can reach this vulnerability:** Port 8009 (AJP) is exposed to all devices in `10.10.0.0/16`, including compromised guest Wi-Fi clients and office PCs.
* **What the attacker can reach AFTER exploitation:** Attackers extract database credentials from application files and connect directly to `ehr-db-01` (`10.10.2.11`) across the flat network to steal patient records.
* **Effective Risk:** **Critical.**

### Scenario B: Hypothetical (Segmented Network)
* **Who can reach this vulnerability:** Port 8009 is restricted exclusively to authorized application gateways or load balancers within the Application Tier.
* **What the attacker can reach AFTER exploitation:** Confined to the Application Server zone; direct connection to the Database VLAN on unauthorized ports is blocked by firewall rules.
* **Effective Risk:** **High** (Limited data exfiltration vector).

* **Risk Amplification Factor:** **High (4x).** The absence of network segmentation permits unauthenticated access to administrative backend ports (AJP) from low-trust user zones.

---

## Network Posture Summary

The flat network architecture acts as a massive risk multiplier across the entire MedDefense scan report. By allowing unrestricted Layer 3 visibility and communication between unrelated subnets (DMZ, Clinical, Medical Devices, Financial, and Identity Management), a single compromised host anywhere on the network immediately yields an unrestricted attack surface against all 31 reported vulnerabilities. Implementing network segmentation is fundamentally more impactful than patching any single CVE because patching only fixes a single vulnerability on a single server, whereas proper network micro-segmentation contains all current and future vulnerabilities—including zero-days, unpatchable legacy systems, and misconfigurations—preventing localized breaches from escalating into total organizational compromise.
