# 12. The Legacy Systems Risk Assessment

## System 1: Windows XP SP3 (10.10.1.70 - MRI Workstation)

* **EOL Research:**
  * **Critical CVEs (Recent):** Over 100+ critical CVEs published cumulatively since EOL (April 2014). Recent notable CVEs include **CVE-2019-0708 (BlueKeep)** and **CVE-2017-0144 (EternalBlue)**.
  * **Top 2 Critical CVEs:**
    1. **CVE-2017-0144 (EternalBlue):** Remote Code Execution via unauthenticated SMBv1 packets.
    2. **CVE-2019-0708 (BlueKeep):** Unauthenticated Remote Code Execution in Remote Desktop Services (RDP).
* **Permanent Exposure:**
  An EOL system is categorically different from an "unpatched" system because vendors no longer produce security updates, patches, or advisories for newly discovered vulnerabilities. You can never close this risk through patching alone because the vendor code is permanently frozen, leaving zero possibility for vendor-backed security remediation.
* **Scan Findings:**
  * Finding 004 (Windows XP Legacy OS & EternalBlue SMB Vulnerability)
  * Finding 008 (Legacy SMBv1 Protocol Enabled)
  * Finding 018 (Weak RDP Encryption Mechanisms)
  * *Exploitability:* All listed findings are fully exploitable specifically because Microsoft no longer supplies updates to secure the legacy kernel, SMB stack, or RDP implementation.
* **Compensating Controls:**
  * *1x00 Proposed Controls:* Isolated Micro-Segmentation (strict VLAN boundaries), Host-Based IPS, strict perimeter firewall rules blocking inbound SMB (port 445) and RDP (port 3389).
  * *Adequacy:* These controls reduce network exposure, but if an attacker compromises any host on the internal flat network, the MRI workstation remains vulnerable to SMB/RDP lateral movement. Additional controls needed: Disabling SMBv1 entirely, restricting access via 802.1X, and enforcing zero-trust jump servers for maintenance.
* **Business Decision Impact:** High clinical/operational impact, but hardware migration depends on medical vendor certification.

---

## System 2: Windows Server 2012 R2 (10.10.2.31 - Print Server)

* **EOL Research:**
  * **Critical CVEs (Recent):** 50+ critical/high vulnerabilities disclosed since Official Extended Support Ended (October 2023).
  * **Top 2 Critical CVEs:**
    1. **CVE-2023-36884:** Office and Windows HTML Remote Code Execution / Privilege Escalation.
    2. **CVE-2024-21338:** Windows Kernel Elevation of Privilege Vulnerability (used in active exploitation).
* **Permanent Exposure:**
  Unpatched active systems can be remediated with routine patch management cycles. In contrast, EOL systems remain perpetually exposed to every public CVE published after the support lifecycle ends, expanding the attack surface continuously over time.
* **Scan Findings:**
  * Finding 012 (Windows Server 2012 R2 EOL Operating System)
  * Finding 019 (Spooler Service Running on Server Core)
  * Finding 025 (Outdated NetBIOS / LLMNR Resolution Enabled)
  * *Exploitability:* The Print Spooler service vulnerabilities (e.g., PrintNightmare descendants) are unpatchable on this host, allowing local or remote privilege escalation across the domain.
* **Compensating Controls:**
  * *1x00 Proposed Controls:* Disabling the Print Spooler service on non-essential hosts, network segmentation blocking legacy resolution protocols (LLMNR/NetBIOS).
  * *Adequacy:* Completely disabling the Spooler service mitigates PrintNightmare-style exploits, but limits print server functionality. Additional control: Migrating print queues to modern cloud print solutions or updated OS instances.
* **Business Decision Impact:** Lower priority than core medical database systems.

---

## System 3: Ubuntu 18.04 LTS without ESM (10.10.2.15 - Billing Server)

* **EOL Research:**
  * **Critical CVEs (Recent):** 40+ high/critical vulnerabilities since standard support ended (April 2023) without Expanded Security Maintenance (ESM).
  * **Top 2 Critical CVEs:**
    1. **CVE-2023-4911 (Looney Tunables):** Local Privilege Escalation in GNU C Library's dynamic loader (`ld.so`).
    2. **CVE-2024-1086:** Linux Kernel Use-After-Free Privilege Escalation in `netfilter`.
* **Permanent Exposure:**
  Without ESM subscription coverage, the Linux kernel and core base packages cease to receive security backports. An unpatched system can be updated with a single `apt upgrade`, whereas an EOL system without vendor support cannot receive security fixes regardless of maintenance efforts.
* **Scan Findings:**
  * Finding 001 (Apache `mod_lua` Buffer Overflow / RCE)
  * Finding 002 (Local Privilege Escalation via Outdated Kernel)
  * Finding 006 (MySQL Remote Exposure on Legacy Host)
  * Finding 011 (Unsupported Ubuntu OS Release)
  * *Exploitability:* Local kernel privilege escalation (Finding 002) is directly exploitable because security backports are blocked by the lack of ESM/EOL status.
* **Compensating Controls:**
  * *1x00 Proposed Controls:* Restricting SSH access, deploying Web Application Firewalls (WAF) in front of billing web services, isolating database traffic.
  * *Adequacy:* WAF and firewall rules mitigate external network threats, but do not prevent local privilege escalation once an application flaw is exploited. Additional control: Enrolling in Ubuntu ESM immediately as a temporary patch bridge.

---

## Business Decision: Migration Priority

### Selection: **System 3: Ubuntu 18.04 LTS (`billing-srv-01` - Billing Server)**

### Justification:
1. **Asset Criticality (from 1x00):** `billing-srv-01` holds a **Critical** asset rating due to processing sensitive financial transactions, payment card information (PCI-DSS), and medical billing logs.
2. **Threat Exposure & Past History (from 1x01):** Unlike the MRI workstation (isolated in an internal network segment) or the Print Server, `billing-srv-01` has a documented **history of active crypto-miner compromise** and hosts web services accessible internally and externally.
3. **Exploit Chain Threat:** The scan identifies a multi-stage compromise path: an external Apache RCE (Finding 001) combined with an unpatchable Linux kernel local privilege escalation (Finding 002) grants attackers full root access to financial records and database credentials.
4. **Feasibility:** Migrating a Linux web/billing server stack to a modern Ubuntu LTS release (or enabling ESM immediately) is significantly more cost-effective and faster to achieve within one quarter compared to replacing certified medical hardware (MRI scanner).
