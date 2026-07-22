# 6. The ALE Workshop: Quantitative Risk & Control Investment

## Risk 1: Ransomware Encrypts ePHI Database & EHR System

* **Source:** GAP-003 (Flat Network) + Finding 003 (PostgreSQL Unrestricted Access) + Threat Actor: BlackReef Ransomware Group
* **Asset:** `ehr-db-01` (ePHI Database Cluster)
* **Asset Value (AV):** **$9,675,000**
  * *Replacement/recovery cost:* $150,000 (forensics, database rebuild, incident response)
  * *Revenue loss during downtime:* $30,000/day $\times$ 14 days = $420,000
  * *Regulatory penalties:* $250,000 (HIPAA violation fines)
  * *Reputation/patient trust impact:* $8,855,000 (class-action lawsuits, notification, long-term patient attrition)
* **Exposure Factor (EF):** **100% (1.0)**
  * *Reasoning:* Ransomware encryption of the core database causes complete loss of availability and triggers full regulatory/reputational liabilities.
* **SLE:** $\$9,675,000 \times 1.0 = \mathbf{\$9,675,000}$
* **ARO:** **0.30** (Once every 3.3 years)
  * *Reasoning:* Healthcare ransomware frequency baselines combined with MedDefense's flat network, unpatched legacy systems, and unisolated backups.
* **ALE:** $\$9,675,000 \times 0.30 = \mathbf{\$2,902,500}$
* **Proposed Control:** Deploy network segmentation (VLANs/ACLs), immutable air-gapped backups, and automated endpoint detection (EDR).
* **Control Annual Cost:** $80,000
* **Estimated ALE After Control:** **$145,125** (New ARO drops to 0.03, EF drops to 50% due to rapid immutable backup restoration).
* **Net Benefit:** $\$2,902,500 - \$145,125 - \$80,000 = \mathbf{\$2,677,375/\text{year}}$

---

## Risk 2: Perimeter Breach via Credential Hijacking on Unprotected FortiGate VPN

* **Source:** GAP-004 (Missing MFA) + Finding 004 (Single-Factor Remote Auth) + Threat Actor: Credential Brokers / External Attackers
* **Asset:** `fg-edge-01` (FortiGate Perimeter Gateway)
* **Asset Value (AV):** **$9,548,000**
  * *Replacement/recovery cost:* $75,000
  * *Revenue loss during downtime:* $20,000/day $\times$ 10 days = $200,000
  * *Regulatory penalties:* $200,000
  * *Reputation/patient trust impact:* $9,073,000 (Aggregate lateral movement impact touching ePHI & billing)
* **Exposure Factor (EF):** **100% (1.0)**
  * *Reasoning:* Compromising the sole perimeter gateway grants full internal network access across all three hospital sites.
* **SLE:** $\$9,548,000 \times 1.0 = \mathbf{\$9,548,000}$
* **ARO:** **0.38** (38% annual probability)
  * *Reasoning:* VPN credential compromise is the #1 initial access vector in healthcare attacks (38% of incidents).
* **ALE:** $\$9,548,000 \times 0.38 = \mathbf{\$3,628,240}$
* **Proposed Control:** Enforce mandatory Multi-Factor Authentication (MFA) across all VPN and remote access points.
* **Control Annual Cost:** $15,000
* **Estimated ALE After Control:** **$190,960** (New ARO drops to 0.02 as credential-stuffing attacks are effectively neutralized).
* **Net Benefit:** $\$3,628,240 - \$190,960 - \$15,000 = \mathbf{\$3,422,280/\text{year}}$

---

## Risk 3: Automated Exploitation of Unpatched Critical OS & Web Vulnerabilities

* **Source:** GAP-002 (Unpatched Systems) + Finding 001/002 (Outdated Apache/OS CVEs) + Threat Actor: Opportunistic Cybercrime Syndicates
* **Asset:** `billing-srv-01` (Billing Operations Server)
* **Asset Value (AV):** **$473,000**
  * *Replacement/recovery cost:* $85,000
  * *Revenue loss during downtime:* $16,000/day $\times$ 18 days = $288,000
  * *Regulatory penalties:* $100,000
  * *Reputation/patient trust impact:* Negligible relative to ePHI breaches ($0)
* **Exposure Factor (EF):** **100% (1.0)**
  * *Reasoning:* Publicly known exploits targeting unpatched web servers allow remote code execution, disabling billing services.
* **SLE:** $\$473,000 \times 1.0 = \mathbf{\$473,000}$
* **ARO:** **0.50** (Once every 2 years)
  * *Reasoning:* High frequency of public exploit kits actively scanning healthcare IP ranges for known CVEs.
* **ALE:** $\$473,000 \times 0.50 = \mathbf{\$236,500}$
* **Proposed Control:** Implement automated 30-day vulnerability patch management and Web Application Firewall (WAF).
* **Control Annual Cost:** $25,000
* **Estimated ALE After Control:** **$23,650** (New ARO drops to 0.05).
* **Net Benefit:** $\$236,500 - \$23,650 - \$25,000 = \mathbf{\$187,850/\text{year}}$

---

## Risk 4: Unmonitored Clinical Staff Negligence & Data Theft via Workstations

* **Source:** GAP-008 (Lack of Training/DLP) + Finding 008 (Phishing / Unrestricted Removable Media) + Threat Actor: Negligent Insiders
* **Asset:** Clinical Workstation Fleet (280 Endpoints)
* **Asset Value (AV):** **$120,000** (per incident)
  * *Replacement/recovery cost:* $30,000 (investigation) + $25,000 (containment) = $55,000
  * *Revenue loss during downtime:* Minimal ($0)
  * *Regulatory penalties:* $25,000
  * *Reputation/patient trust impact:* $40,000
* **Exposure Factor (EF):** **100% (1.0)**
  * *Reasoning:* Each successful phishing or USB data theft incident incurs standard remediation and notification costs.
* **SLE:** $\$120,000 \times 1.0 = \mathbf{\$120,000}$
* **ARO:** **2.50** (2 to 3 incidents per year)
  * *Reasoning:* 2,000 untrained staff with no USB restrictions, no DLP, and shared domain accounts.
* **ALE:** $\$120,000 \times 2.50 = \mathbf{\$300,000}$
* **Proposed Control:** Implement Endpoint USB restrictions, GPO hardening, security awareness training, and phishing simulation.
* **Control Annual Cost:** $20,000
* **Estimated ALE After Control:** **$36,000** (New ARO drops to 0.30).
* **Net Benefit:** $\$300,000 - \$36,000 - \$20,000 = \mathbf{\$244,000/\text{year}}$

---

## Risk 5: Malicious Tampering or Denial-of-Service on Networked Medical Devices

* **Source:** GAP-003 (Flat Network) + Finding 010 (Default Credentials on BD Alaris Pumps) + Threat Actor: Opportunistic Network Scanning Attackers
* **Asset:** BD Alaris Infusion Pumps (7 Units + Network Interface)
* **Asset Value (AV):** **$355,000**
  * *Replacement/recovery cost:* $105,000 (7 replacement units @ $15k)
  * *Revenue loss during downtime:* $20,000/day $\times$ 5 days = $100,000 (manual dosing operational delay)
  * *Regulatory penalties:* $150,000 (FDA mandatory breach investigation)
  * *Reputation/patient trust impact:* Uncalculated patient safety liability
* **Exposure Factor (EF):** **100% (1.0)**
  * *Reasoning:* Exploiting default credentials allows attackers to reflash or disable infusion pumps across the subnet.
* **SLE:** $\$355,000 \times 1.0 = \mathbf{\$355,000}$
* **ARO:** **0.10** (Once every 10 years)
  * *Reasoning:* Low likelihood of direct targeted attack, but flat network visibility makes opportunistic DoS plausible.
* **ALE:** $\$355,000 \times 0.10 = \mathbf{\$35,500}$
* **Proposed Control:** Change default administrative passwords and isolate medical devices into a dedicated, air-gapped VLAN.
* **Control Annual Cost:** $5,000
* **Estimated ALE After Control:** **$1,775** (New ARO drops to 0.005).
* **Net Benefit:** $\$35,500 - \$1,775 - \$5,000 = \mathbf{\$28,725/\text{year}}$

---

## Risk Prioritization by ALE

| Rank | Risk Description | Initial ALE ($/year) | Proposed Control | Control Cost ($) | Post-Control ALE ($) | Net Annual Benefit ($) |
| :---: | :--- | :---: | :--- | :---: | :---: | :---: |
| **1** | **VPN Credential Hijacking & Perimeter Breach** | $3,628,240 | Mandatory MFA Enforcement | $15,000 | $190,960 | **$3,422,280** |
| **2** | **Ransomware Encryption of ePHI Database** | $2,902,500 | Network Segmentation & Immutable Backups | $80,000 | $145,125 | **$2,677,375** |
| **3** | **Clinical Workstation Phishing & Insider Data Theft** | $300,000 | USB Blocking & Security Training | $20,000 | $36,000 | **$244,000** |
| **4** | **Automated Vulnerability Exploitation on Billing Server** | $236,500 | Patch Management Pipeline & WAF | $25,000 | $23,650 | **$187,850** |
| **5** | **Medical Device Compromise (BD Alaris Pumps)** | $35,500 | Credential Change & Medical VLAN Isolation | $5,000 | $1,775 | **$28,725** |
