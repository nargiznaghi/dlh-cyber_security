# 7. The Cost-Benefit Analysis

## Control Evaluation

### Control 1: Network Segmentation (VLAN Implementation)
* **CIS Control Reference:** CIS Control 12 (Network Infrastructure Management)
* **Annual Cost:** **$15,000**
  * *Breakdown:* Labor cost for network architecture setup & firewall rule maintenance ($15,000/year labor; existing switches/firewalls utilized).
* **Risk(s) Addressed:** Risk 1 (Ransomware Lateral Movement) & Risk 5 (Medical Device Compromise)
* **ALE Reduction:** **$1,484,900** ($2,938,000 pre-control aggregate ALE $\rightarrow$ $1,453,100 post-control ALE)
* **Net Value:** $\$1,484,900 - \$15,000 = \mathbf{\$1,469,900}$
* **Verdict:** Justified
* **Recommendation:** **Implement.** Provides massive risk reduction against lateral ransomware movement at minimal incremental labor cost.

---

### Control 2: MFA Deployment on VPN and Administrative Accounts
* **CIS Control Reference:** CIS Control 6 (Access Control Management)
* **Annual Cost:** **$5,000**
  * *Breakdown:* Utilizing existing Microsoft 365 E3 licenses ($0 licensing fees); internal labor for rollout and FortiGate integration ($5,000/year).
* **Risk(s) Addressed:** Risk 2 (VPN Credential Hijacking & Perimeter Breach)
* **ALE Reduction:** **$3,437,280** ($3,628,240 pre-control ALE $\rightarrow$ $190,960 post-control ALE)
* **Net Value:** $\$3,437,280 - \$5,000 = \mathbf{\$3,432,280}$
* **Verdict:** Justified
* **Recommendation:** **Implement immediately.** Highest return on investment (ROI) across the entire portfolio, leveraging pre-existing software licensing.

---

### Control 3: Enterprise SIEM Deployment (Open-Source Wazuh)
* **CIS Control Reference:** CIS Control 8 (Audit Log Management)
* **Annual Cost:** **$18,000**
  * *Breakdown:* Open-source software licenses ($0); Cloud storage for log retention ($3,000/year); Analyst labor for rule tuning ($15,000/year).
* **Risk(s) Addressed:** Risk 1, Risk 2, Risk 3, Risk 4 (General Lack of Log Visibility)
* **ALE Reduction:** **$120,000** (Provides baseline visibility to detect active attacks early, reducing overall breach impact by ~25%).
* **Net Value:** $\$120,000 - \$18,000 = \mathbf{\$102,000}$
* **Verdict:** Justified
* **Recommendation:** **Implement.** High net value open-source solution that establishes centralized monitoring without prohibitive software licensing costs.

---

### Control 4: Offsite Immutable Backup Replication (AWS S3 Glacier)
* **CIS Control Reference:** CIS Control 11 (Data Recovery)
* **Annual Cost:** **$12,000**
  * *Breakdown:* AWS S3 Object Lock immutable storage fees ($7,000/year); annual restoration drill testing labor ($5,000/year).
* **Risk(s) Addressed:** Risk 1 (Ransomware Backup Destruction)
* **ALE Reduction:** **$1,272,250** (Guarantees database restoration without paying ransom, reducing downtime duration and SLE).
* **Net Value:** $\$1,272,250 - \$12,000 = \mathbf{\$1,260,250}$
* **Verdict:** Justified
* **Recommendation:** **Implement.** Essential safety net that ensures operational recovery during catastrophic ransomware events.

---

### Control 5: Endpoint Detection and Response (EDR) Upgrade (Sophos Intercept X)
* **CIS Control Reference:** CIS Control 10 (Malware Defenses)
* **Annual Cost:** **$22,000**
  * *Breakdown:* Sophos Intercept X Advanced licensing for 300 endpoints/servers ($16,000/year); deployment and agent management labor ($6,000/year).
* **Risk(s) Addressed:** Risk 1 (Ransomware Execution) & Risk 4 (Workstation Malware)
* **ALE Reduction:** **$214,000** (Neutralizes ransomware execution and endpoint malware propagation).
* **Net Value:** $\$214,000 - \$22,000 = \mathbf{\$192,000}$
* **Verdict:** Justified
* **Recommendation:** **Implement.** Upgrades standard antivirus to behavioral detection, blocking active exploit payloads on endpoints.

---

### Control 6: Dedicated Firewall for Westside Clinic
* **CIS Control Reference:** CIS Control 4 (Secure Configuration of Enterprise Assets)
* **Annual Cost:** **$4,000**
  * *Breakdown:* Next-Gen Firewall hardware appliance + security subscription ($2,500/year); installation and setup labor ($1,500/year).
* **Risk(s) Addressed:** Risk 2 (Remote Site Perimeter Compromise)
* **ALE Reduction:** **$45,000** (Eliminates consumer router vulnerabilities at remote clinic branch).
* **Net Value:** $\$45,000 - \$4,000 = \mathbf{\$41,000}$
* **Verdict:** Justified
* **Recommendation:** **Implement.** Highly cost-effective hardware upgrade that hardens perimeter exposure at the branch office.

---

### Control 7: 24/7 Managed SOC Staffing (Outsourced Managed Detection & Response)
* **CIS Control Reference:** CIS Control 13 (Network Monitoring and Defense)
* **Annual Cost:** **$140,000**
  * *Breakdown:* Outsourced MDR service subscription for 300 nodes ($130,000/year); vendor management labor ($10,000/year).
* **Risk(s) Addressed:** Risk 1, Risk 2, Risk 3, Risk 4, Risk 5 (24/7 Threat Detection)
* **ALE Reduction:** **$90,000** (Marginal improvement over open-source Wazuh SIEM + EDR alerting for a small environment).
* **Net Value:** $\$90,000 - \$140,000 = \mathbf{-\$50,000}$
* **Verdict:** Not Justified
* **Recommendation:** **Reject.** Annual cost exceeds total risk reduction and exceeds the hospital's entire $120,000 security budget.

---

### Control 8: Full Medical Device Network Isolation with Dedicated Monitoring
* **CIS Control Reference:** CIS Control 12 (Network Infrastructure Management)
* **Annual Cost:** **$45,000**
  * *Breakdown:* Specialized IoT/Medical security sensor licenses ($35,000/year); dedicated network engineering maintenance ($10,000/year).
* **Risk(s) Addressed:** Risk 5 (BD Alaris Pump Medical Device Compromise)
* **ALE Reduction:** **$33,725** (Reduces Risk 5 ALE from $35,500 down to $1,775).
* **Net Value:** $\$33,725 - \$45,000 = \mathbf{-\$11,275}$
* **Verdict:** Marginal / Not Justified
* **Recommendation:** **Defer / Reject standalone purchase.** Basic VLAN segmentation (Control 1) covers medical isolation at $0 additional software cost; dedicated specialized monitoring is financially unviable.

---

## Cost-Benefit Summary Table

| Rank | Control Description | Annual Cost ($) | ALE Reduction ($) | Net Value ($) | Verdict | Selection Status |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **1** | **MFA Deployment (VPN & Admin)** | $5,000 | $3,437,280 | **$3,432,280** | Justified | **Selected (Budget)** |
| **2** | **Network Segmentation (VLANs)** | $15,000 | $1,484,900 | **$1,469,900** | Justified | **Selected (Budget)** |
| **3** | **Offsite Immutable Backups (AWS)** | $12,000 | $1,272,250 | **$1,260,250** | Justified | **Selected (Budget)** |
| **4** | **EDR Upgrade (Sophos Intercept X)** | $22,000 | $214,000 | **$192,000** | Justified | **Selected (Budget)** |
| **5** | **Wazuh Open-Source SIEM** | $18,000 | $120,000 | **$102,000** | Justified | **Selected (Budget)** |
| **6** | **Westside Clinic Dedicated Firewall** | $4,000 | $45,000 | **$41,000** | Justified | **Selected (Budget)** |
| **7** | **Medical Device Dedicated Monitoring** | $45,000 | $33,725 | **-$11,275** | Not Justified | Rejected |
| **8** | **24/7 Managed SOC Staffing** | $140,000 | $90,000 | **-$50,000** | Not Justified | Rejected |

---

## $120,000 Annual Budget Allocation Breakdown

By rejecting financially unjustified controls (Control 7 and Control 8), MedDefense can implement **all six justified security controls** while remaining well within its **$120,000 annual budget limit**:

1. **MFA Deployment:** $5,000
2. **Network Segmentation:** $15,000
3. **Offsite Immutable Backups:** $12,000
4. **EDR Upgrade (Sophos Intercept X):** $22,000
5. **Open-Source Wazuh SIEM:** $18,000
6. **Westside Clinic Firewall:** $4,000

* **Total Approved Implementation Cost:** **$76,000 / year**
* **Remaining Budget Reserve:** **$44,000 / year** (Allocated for security awareness training programs, incident response retainers, or emergency buffer).
* **Total Risk Reduction Achieved:** **$6,573,430 / year in ALE reduction** for an investment of $76,000.
