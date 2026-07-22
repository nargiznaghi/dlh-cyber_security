# 8. The Budget Game: Strategic Resource Allocation

## Part 1 - The Selection ($120,000 Budget Allocation)

MedDefense has been allocated a strict annual cybersecurity budget of **$120,000**. Based on quantitative cost-benefit analysis and risk prioritization, the funding strategy focuses on maximizing risk reduction per dollar spent.

### Funded Controls (Primary Recommendation)

1. **MFA Deployment on VPN & Administrative Accounts**
   * **Cost:** $5,000
   * **Reasoning:** Eliminates the single largest attack vector (#1 remote breach path) using existing Microsoft 365 E3 licenses. Yields an ALE reduction of $3,437,280.
2. **Network Segmentation (VLANs & Access Control Lists)**
   * **Cost:** $15,000
   * **Reasoning:** Prevents lateral movement of ransomware across servers, workstations, and medical device networks. Yields an ALE reduction of $1,484,900.
3. **Offsite Immutable Backup Replication (AWS S3 Glacier with Object Lock)**
   * **Cost:** $12,000
   * **Reasoning:** Guarantees business continuity and operational recovery from catastrophic ransomware without paying extortion demands. Yields an ALE reduction of $1,272,250.
4. **Endpoint Detection and Response (EDR) Upgrade (Sophos Intercept X)**
   * **Cost:** $22,000
   * **Reasoning:** Replaces basic legacy antivirus with behavioral ransomware blocking across 300 endpoints. Yields an ALE reduction of $214,000.
5. **Enterprise Open-Source SIEM Deployment (Wazuh)**
   * **Cost:** $18,000
   * **Reasoning:** Establishes centralized audit log collection, alert aggregation, and baseline visibility for the security team. Yields an ALE reduction of $120,000.
6. **Dedicated Next-Gen Firewall for Westside Clinic**
   * **Cost:** $4,000
   * **Reasoning:** Replaces a consumer-grade router at a remote clinical site with an enterprise security appliance. Yields an ALE reduction of $45,000.

---

### Deferred Controls (Next Fiscal Year / Phase 2)

* **Security Awareness & Phishing Simulation Program**
  * **Estimated Cost:** $15,000
  * **Reasoning:** Deferred to FY2027 to allow core technical controls (MFA, Segmentation, EDR) to be fully implemented first.

---

### Rejected Controls

1. **24/7 Managed SOC Staffing (Outsourced MDR)**
   * **Annual Cost:** $140,000
   * **Reasoning:** Financial unfeasibility. The annual cost exceeds the entire $120,000 security budget while providing marginal extra risk reduction over open-source Wazuh SIEM + EDR alerting.
2. **Full Medical Device Network Isolation with Dedicated Monitoring**
   * **Annual Cost:** $45,000
   * **Reasoning:** Negative net value (-$11,275). Network segmentation (Control 1) already isolates medical devices into dedicated VLANs at $0 added software cost.

---

### Budget Summary Table

| Metric | Amount ($) |
| :--- | :---: |
| **Total Annual Budget** | **$120,000** |
| **Total Funded Spend** | **$76,000** |
| **Remaining Budget Reserve (Unallocated Buffer)** | **$44,000** |
| **Total Annual Risk Exposure Reduction (ALE Reduced)** | **$6,573,430** |

*Note: The $44,000 unallocated reserve is retained for incident response retainers, emergency patching hardware, or unforeseen compliance auditing expenses.*

---

## Part 2 - The Opportunity Cost

Every unfunded or deferred control leaves residual risk on the table. The opportunity cost of delaying controls expresses the unaddressed ALE accepted by MedDefense leadership:

1. **Deferring 24/7 Managed SOC Staffing:**
   * **Opportunity Cost:** By deferring an outsourced 24/7 Managed SOC, MedDefense accepts an estimated **$90,000** in unaddressed annual risk exposure related to off-hours threat detection latency (partially compensated by automated EDR blocking and Wazuh alert rules).
2. **Rejecting Dedicated Medical Device Monitoring Sensors:**
   * **Opportunity Cost:** By rejecting specialized medical device monitoring software, MedDefense accepts an estimated **$1,775** in residual annual risk exposure for medical devices (effectively mitigated to acceptable levels via VLAN segmentation).
3. **Deferring Formal Security Awareness Training Platform:**
   * **Opportunity Cost:** By deferring dedicated phishing simulation software, MedDefense accepts an estimated **$36,000** in residual annual risk exposure from clinical staff credential handling and negligent insider mistakes.

---

## Part 3 - The Alternative Allocation Strategy

### Alternative Allocation (Aggressive Operational Expansion)

An alternative proposal evaluates spending the entire $120,000 budget by adding a outsourced 24/7 SOC lite tier and formal security awareness training, while dropping the EDR upgrade and offsite backups:

* **MFA Deployment:** $5,000
* **Network Segmentation:** $15,000
* **Wazuh SIEM Deployment:** $18,000
* **Westside Clinic Firewall:** $4,000
* **Security Awareness Training Platform:** $15,000
* **Outsourced SOC Lite (12/5 Coverage):** $63,000
* **Total Cost:** **$120,000** (0 Reserve)

### Comparative Analysis: Primary Recommendation vs. Alternative Allocation

| Parameter | Primary Recommendation | Alternative Allocation |
| :--- | :---: | :---: |
| **Total Funded Cost** | **$76,000** | **$120,000** |
| **Budget Reserve Maintained** | **$44,000** | **$0** |
| **Total Risk Reduction (ALE Reduced)** | **$6,573,430** | **$5,112,000** |
| **Ransomware Recovery Assurance** | **High** (Immutable AWS Backups) | **Low** (No Immutable Offsite Backup) |
| **Endpoint Threat Prevention** | **High** (Sophos Intercept X EDR) | **Low** (Legacy Antivirus) |
| **Financial Net Efficiency** | **Highest ($86.49 ALE saved per $ spent)** | **Lower ($42.60 ALE saved per $ spent)** |

### Conclusion & Final Recommendation
The **Primary Recommendation ($76,000 spend)** is vastly superior. It delivers **$1.46 Million MORE in total risk reduction** while spending **$44,000 LESS**, leaving a crucial financial contingency reserve for MedDefense.
