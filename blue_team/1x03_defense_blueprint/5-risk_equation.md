# 5. Quantitative Risk Analysis & The Risk Equation

## Scenario 1: Ransomware Attack on Billing Server (`billing-srv-01`)

### 1. Asset Value (AV)
* **Reasoning:** Total financial exposure of the billing service includes operational revenue loss, technical recovery, and HIPAA regulatory fines.
  * **Direct Downtime Loss:** 18 days $\times$ $16,000/day = $288,000
  * **Recovery & Incident Support:** $85,000
  * **HIPAA Penalty (Mid-range):** $100,000
  * **Total AV:** $288,000 + $85,000 + $100,000 = **$473,000**

### 2. Exposure Factor (EF)
* **Reasoning:** **1.0 (100%)**. A ransomware attack encrypting `billing-srv-01` completely halts billing operations, triggering 100% of the calculated downtime, recovery, and regulatory compliance costs.

### 3. Single Loss Expectancy (SLE)
* **Calculation:** $$\text{SLE} = \text{AV} \times \text{EF} = \$473,000 \times 1.0 = \mathbf{\$473,000}$$

### 4. Annualized Rate of Occurrence (ARO)
* **Reasoning:** **0.285** (Approximately 1 attack every 3.5 years based on sector baseline intelligence of 1 attack every 3 to 4 years).

### 5. Annualized Loss Expectancy (ALE)
* **Calculation:** $$\text{ALE} = \text{SLE} \times \text{ARO} = \$473,000 \times 0.285 = \mathbf{\$134,805}$$

### 6. Confidence Level & Key Sensitivity
* **Confidence Level:** **Medium**
* **Key Assumption Sensitivity:** The estimated downtime duration (18 days). If MedDefense's unisolated backups cause recovery to extend to 30 days, downtime loss increases to $480,000, driving the SLE to $665,000 and pushing the ALE above $189,500.

---

## Scenario 2: Patient Data Breach via EHR System (`ehr-srv-01` & `ehr-db-01`)

### 1. Asset Value (AV)
* **Reasoning:** Total economic impact of exfiltrating 50,000 electronic protected health information (ePHI) records.
  * **Record Exfiltration Loss:** 50,000 records $\times$ $165/record = $8,250,000
  * **Breach Notification & Credit Monitoring:** $25,000
  * **Litigation & Legal Defense Exposure:** $200,000
  * **Reputational Loss / Patient Attrition:** $600,000
  * **Total AV:** $8,250,000 + $25,000 + $200,000 + $600,000 = **$9,075,000**

### 2. Exposure Factor (EF)
* **Reasoning:** **1.0 (100%)**. Exfiltration of the primary EHR database compromises the entire repository, triggering full regulatory, legal, and reputational liabilities.

### 3. Single Loss Expectancy (SLE)
* **Calculation:** $$\text{SLE} = \text{AV} \times \text{EF} = \$9,075,000 \times 1.0 = \mathbf{\$9,075,000}$$

### 4. Annualized Rate of Occurrence (ARO)
* **Reasoning:** **0.33** (1 breach every 3 years). Given that MedDefense operates a flat network with no SIEM and missing patches, its vulnerability profile is significantly higher than average sector baselines.

### 5. Annualized Loss Expectancy (ALE)
* **Calculation:** $$\text{ALE} = \text{SLE} \times \text{ARO} = \$9,075,000 \times 0.33 = \mathbf{\$2,994,750}$$

### 6. Confidence Level & Key Sensitivity
* **Confidence Level:** **Medium-High**
* **Key Assumption Sensitivity:** Cost per breached healthcare record ($165). If class-action litigation increases per-record damages or patient attrition reaches 10%, the total loss scales linearly into tens of millions.

---

## Scenario 3: Negligent Insider Data Theft

### 1. Asset Value (AV)
* **Reasoning:** Average cost of a single negligent insider security incident in healthcare, including investigation ($30,000), containment ($25,000), remediation ($40,000), and regulatory reporting ($25,000).
  * **Total AV per Incident:** **$120,000**

### 2. Exposure Factor (EF)
* **Reasoning:** **1.0 (100%)**. Each individual negligent event incurs the baseline operational, containment, and regulatory response expenditure.

### 3. Single Loss Expectancy (SLE)
* **Calculation:** $$\text{SLE} = \text{AV} \times \text{EF} = \$120,000 \times 1.0 = \mathbf{\$120,000}$$

### 4. Annualized Rate of Occurrence (ARO)
* **Reasoning:** **2.5** incidents per year. Across 2,000 employees and 280 workstations with no DLP, no USB blocking, shared accounts, and zero formal training, 2 to 3 negligent incidents per year are expected.

### 5. Annualized Loss Expectancy (ALE)
* **Calculation:** $$\text{ALE} = \text{SLE} \times \text{ARO} = \$120,000 \times 2.5 = \mathbf{\$300,000}$$

### 6. Confidence Level & Key Sensitivity
* **Confidence Level:** **High**
* **Key Assumption Sensitivity:** Estimated incident frequency (2.5/year). Implementing basic USB restrictions and endpoint DLP via GPO would drastically reduce the ARO to 0.5, cutting the annual expected loss by $240,000.

---

## Scenario 4: Medical Device Compromise (BD Alaris Infusion Pumps)

### Option A: Operational Denial-of-Service (DoS)
1. **Asset Value (AV):** Operational disruption (5 days $\times$ $20,000/day = $100,000) + FDA investigation costs ($150,000) + device replacement/reflash ($105,000) = **$355,000**
2. **Exposure Factor (EF):** **1.0 (100%)** $\rightarrow$ $\text{SLE} = \mathbf{\$355,000}$
3. **ARO:** **0.1** (1 incident every 10 years via opportunistic network scan).
4. **ALE:** $$\text{ALE}_{\text{DoS}} = \$355,000 \times 0.1 = \mathbf{\$35,500}$$

### Option B: Severe Patient Safety Incident
1. **Asset Value (AV):** Malpractice & patient safety litigation liability (estimated average **$2,750,000**) + FDA investigation ($150,000) + disruption ($100,000) = **$3,000,000**
2. **Exposure Factor (EF):** **1.0 (100%)** $\rightarrow$ $\text{SLE} = \mathbf{\$3,000,000}$
3. **ARO:** **0.02** (1 incident every 50 years).
4. **ALE:** $$\text{ALE}_{\text{Safety}} = \$3,000,000 \times 0.02 = \mathbf{\$60,000}$$

### Total Combined ALE (Scenario 4):
$$\text{Total ALE} = \text{ALE}_{\text{DoS}} + \text{ALE}_{\text{Safety}} = \$35,500 + \$60,000 = \mathbf{\$95,500}$$

* **Confidence Level:** **Low**
* **Key Assumption Sensitivity:** Patient liability lawsuit outcome. Malpractice liability ranges from $500,000 to $5,000,000+, causing dramatic shifts in SLE.

---

## Scenario 5: FortiGate VPN Compromise (Perimeter Breach Gateway)

### 1. Asset Value (AV)
* **Reasoning:** Maximum aggregate operational loss from a full perimeter breach. An attacker gaining full access via VPN executes a dual-impact campaign: widespread ransomware deployment (Scenario 1) combined with massive ePHI exfiltration (Scenario 2).
  * **Aggregate Loss (Scenario 1 + Scenario 2):** $473,000 + $9,075,000 = **$9,548,000**

### 2. Exposure Factor (EF)
* **Reasoning:** **1.0 (100%)**. Total perimeter breach allows unhindered lateral movement across the unsegmented network, impacting all critical systems and backups.

### 3. Single Loss Expectancy (SLE)
* **Calculation:** $$\text{SLE} = \text{AV} \times \text{EF} = \$9,548,000 \times 1.0 = \mathbf{\$9,548,000}$$

### 4. Annualized Rate of Occurrence (ARO)
* **Reasoning:** **0.30** (Once every 3.3 years). Perimeter VPN exposures are the leading initial access vector (38% of healthcare attacks).

### 5. Annualized Loss Expectancy (ALE)
* **Calculation:** $$\text{ALE} = \text{SLE} \times \text{ARO} = \$9,548,000 \times 0.30 = \mathbf{\$2,864,400}$$

### 6. Confidence Level & Key Sensitivity
* **Confidence Level:** **Medium**
* **Key Assumption Sensitivity:** Multi-Factor Authentication (MFA) deployment status on VPN. Enforcing MFA on the FortiGate VPN drops the ARO from 0.30 to 0.03, mitigating over $2.5M in annual risk exposure.

---

## Quantitative Risk Summary Table

| Scenario | Asset | Threat | SLE ($) | ARO | ALE ($/year) | Confidence |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **Scenario 1** | Billing Server | Ransomware Attack | $473,000 | 0.285 | $134,805 | Medium |
| **Scenario 2** | EHR System | ePHI Data Exfiltration | $9,075,000 | 0.33 | $2,994,750 | Medium-High |
| **Scenario 3** | Clinical Workstations | Negligent Insider Data Theft | $120,000 | 2.50 | $300,000 | High |
| **Scenario 4** | BD Alaris Pumps | Device Compromise (DoS + Safety) | $3,000,000 | Variable | $95,500 | Low |
| **Scenario 5** | FortiGate VPN | Perimeter Gateway Breach | $9,548,000 | 0.30 | $2,864,400 | Medium |
