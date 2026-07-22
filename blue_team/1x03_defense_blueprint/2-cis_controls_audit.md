# 2. CIS Controls v8 Audit for MedDefense

## CIS Controls Scoring

### CIS Control 1: Inventory and Control of Enterprise Assets
* **Score:** Partial
* **Evidence:** While initial hardware asset mapping was completed during Project 1x00, MedDefense lacks automated asset discovery and real-time tracking for unauthorized devices entering the network.

### CIS Control 2: Inventory and Control of Software Assets
* **Score:** Partial
* **Evidence:** Software inventories were partially identified during vulnerability scanning in Project 1x02, but there is no centralized application whitelisting or automated software asset management process.

### CIS Control 3: Data Protection
* **Score:** Partial
* **Evidence:** Basic data handling is in place, but sensitive ePHI and patient records are not systematically inventoried, classified, or uniformly encrypted across all endpoint devices.

### CIS Control 4: Secure Configuration of Enterprise Assets and Software
* **Score:** Not Implemented
* **Evidence:** Vulnerability scans in Project 1x02 revealed widespread unhardened systems, default configurations, and unpatched OS baselines across network infrastructure and servers.

### CIS Control 5: Account Management
* **Score:** Partial
* **Evidence:** Domain accounts exist within Active Directory, but dormant accounts remain active past 45 days and administrator privileges are not strictly segregated into dedicated management accounts.

### CIS Control 6: Access Control Management
* **Score:** Partial
* **Evidence:** Access control processes are partially enforced, but Multi-Factor Authentication (MFA) is not universally mandated for remote access or administrative privileges.

### CIS Control 7: Continuous Vulnerability Management
* **Score:** Not Implemented
* **Evidence:** Project 1x02 conducted a one-time vulnerability scan, confirming the absence of an automated, recurring patch management and vulnerability remediation lifecycle.

### CIS Control 8: Audit Log Management
* **Score:** Not Implemented
* **Evidence:** System logs remain isolated on individual endpoints and servers with no centralized SIEM, log collection pipeline, or long-term storage policy established.

### CIS Control 9: Email and Web Browser Protections
* **Score:** Partial
* **Evidence:** Basic email filters are active, but DNS filtering services and enforced web browser hardening policies are not deployed enterprise-wide.

### CIS Control 10: Malware Defenses
* **Score:** Partial
* **Evidence:** Antivirus software is present on some legacy endpoints, but signature updates are inconsistent and removable media autorun mechanisms are not centrally restricted.

### CIS Control 11: Data Recovery
* **Score:** Partial
* **Evidence:** Routine system backups are executed, but backup instances are not strictly air-gapped/isolated from the main network nor routinely tested for ransomware restoration scenarios.

### CIS Control 12: Network Infrastructure Management
* **Score:** Not Implemented
* **Evidence:** Project 1x01 revealed a flat network topology with outdated router firmware, missing network architecture diagrams, and a lack of clinical/administrative network segmentation.

### CIS Control 13: Network Monitoring and Defense
* **Score:** Not Implemented
* **Evidence:** Operations notes confirm zero continuous monitoring, with no Intrusion Detection System (IDS), Network Intrusion Prevention System (NIPS), or flow log collection deployed.

### CIS Control 14: Security Awareness and Skills Training
* **Score:** Not Implemented
* **Evidence:** MedDefense lacks a structured security awareness training curriculum, leaving hospital staff untrained against phishing, social engineering, and healthcare-specific data handling threats.

### CIS Control 15: Service Provider Management
* **Score:** Partial
* **Evidence:** Third-party medical vendor lists exist for procurement, but a formal vendor security risk management policy and ongoing third-party assessment process are absent.

### CIS Control 16: Application Software Security
* **Score:** Not Implemented
* **Evidence:** MedDefense does not enforce secure application development lifecycles or security evaluations for internally managed web portals and scripts.

### CIS Control 17: Incident Response Management
* **Score:** Partial
* **Evidence:** Personnel have been designated (Deputy CISO and Security Analyst), but there is no formalized, tested Incident Response Plan or escalation matrix for breach notifications.

### CIS Control 18: Penetration Testing
* **Score:** Not Implemented
* **Evidence:** MedDefense has never conducted periodic internal or external penetration testing to validate its security defenses or identify exploitable attack paths.

---

## Scorecard Summary

| Status | Count |
| :--- | :--- |
| **Implemented** | 0 |
| **Partial** | 10 |
| **Not Implemented** | 8 |

---

## Top 5 Priority Controls

1. **CIS Control 7: Continuous Vulnerability Management**
   * *Justification:* Project 1x02 highlighted severe unpatched vulnerabilities that leave critical hospital systems exposed to automated exploit kits and ransomware attacks.
2. **CIS Control 6: Access Control Management**
   * *Justification:* Mandating MFA across remote access and administrative accounts immediately neutralizes the threat of compromised credentials gaining elevated access to sensitive patient data.
3. **CIS Control 12: Network Infrastructure Management**
   * *Justification:* Segmenting the flat network isolates critical medical devices and ePHI databases from standard staff workstation infections, drastically containing lateral movement during a breach.
4. **CIS Control 11: Data Recovery**
   * *Justification:* Implementing immutable, air-gapped backups guarantees that MedDefense can recover clinical systems and patient records independently without paying ransom during a severe ransomware incident.
5. **CIS Control 8: Audit Log Management**
   * *Justification:* Centralizing security logs into a unified repository provides the lean security team with the basic visibility required to detect, investigate, and respond to unauthorized network activity.
