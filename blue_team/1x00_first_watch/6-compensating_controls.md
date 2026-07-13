# Compensating Control Strategy: Legacy MRI Workstation

This document outlines the risk analysis and compensating control strategy for the Radiology department's MRI control workstation, which runs on an unpatchable, certified Windows XP Embedded operating system.

---

## 1. Risk Analysis

The Windows XP Embedded MRI workstation represents a critical systemic risk because it resides on a flat, unsegmented network topology alongside standard hospital workstations. Windows XP suffers from hundreds of publicly known, unpatched vulnerabilities (such as EternalBlue and critical Remote Code Execution flaws) that require zero user interaction to exploit. If any single workstation in the hospital is compromised via phishing or malware, an attacker can perform lateral movement across the shared VLAN and easily seize full administrative control of the legacy MRI system. Once compromised, this critical node can be utilized as a stable pivot point to launch further attacks deeper into the MedDefense internal network or directly disrupt life-critical clinical operations.

---

## 2. Compensating Control Strategy

Since the operating system cannot be altered, patched, or disconnected due to medical certification and clinical needs, the following controls are engineered to wrap protection around the asset.

### Control 1: Strict Micro-Segmentation (Network Isolation)
*   **Description:** Move the MRI workstation off the general corporate VLAN and place it into its own dedicated, isolated hardware VLAN. Configure a stateful firewall or Access Control List (ACL) between this new segment and the rest of the hospital. The firewall rule must exclusively allow inbound/outbound communication over specific ports required to transmit images directly to the PACS server's IP address, blocking all other corporate network traffic.
*   **Classification:** Technical / Preventive
*   **Risk Reduction:** It shrinks the attack surface dramatically by breaking the flat network layout. General corporate workstations can no longer reach or scan the vulnerable Windows XP system, preventing automated lateral malware infection.
*   **Limitations / Residual Risk:** If the PACS server itself is compromised, the threat can still traverse the open firewall rule into the MRI network.

### Control 2: USB and Periphery Port Disablement
*   **Description:** Physically block or programmatically disable all unused USB ports, CD/DVD drives, and external expansion slots on the Windows XP computer chassis using physical port locks.
*   **Classification:** Physical / Preventive
*   **Risk Reduction:** It addresses the local physical insider threat vector. This stops staff, engineers, or visitors from introducing unauthorized USB devices, data-stealing tools, or accidental malware via physical media directly into the unpatched system.
*   **Limitations / Residual Risk:** Does not protect against threats originating over the network through the allowed PACS communications channel.

### Control 3: Role-Based Access and Incident Response Playbook
*   **Description:** Implement a strict administrative policy restricting physical access to the MRI console to authorized radiology staff only. Combine this with a dedicated, short incident response playbook outlining immediate isolation procedures (such as pulling the network cable) the moment the MRI displays anomalous or erratic behavior.
*   **Classification:** Administrative / Preventive & Corrective
*   **Risk Reduction:** Minimizes human error and local unauthorized interaction, while creating a standardized mechanism for containment to prevent an infection from spreading back into the network.
*   **Limitations / Residual Risk:** Administrative policies rely heavily on human compliance and do not actively stop automated technical exploits.

---

## 3. Implementation Priority

If MedDefense can only implement ONE control immediately due to budget or resource constraints, **Control 1: Strict Micro-Segmentation (Network Isolation)** must be chosen. 

**Justification:** Network isolation provides the highest possible risk reduction return on investment. It acts as a technical perimeter wall around the defenseless Windows XP system. While disabling USB ports only stops local physical tampering, micro-segmentation completely cuts off the machine from the broader hospital network—mitigating the massive risk of automated worm propagation and network-based remote code execution without altering a single file on the certified medical device itself.
