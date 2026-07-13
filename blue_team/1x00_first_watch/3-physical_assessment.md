# Physical Security Assessment: MedDefense Central

This report decomposes five critical physical observations made during the facility walk-through into formal risk components, establishing the relationship between physical vulnerabilities and logical network impacts.

---

### Observation 1: Server Room Access
*   **Vulnerability:** Weak authentication and complete lack of surveillance/logging; the core server room uses generic building-wide badge access, lacks security cameras, and has no physical visitor log.
*   **Threat:** An unauthorized employee (e.g., disgruntled staff or custodial worker) or an intruder utilizing a lost/stolen generic badge enters the server room undetected to steal hardware, plant a rogue device, or disconnect equipment.
*   **Impact:** **Confidentiality, Integrity, and Availability Compromise.** Malicious physical access allows for direct data theft, hardware manipulation, or catastrophic destruction of core infrastructure.
*   **Severity:** **Critical.** The server room houses the entire organization's data backbone, and the lack of isolation or audit trails means a breach here could compromise all systems irreversibly[cite: 1].

---

### Observation 2: Network Closet
*   **Vulnerability:** Unlocked physical infrastructure combined with cleartext credential exposure; the network closet door is left open, and switch management credentials are written on a laminated sheet taped directly to the wall.
*   **Threat:** A visitor, patient, or unauthorized staff member walks into the closet, logs into the switch interface with the exposed credentials, and reconfigures the network or deploys a malicious packet sniffer.
*   **Impact:** **Confidentiality, Integrity, and Availability Compromise.** Complete administrative control over the switches allows the threat actor to intercept patient data, alter network traffic routing, or shut down network connectivity.
*   **Severity:** **Critical.** Exposing cleartext administrative credentials alongside unmonitored, open physical access to core network switches allows an attacker to control or disable local corporate traffic instantly.

---

### Observation 3: Nurse Station
*   **Vulnerability:** Unattended active sessions and non-compliant administrative policies; a clinical workstation logged into the EHR system is left idle for 15 minutes in a public-facing area with an explicit policy forbidding logouts.
*   **Threat:** A patient or passerby accesses the unattended terminal to view, download, or maliciously modify private medical records while pretending to look at the screen.
*   **Impact:** **Confidentiality and Integrity Compromise.** Unauthorized disclosure of Protected Health Information (PHI) and potential tampering with patient medical histories, medications, or allergy logs[cite: 1].
*   **Severity:** **High.** This directly violates basic HIPAA security compliance mandates and introduces immediate risk of localized data exposure and unauthorized patient record alteration[cite: 1].

---

### Observation 4: Medical IoT
*   **Vulnerability:** Outdated legacy firmware and a completely flat network layout; a patient vital signs monitor runs unpatched firmware from 2019 and shares the exact same logical IP range as public nurse workstations[cite: 1].
*   **Threat:** An attacker on the local network segments or connected via guest WiFi exploits known vulnerabilities in the 2019 firmware to compromise the monitor and use it as a pivot point to attack clinical infrastructure[cite: 1].
*   **Impact:** **Integrity and Availability Compromise.** Manipulating the monitor could alter vital sign data on screen (endangering patients) or take life-critical medical devices offline entirely.
*   **Severity:** **High.** Legacy medical IoT devices on a flat network domain pose life-safety risks, as a lateral movement attack can directly cross from a workstation to active patient care monitors[cite: 1].

---

### Observation 5: Emergency Exit
*   **Vulnerability:** Physical perimeter breach; a fire exit door separating public waiting zones from the restricted IT and administrative wing is propped open with a wooden wedge.
*   **Threat:** An external threat actor walks directly past public security boundaries into the restricted administrative wing without authentication, gaining immediate access to the IT offices and executive rooms[cite: 1].
*   **Impact:** **Confidentiality, Integrity, and Availability Compromise.** Direct exposure of administrative physical endpoints, intellectual assets, and security personnel to theft, espionage, or physical duress.
*   **Severity:** **Medium.** While it bypasses the primary facility physical perimeter, an attacker must still breach secondary machine-level locks or active employee presence within the IT wing to impact logical infrastructure[cite: 1].
