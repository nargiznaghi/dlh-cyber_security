# Root Cause Analysis: billing-srv-01 Performance Degradation

## 1. Process Identification and Technical Analysis

Based on the forensic data gathered in `billing-srv-01_diagnostics.txt`, the system administrator's diagnosis ("undersized hardware for billing workload") is fundamentally flawed. The server is actively compromised by an unauthorized cryptocurrency miner.

*   **Process Misdirection (`top`):** The process named `/kworker` (PID 8834) is consuming **94.2% of the CPU**. Legitimate kernel processes appear in brackets as `[kworker]` and execute with `root` privileges[cite: 2]. This rogue process runs under the **`www-data`** user account (the Apache web server user)[cite: 2].
*   **Binary and Source Location:** Forensic tracking (`ls -la /proc/8834/exe`) reveals that the binary is executing from an unauthorized hidden directory: `/var/www/html/.cache/kworker`[cite: 2].
*   **Network and Configuration Analysis:** The `netstat` logs show active connections to external servers over non-standard ports (e.g., `185.243.115.89:4443`, `91.121.87.10:8080`, and `104.238.140.32:3333`)[cite: 2]. Inspection of `/var/www/html/.cache/config.json` confirms the payload is configured to mine **Monero (XMR)** utilizing public mining pools (`pool.monero.org`) under a redacted wallet address (`48Bv3...REDACTED...Kj2`) with 4 dedicated threads[cite: 2].

---

## 2. Classification of the Real Compromise

While the visible symptom is performance degradation (an **Availability** impact causing the billing application to slow down), the security breach is rooted in two preceding violations[cite: 2]:

1.  **Confidentiality Compromise:** The initial vector involved a breakdown in Confidentiality. Unauthorized access was gained to the server's web application tier, circumventing normal authentication/authorization boundaries to drop files and read directory structures as `www-data`[cite: 2].
2.  **Integrity Compromise:** System Integrity was violated when an external actor altered the server's state by uploading the malicious `kworker` binary, creating a hidden configuration file (`config.json`), and executing unauthorized mining processes on the OS layer[cite: 2].

---

## 3. Flaws in the Proposed Solution

The system administrator's recommendation to upgrade the hardware or migrate to a new Virtual Machine (VM) with 16GB RAM and 8 vCPUs will **fail to resolve the security issue**[cite: 2].

*   **The Mining Loop Logic:** The malicious `config.json` file dictates resource parameters[cite: 2]. Cryptocurrency mining software is designed to dynamically consume all available computing capacity. 
*   **The Consequence:** Upgrading the hardware will only result in the malware spawning more threads or increasing intensity to saturate **94%+ of the newly allocated vCPUs**[cite: 2]. MedDefense would essentially be using its budget to finance the attacker's mining speed without patching the entry point[cite: 2].

---

## 4. Connection to the January Incident

The fact that `billing-srv-01` suffered a ransomware attack in January and is currently infected with a crypto-miner implies that **the server's initial entry vector was never identified or remediated during the post-incident rebuild**[cite: 2]. 

Marcus's notes reveal that the server is running an outdated version of **Apache 2.4.29**, which contains known Remote Code Execution (RCE) vulnerabilities[cite: 2]. The different payloads (Ransomware in January, Crypto-miner now) suggest that while the malicious objectives changed, the unpatched web application vulnerability remained identical[cite: 2].

### Critical Questions to Investigate Immediately:
1.  **Rebuild Integrity:** Was the server rebuilt in January from an unpatched template or an already infected backup snapshot containing a web shell backdoor?[cite: 2]
2.  **Egress Firewall Rules:** Why is a critical, internal billing server allowed to establish unmonitored, direct outbound TCP connections over non-standard ports (`4443`, `8080`, `3333`) to public internet addresses?[cite: 2]
3.  **Vulnerability Lifecycle:** Why was a known vulnerable service (Apache 2.4.29) re-deployed on an operating system (Ubuntu 18.04 LTS) nearing End-of-Life (EOL) without immediate patching or isolation?[cite: 2]
