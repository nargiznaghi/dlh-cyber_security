# The CVSS Deconstruction

## Exercise 1: Deconstruction

**Target Vector String:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` *(Finding 001, CVE-2021-44790)*

---

### Component-by-Component Breakdown

#### 1. Attack Vector (`AV:N`)
* **Abbreviation:** Attack Vector
* **Selected Value (`N`):** Network. The vulnerability is reachable from the internet or remote networks without network constraints.
* **Other Possible Values:**
  * `Adjacent (A)`: Requires access to the same physical or logical network (e.g., local Wi-Fi, subnet). Lowers score.
  * `Local (L)`: Requires local access to the target host (shell or console). Lowers score significantly.
  * `Physical (P)`: Requires physical interaction with the device. Results in the lowest score.
* **Why Selected:** `CVE-2021-44790` is an Apache HTTP server bug reachable over HTTP/HTTPS ports across standard network routes.

#### 2. Attack Complexity (`AC:L`)
* **Abbreviation:** Attack Complexity
* **Selected Value (`L`):** Low. Specialized conditions or extra effort are not required to execute the exploit.
* **Other Possible Values:**
  * `High (H)`: Requires specific timing, race conditions, or active interception (man-in-the-middle). Lowers score.
* **Why Selected:** Sending a specially crafted HTTP request to trigger the buffer overflow is deterministic and repeatable.

#### 3. Privileges Required (`PR:N`)
* **Abbreviation:** Privileges Required
* **Selected Value (`N`):** None. The attacker does not need to be authenticated to the target system.
* **Other Possible Values:**
  * `Low (L)`: Requires standard user credentials. Lowers score.
  * `High (H)`: Requires administrative/root permissions. Lowers score significantly.
* **Why Selected:** Anyone capable of making an unauthenticated web request to the web server can trigger the vulnerability.

#### 4. User Interaction (`UI:N`)
* **Abbreviation:** User Interaction
* **Selected Value (`N`):** None. The attack requires no intervention or action from a human victim.
* **Other Possible Values:**
  * `Required (R)`: Requires a victim to take an action (e.g., clicking a phishing link, opening a malicious file). Lowers score.
* **Why Selected:** The exploit operates autonomously against the daemon without waiting for human interaction.

#### 5. Scope (`S:U`)
* **Abbreviation:** Scope
* **Selected Value (`U`):** Unchanged. The exploited component and the impacted component are managed by the same security authority.
* **Other Possible Values:**
  * `Changed (C)`: The compromised component breaks out to impact components in a different security zone (e.g., VM escape). Increases score significantly.
* **Why Selected:** The buffer overflow directly impacts the Apache web server process itself.

#### 6. Confidentiality Impact (`C:H`)
* **Abbreviation:** Confidentiality
* **Selected Value (`H`):** High. Complete loss of confidentiality; all system data or memory can be read by the attacker.
* **Other Possible Values:**
  * `None (N)`: No impact on confidentiality.
  * `Low (L)`: Access to limited or non-sensitive information.
* **Why Selected:** Remote Code Execution (RCE) enables full memory and file system read access.

#### 7. Integrity Impact (`I:H`)
* **Abbreviation:** Integrity
* **Selected Value (`H`):** High. Complete loss of system integrity; attackers can modify any data, system files, or settings.
* **Other Possible Values:**
  * `None (N)`: No impact on integrity.
  * `Low (L)`: Minor modifications allowed without total control.
* **Why Selected:** Executing arbitrary code gives full write access to the host within the daemon's context.

#### 8. Availability Impact (`A:H`)
* **Abbreviation:** Availability
* **Selected Value (`H`):** High. Total denial of service or crashing of the vulnerable component/system.
* **Other Possible Values:**
  * `None (N)`: No impact on service availability.
  * `Low (L)`: Reduced performance or temporary minor interruptions.
* **Why Selected:** Exploiting a heap buffer overflow crashes the HTTP process or grants control to shutdown services.

---

### Metric Change Impact Test

* **Original Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` ➔ **Score: 9.8 (Critical)**
* **Modified Vector:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` ➔ **New Score: 7.8 (High)**

#### Why the Score Changed:
The score drops from **9.8 to 7.8** because requiring local access (`AV:L`) restricts the attack surface. An attacker can no longer execute the exploit remotely over the internet; they must first obtain a shell or local foothold on the host, significantly reducing the immediate threat.

---

## Exercise 2: Construction

### Custom Scenario Specifications
* **Attack Vector:** Adjacent Network (`AV:A`)
* **Attack Complexity:** High (`AC:H`)
* **Privileges Required:** Low (`PR:L`)
* **User Interaction:** None (`UI:N`)
* **Scope:** Unchanged (`S:U`)
* **Confidentiality:** High (`C:H`)
* **Integrity:** None (`I:N`)
* **Availability:** None (`A:N`)

### Constructed Vector String
`CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N`

### Calculated Results
* **CVSS Base Score:** **4.8**
* **Severity Rating:** **Medium**

---

## Exercise 3: Comparison

### Side-by-Side Comparison

| Metric / Parameter | High-Severity Finding (Finding 001) | Medium-Severity Finding (Finding 005) |
| :--- | :--- | :--- |
| **CVE ID** | `CVE-2021-44790` | `CVE-2011-3389` (BEAST) |
| **CVSS v3.1 Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Base Score** | **9.8** | **7.5** |
| **Severity** | **Critical** | **High** (Scan rated 7.5) |
| **Attack Vector (AV)** | `Network (N)` | `Network (N)` |
| **Attack Complexity (AC)**| `Low (L)` | `Low (L)` |
| **Privileges Required (PR)**| `None (N)` | `None (N)` |
| **User Interaction (UI)** | `None (N)` | `None (N)` |
| **Scope (S)** | `Unchanged (U)` | `Unchanged (U)` |
| **Confidentiality (C)** | `High (H)` | `High (H)` |
| **Integrity (I)** | **`High (H)`** | **`None (N)`** |
| **Availability (A)** | **`High (H)`** | **`None (N)`** |

---

### Score Difference & Impact Analysis

1. **Specific Driver Component Differences:**
   Both findings share identical exploitability metrics (`AV:N/AC:L/PR:N/UI:N/S:U`) and identical Confidentiality impact (`C:H`). The entire score difference between 9.8 and 7.5 comes from **Integrity (`I`)** and **Availability (`A`)**.
   * `CVE-2021-44790` (9.8) causes complete compromise across all three CIA triad components (`C:H/I:H/A:H`) via Remote Code Execution.
   * `CVE-2011-3389` (7.5) only impacts Confidentiality (`C:H`) via SSL traffic decryption, having **zero direct effect** on Integrity (`I:N`) or Availability (`A:N`).

2. **Which Metrics Have the Biggest Impact?**
   * **Scope (`S`):** Toggling scope from `Unchanged (U)` to `Changed (C)` causes the largest upwards jump in the scoring algorithm because it signals a breach beyond the immediate application boundary.
   * **Privileges Required (`PR`) & Attack Vector (`AV`):** Transitioning from `PR:N` to `PR:H` or `AV:N` to `AV:P` dramatically penalizes exploitability and drops scores faster than minor impact shifts.
   * **Triad Accumulation (`C/I/A`):** The CVSS formula heavily punishes vulnerabilities that hit all three pillars simultaneously (`H/H/H`) vs single-impact vulnerabilities (`H/N/N`).
