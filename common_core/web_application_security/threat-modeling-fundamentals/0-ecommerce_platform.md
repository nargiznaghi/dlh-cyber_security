* **Trust Boundary 1: User Browser (React) to Node.js API Backend**
    Data crosses from the completely untrusted public environment (client side) into our corporate cloud/network infrastructure. All inputs originating from this layer must be treated as hostile and explicitly validated on the server side.
* **Trust Boundary 2: Node.js API Backend to PostgreSQL Database**
    This isolates the application processing logic from the persistent state layer. Even though both reside in the internal backend network, access controls, query sanitization, and the principle of least privilege must be enforced to prevent lateral data compromise.
* **Trust Boundary 3: Node.js API Backend to Stripe Payment Gateway**
    Data crosses from our corporate trusted application infrastructure to a specialized external third-party environment. Secure cryptographic tokens and verified webhooks are mandatory to maintain safe financial state transactions.

---

## 2. STRIDE Threat Analysis for Checkout Process

The checkout process handles sensitive state changes (inventory reductions, payments, order creations). Below are three prioritized STRIDE threats mapping to this process:

### Threat 1: Tampering (Price/Quantity Manipulation in Transit)
* **Description / Attack Scenario:** An attacker intercepts the outgoing checkout HTTP request from the React frontend using an intercepting proxy (e.g., Burp Suite). They modify the price parameter from `$100.00` to `$1.00` or alter product IDs before the payload reaches the Node.js backend.
* **Potential Impact:** Severe financial loss, direct theft of inventory, and broken business logic integrity across accounting and fulfillment systems.
* **Suggested Mitigation:** Never rely on prices or calculated totals supplied by the client application. The Node.js API backend must query the master item record directly from the PostgreSQL database using the product ID, recalculate the basket total server-side, and submit the server-generated total to Stripe.

### Threat 2: Spoofing (Session Hijacking / Token Replay)
* **Description / Attack Scenario:** An attacker targets an active session, stealing a user's JSON Web Token (JWT) or session identifier via Cross-Site Scripting (XSS) or network sniffing on unencrypted connections. The attacker then submits the stolen authorization token to checkout and purchase goods using the victim's profile.
* **Potential Impact:** Full account takeover, unauthorized financial charges, and loss of consumer trust leading to reputational damage.
* **Suggested Mitigation:** Implement strict transport security (TLS 1.3 exclusively). Session tokens must be stored in `HttpOnly`, `Secure`, and `SameSite=Strict` cookies to protect against client-side script extraction. Implement short token lifespans paired with secure cryptographic rotation schemes.

### Threat 3: Information Disclosure (Leakage of Transactional PII/PCI Data)
* **Description / Attack Scenario:** During the checkout payload transfer or due to improper error handling inside the Node.js backend, system trace logs or error strings containing raw Stripe tokens, consumer addresses, or database table structures are returned directly to the client or written to world-readable files.
* **Potential Impact:** Non-compliance with strict industry regulations (PCI-DSS, GDPR), massive legal fines, and exposing the underlying stack structure for easier multi-stage attacks.
* **Suggested Mitigation:** Build a global production error boundary that sanitizes out internal system details before responding to callers. Only general error identifiers should be exposed externally. Ensure verbose application diagnostics are piped securely into dedicated log collectors (e.g., Sentry, Winston) with automatic PII masking enabled.

---

## 3. DREAD Risk Assessment: SQL Injection in Product Search

A risk assessment has been performed on the unauthenticated product search feature to quantify the exposure to SQL Injection (SQLi) vulnerabilities.

### DREAD Formula:
$$\text{Risk Score} = \frac{\text{Damage} + \text{Reproducibility} + \text{Exploitability} + \text{Affected Users} + \text{Discoverability}}{5}$$

### Scoring & Justification Matrix

| DREAD Factor | Score (1-10) | Justification & Technical Context |
| :--- | :--- | :--- |
| **Damage Potential** | **9 / 10** | A successful SQL Injection in the search bar can bypass authentication filters entirely. It allows adversaries to map, extract, or drop structural tables within PostgreSQL, compromising the confidentiality and availability of all persistent records. |
| **Reproducibility** | **10 / 10** | If the application code builds raw query strings via direct input concatenation, the structural flaw is completely deterministic. The same payload will yield successful exploitation 100% of the time. |
| **Exploitability** | **8 / 10** | The product search is exposed broadly without authentication requirements. Readily available automated scanners (e.g., `sqlmap` combustibles) can discover and easily extract entire structures over public networks with minimal technical resistance. |
| **Affected Users** | **10 / 10** | Since all users share a centralized PostgreSQL persistent store, a full data breach compromises the personal and transactional data records of the entire customer base. |
| **Discoverability** | **9 / 10** | Public text input fields connected directly to data queries are the absolute primary vectors targeted during initial external adversarial reconnaissance and standard vulnerability scans. |

### Final DREAD Calculation:
$$\text{Risk Score} = \frac{9 + 10 + 8 + 10 + 9}{5} = \frac{46}{5} = 9.2$$

* **Risk Rating:** **CRITICAL / HIGH (9.2 / 10)**
* **Actionable Mitigation Strategy:** Do **not** implement search queries using raw template string interpolation (e.g., `` `SELECT * FROM products WHERE name LIKE '%${req.query.search}%'` ``). Instead, enforce the use of **Parameterized Queries / Prepared Statements** via native database drivers, or leverage a secure Object-Relational Mapper (ORM) like Prisma or Sequelize which automatically handles input sanitization and encapsulation by default.

---
### References
* OWASP Top 10:2021 - A03:2021-Injection
* Microsoft Threat Modeling Methodology (STRIDE/DREAD Reference Guide)
