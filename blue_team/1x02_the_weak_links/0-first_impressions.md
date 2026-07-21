# First Impressions Summary: Vulnerability Scan Analysis

## 1. Scan Metadata
* **Organization:** MedDefense Health Systems
* **Target Scope:** `10.10.0.0/16` (All internal subnets)
* **Scan Date:** Recent / Active Scan Window
* **Scanner Tool:** OpenVAS 22.x (Greenbone Community Edition)
* **Scan Policy:** Full and Deep (Authenticated where credentials were available)
* **Requested By:** James Chen, Deputy CISO
* **Executed By:** SecurePoint Consulting (Third-party)
* **What Was NOT Scanned / Out of Scope:**
  * Cloud services (e.g., Office 365)
  * Mobile devices (e.g., iPads)
  * Offline assets during the scan window
  * Unauthenticated medical devices were only scanned via network interfaces (no credentialed access)

---

## 2. Finding Distribution

| Severity Level | Count | Percentage |
| :--- | :--- | :--- |
| **Critical** | 4 | 12.9% |
| **High** | 7 (including Finding 031) | 22.6% |
| **Medium** | 11 | 35.5% |
| **Low** | 5 | 16.1% |
| **Informational** | 4 | 12.9% |
| **Total** | **31** | **100%** |

* **Dominant Severity Level:** **Medium** has the highest number of findings (11 total).

---

## 3. Asset Heat Map (Top 5 Affected Hosts)

| Top Host / Subnet | IP Address | Finding Count | Asset Role / Context |
| :--- | :--- | :--- | :--- |
| **`billing-srv-01`** | `10.10.2.15` | **6** | **Billing Server** (Hosts financial records, Apache web server, MySQL DB, SSH, Ubuntu 18.04 EOL) |
| **`ehr-srv-01`** | `10.10.2.10` | **4** | **Electronic Health Record Application Server** (Hosts Tomcat web app, AJP connector, NTP client) |
| **`web-srv-01`** | `10.10.2.50` | **4** | **Patient Portal** (Hosts HTTPS web service, SSL cert, web headers) |
| **`ad-dc-01`** | `10.10.2.20` | **3** | **Active Directory Domain Controller** (Handles Kerberos, LDAP, DNS zone transfers) |
| **BD Alaris Pumps** | `10.10.3.40-46` | **1 (x7 devices)** | **Medical Infusion Devices** (Clinical IoT endpoints running vulnerable firmware and default credentials) |

---

## 4. First Observations

### Critical Findings Distribution
* **Concentration vs. Spread:** The **4 Critical** findings are spread across multiple distinct operational systems rather than isolated on one server:
  * **`10.10.2.15` (billing-srv-01):** Contains **2 Criticals** that form an explicit exploit chain (Remote Code Execution via Apache `mod_lua` + Local Privilege Escalation to root).
  * **`10.10.2.11` (ehr-db-01):** Contains **1 Critical** misconfiguration allowing unrestricted internal database access to Patient Health Information (PHI).
  * **`10.10.1.70` (WS-RAD-01):** Contains **1 Critical** due to EOL Windows XP running unpatched EternalBlue, BlueKeep, and MS08-067.

### Related Findings & Exploit Chains
* **Exploit Chains:** 
  * Findings **001 + 002** allow an unauthenticated attacker to gain full root access on `billing-srv-01`.
  * Finding **031 (Ghostcat)** on `ehr-srv-01` allows unauthenticated file reads (such as database passwords), which directly interfaces with Finding **003** (unrestricted PostgreSQL access).
* **Systemic Misconfigurations:** Flat network design (no VLAN segmentation) enables any compromised endpoint (e.g., Windows XP or medical pumps) to pivot directly to databases and domain controllers.

### Key Surprises
* **Shadow IT:** Unidentified Linux devices were discovered on internal subnets (`10.10.2.99` with Cockpit/Jupyter, and `10.10.10.200` running an unpatched, vulnerable Grafana instance).
* **Medical IoT Security:** 7 BD Alaris infusion pumps and 13 Philips monitors operate with default credentials/unencrypted communications directly accessible on the main network.

---

## 5. Scan Limitations
* **Out-of-Scope Assets:** Mobile devices, O365/Cloud services, and offline systems.
* **Passive Verification Deficit:** The scanner did not attempt active exploitation. High-severity items like OpenSSH (Finding 020) might be **False Positives** depending on system context.
* **Unauthenticated Limits:** Medical devices were scanned without credentials, meaning internal device configurations could not be audited beyond open port discovery.
