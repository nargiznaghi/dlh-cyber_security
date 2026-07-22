# 13. The Web Exposure Analysis

## Host 1: Patient Portal / Web Gateway (`web-gateway-01` - 10.10.1.10 / Public IP)

* **Exposure:** Internet-facing (Directly accessible from the public internet).
* **Findings:**
  * Finding 001: Apache `mod_lua` Buffer Overflow / RCE (CVE-2021-44790)
  * Finding 014: Missing Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
  * Finding 015: HTTP TRACE Method Enabled
* **Combined Risk:** **Critical.** The host is directly exposed to external attackers on the internet. Missing browser security controls combined with a high-severity RCE vulnerability in Apache creates an unmitigated perimeter breach vector.
* **Attack Scenario:** An external attacker sends a crafted request exploiting `mod_lua` (Finding 001) to execute arbitrary code on the perimeter gateway. Alternatively, using missing CSP/HSTS headers (Finding 014), an attacker executes Cross-Site Scripting (XSS) or credential harvesting attacks against external patients accessing the portal.
* **Priority:** **Priority 1 (Fix First).** As the primary perimeter entry point exposed to the public internet, it represents the highest probability of automated exploitation by external threat actors.

---

## Host 2: EHR Application Server (`ehr-srv-01` - 10.10.2.10)

* **Exposure:** Internal-only, but directly accessible across the flat corporate network.
* **Findings:**
  * Finding 017: Apache Tomcat Version & Directory Information Disclosure
  * Finding 031: Apache Tomcat AJP Connector Misconfiguration / Ghostcat (CVE-2020-1938)
  * Finding 030: TLS Certificate Common Name Mismatch
* **Combined Risk:** **Critical.** Although located internally, the flat network topology allows any compromised internal endpoint (or insider) to exploit Tomcat services, access protected health information (ePHI), or retrieve application secrets.
* **Attack Scenario:** An attacker who gains a foothold on the internal network discovers the exposed Tomcat version via banner grabbing (Finding 017). This leads them to exploit the AJP connector on port 8009 using the Ghostcat vulnerability (Finding 031) to read local application files, extract hardcoded database credentials, and pivot directly into the PostgreSQL database (`ehr-db-01`).
* **Priority:** **Priority 2.** Highly critical due to direct access to patient data (ePHI), but requires an initial foothold inside the network (or compromise of the perimeter).

---

## Host 3: Backup NAS Management Interface (`backup-nas-01` - 10.10.3.50)

* **Exposure:** Internal-only (Backup VLAN / Internal Management Network).
* **Findings:**
  * Finding 021: Weak / Default SSL/TLS Cipher Suites Enabled
  * Finding 022: Self-Signed / Untrusted SSL Certificate Warning
* **Combined Risk:** **Medium.** The risk is localized to internal network sniffing, credential interception, or Man-in-the-Middle (MitM) attacks against backup administration sessions.
* **Attack Scenario:** An attacker positioned on the internal network performs ARP spoofing to intercept traffic between an administrator and the NAS web console. Using the weak TLS ciphers (Finding 021) or unverified self-signed certificate warnings (Finding 022), the attacker intercepts session tokens or administrative passwords to compromise system backups.
* **Priority:** **Priority 3.** Lower risk relative to perimeter and database infrastructure, as it requires an active internal adversary position on the management network segment.

---

## Information Disclosure Analysis: "Medium" Findings Value

### Question:
*Finding 017 (Tomcat information disclosure) led SecurePoint to manually discover Finding 031 (Ghostcat - CVSS 9.8). What does this tell you about the value of investigating "Medium" findings that reveal version information?*

### Answer:
1. **Version Information as an Attack Enabler:**
   "Medium" or "Low" findings involving information disclosure (such as HTTP server banners, error stack traces, or version headers) do not directly grant remote execution by themselves. However, they act as primary reconnaissance intelligence for attackers. Knowing the exact software version allows an attacker to look up known, targeted CVEs (like Ghostcat for Tomcat) rather than guessing or triggering loud intrusion detection rules.

2. **Reconnaissance to Exploitation Pipeline:**
   Automated scanners often rank banner grabbing as "Low" or "Medium" because no immediate exploit was executed during the scan. However, in security operations, these findings frequently point to underlying, deeply embedded legacy software components that contain unpatched "Critical" vulnerabilities. 

3. **Value of Investigation:**
   Investigating information disclosure findings allows defense teams to perform manual deep-dives before adversaries do. Removing version banners (banner grabbing mitigation) reduces operational visibility for external actors, while patching the underlying disclosed software eliminates the hidden Critical/High vulnerabilities it exposes.
