# 9. The OSINT Hunt

## 1. FortiGate FortiOS Vulnerability

* **Source:** https://nvd.nist.gov/vuln/detail/CVE-2024-21762 (veya CISA Advisory URL)
* **CVE:** CVE-2024-21762
* **Affected Product:** MedDefense FortiGate 100F Firewall
* **Why the Scan Missed It:** The automated scanner performed an unauthenticated external network scan. It could not fingerprint the underlying FortiOS firmware version behind the firewall or inspect administrative interfaces that were restricted.
* **CVSS / Severity:** 9.8 (Critical)
* **MedDefense Impact:** An unauthenticated remote attacker could execute arbitrary code/commands on the FortiGate 100F via crafted HTTP requests to the SSL-VPN service, gaining full control over the perimeter firewall and entry into the internal network.
* **Recommendation:** Upgrade FortiOS to the latest patched version immediately, or temporarily disable SSL-VPN if patching cannot be applied right away.

---

## 2. Microsoft Office 365 / Entra ID Attack Vector / Vulnerability

* **Source:** CISA Alert / Microsoft Security Advisory (örnek: https://www.cisa.gov/news-events/cybersecurity-advisories/...)
* **CVE:** N/A (AitM / OAuth Phishing Technique) veya CVE-2023-23397
* **Affected Product:** MedDefense O365 E3 Tenant & Entra ID Identity Infrastructure
* **Why the Scan Missed It:** SaaS and cloud infrastructure like Microsoft 365 were entirely out of scope for the local network vulnerability scanner. The scanner has no access to tenant configurations or cloud authentication logs.
* **CVSS / Severity:** High / Critical
* **MedDefense Impact:** Attackers using Adversary-in-the-Middle (AitM) phishing proxies can steal session tokens, bypass Multi-Factor Authentication (MFA), and gain persistent access to executive emails, medical records in SharePoint, or internal communications.
* **Recommendation:** Enforce FIDO2-based / Certificate-Based MFA, restrict user consent for third-party OAuth applications in Entra ID, and enable Conditional Access policies to block risky sign-ins.

---

## 3. Synology DSM 7 Vulnerability

* **Source:** https://nvd.nist.gov/vuln/detail/CVE-2023-5561 (veya Synology Security Advisory URL)
* **CVE:** CVE-2023-5561
* **Affected Product:** MedDefense Backup NAS (Running Synology DSM 7)
* **Why the Scan Missed It:** The NAS was located on a isolated backup VLAN, and the scanner lacked authenticated access to query installed internal packages and full DSM patch levels.
* **CVSS / Severity:** 7.5 (High) / 9.8 (Critical)
* **MedDefense Impact:** An attacker on the local network could exploit this vulnerability to execute arbitrary code on the backup NAS, leading to total destruction, encryption (ransomware), or exfiltration of enterprise backup data.
* **Recommendation:** Update Synology DSM to the latest minor revision immediately, restrict access to the NAS management interface using network firewalls, and disable unused default DSM services/packages.
