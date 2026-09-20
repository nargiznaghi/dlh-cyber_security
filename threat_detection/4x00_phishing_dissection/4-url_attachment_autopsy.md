## Indicator 1 - meddefense-portal.com
- Source email: Email 2
- Original value: http://meddefense-portal.com/login/verify
- Defanged value: hxxp://meddefense-portal[.]com/login/verify
- Domain or IP: meddefense-portal.com
- Indicator type: Domain / URL
- Evidence from email: Embedded login re-verification link targeting user Diane Marsh in Email 2. Sender IP failed SPF and DMARC checks.
- Safe investigation method: whois meddefense-portal[.]com, dig meddefense-portal[.]com, urlscan.io passive search
- Finding: Typosquatted/lookalike domain impersonating official MedDefense portal; sending IP 91.234.99.107 failed SPF/DMARC.
- Risk rating: HIGH

---

## Indicator 2 - outlook-protection.com
- Source email: Email 3
- Original value: http://outlook-protection.com/auth/login
- Defanged value: hxxp://outlook-protection[.]com/auth/login
- Domain or IP: outlook-protection.com
- Indicator type: Domain / URL
- Evidence from email: Embedded security review link in Microsoft 365 security alert email.
- Safe investigation method: whois outlook-protection[.]com, VirusTotal domain lookup, Passive DNS lookup
- Finding: Attacker-controlled lookalike domain designed to harvest Microsoft 365 login credentials.
- Risk rating: HIGH

---

## Indicator 3 - 203.0.113.228
- Source email: Email 5
- Original value: http://203.0.113.228/invoices/INV-2026-04891.pdf
- Defanged value: hxxp://203[.]0[.]113[.]228/invoices/INV-2026-04891[.]pdf
- Domain or IP: 203.0.113.228
- Indicator type: IP Address / URL
- Evidence from email: Direct IP URL hosting malicious invoice document reference INV-2026-04891.pdf.
- Safe investigation method: Threat intelligence lookup on IP 203[.]0[.]113[.]228, urlscan.io passive search
- Finding: External IP hosting malicious payload/invoice PDF; bypasses domain-based filtering.
- Risk rating: HIGH

---

## Indicator 4 - medequip-supplies.net
- Source email: Email 5
- Original value: medequip-supplies.net
- Defanged value: medequip-supplies[.]net
- Domain or IP: medequip-supplies.net
- Indicator type: Domain
- Evidence from email: Sender domain claiming to be billing infrastructure for MedEquip Supplies with SPF softfail and missing DKIM.
- Safe investigation method: whois medequip-supplies[.]net, dig TXT medequip-supplies[.]net
- Finding: Unverified billing domain with SPF softfail and missing DKIM signatures; fake invoice scam.
- Risk rating: HIGH

---

## Indicator 5 - meddefense-benefits.org
- Source email: Email 7
- Original value: http://meddefense-benefits.org/enrollment/login
- Defanged value: hxxp://meddefense-benefits[.]org/enrollment/login
- Domain or IP: meddefense-benefits.org
- Indicator type: Domain / URL
- Evidence from email: Embedded link in open-enrollment notification urging immediate login. Fails SPF, DKIM, and DMARC.
- Safe investigation method: whois meddefense-benefits[.]org, urlscan.io scan history lookup
- Finding: Spoofed HR benefits domain registered externally; fails all authentication checks.
- Risk rating: HIGH
