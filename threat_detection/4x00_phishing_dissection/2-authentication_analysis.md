## Email 1 — healthcare-education-weekly.com
- SPF: PASS (Sender IP 198.51.100.42 is authorized for healthcare-education-weekly.com).
- DKIM: PASS (Valid cryptographic signature for header.d=healthcare-education-weekly.com).
- DMARC: PASS (Header From domain aligns with authenticated SPF/DKIM domains; action=none).
- Authentication verdict: Authenticated. The sending infrastructure matches the domain owner.
- Investigation meaning: Supports legitimacy of origin as an authorized marketing campaign, though categorized as low-priority spam based on user solicitation status.

## Email 2 — meddefense-portal.com
- SPF: FAIL (Sender IP 91.234.99.107 is not authorized for meddefense-portal.com).
- DKIM: NONE (No cryptographic DKIM signature present).
- DMARC: FAIL (Header From domain fails alignment due to SPF failure and missing DKIM; action=none).
- Authentication verdict: Failed. The sending server is unauthorized.
- Investigation meaning: Strongly supports suspicion of identity spoofing and active phishing, confirming the email is malicious.

## Email 3 — outlook-protection.com
- SPF: PASS (Sender IP 51.38.42.17 is authorized for outlook-protection.com).
- DKIM: PASS (Valid signature for header.d=outlook-protection.com).
- DMARC: PASS (Header From domain aligns with authenticated SPF/DKIM domains; action=none).
- Authentication verdict: Authenticated, but on an attacker-owned domain.
- Investigation meaning: Passing SPF, DKIM, and DMARC does not prove the email is legitimate. The domain outlook-protection.com is a malicious lookalike domain and is completely distinct from official Microsoft properties such as microsoft.com or outlook.com. The attacker configured valid authentication mechanisms on their registered domain to bypass basic email filters.

## Email 4 — meddefense.com
- SPF: PASS (Sender IP 10.10.1.15 is internal to meddefense.com).
- DKIM: PASS (Valid signature for header.d=meddefense.com using selector1).
- DMARC: PASS (Header From domain aligns with internal Exchange infrastructure; action=none).
- Authentication verdict: Fully Authenticated internal message.
- Investigation meaning: Confirms legitimate internal origin from the MedDefense Exchange server environment.

## Email 5 — medequip-supplies.net
- SPF: SOFTFAIL (Sender IP 185.176.43.22 is not explicitly authorized under SPF policy).
- DKIM: NONE (No cryptographic signature provided).
- DMARC: FAIL (Header From domain fails authentication alignment; action=none).
- Authentication verdict: Failed.
- Investigation meaning: Supports suspicion of fraudulent billing activity and spoofed sender infrastructure.

## Email 6 — canadian-pharma-discount.org
- SPF: SOFTFAIL (Sender IP is not explicitly authorized for canadian-pharma-discount.org).
- DKIM: NONE (No DKIM signature present).
- DMARC: FAIL (Authentication alignment failed; action=quarantine).
- Authentication verdict: Failed.
- Investigation meaning: Indicates unverified spam infrastructure, consistent with high-volume pharmaceutical spam.

## Email 7 — meddefense-benefits.org
- SPF: FAIL (Sender IP 164.90.218.73 is not authorized for meddefense-benefits.org).
- DKIM: NONE (No cryptographic signature present).
- DMARC: FAIL (Header From domain fails alignment; action=none).
- Authentication verdict: Failed.
- Investigation meaning: Confirms unauthorized sender attempting to impersonate internal HR benefits communications.

## Email 8 — hhs.gov
- SPF: PASS (Sender IP 134.174.47.82 is authorized for hhs.gov).
- DKIM: PASS (Valid signature for header.d=hhs.gov using selector hhs2026).
- DMARC: PASS (Header From domain fully aligns with official government domain; action=none).
- Authentication verdict: Fully Authenticated official government alert.
- Investigation meaning: Confirms trusted origin from the Department of Health and Human Services (HC3).
