| Email | From | Subject | SPF | DKIM | DMARC | Class | Priority | Evidence |
|---|---|---|---|---|---|---|---|---|
| E1 | newsletter@healthcare-education-weekly.com | Your April newsletter: Medication reconciliation best practices | PASS | PASS | PASS | SPAM | P4-LOW | Valid authentication headers; unsolicited healthcare marketing newsletter. |
| E2 | noreply@meddefense-portal.com | ACTION REQUIRED: Portal re-verification needed within 24 hours | FAIL | NONE | FAIL | SUSPICIOUS | P1-URGENT | User Diane Marsh clicked link; spoofed domain, failed SPF/DMARC. |
| E3 | security@outlook-protection.com | Unusual sign-in activity detected on your Microsoft 365 account | PASS | PASS | PASS | SUSPICIOUS | P2-HIGH | Phishing lure via lookalike domain (outlook-protection.com) impersonating Microsoft. |
| E4 | it-announcements@meddefense.com | Reminder: Quarterly password change window opens April 20 | PASS | PASS | PASS | LEGITIMATE | P4-LOW | Authentic internal Exchange communication from SOC lead with valid domain signatures. |
| E5 | invoices@medequip-supplies.net | Invoice INV-2026-04891 — Payment required within 7 days | SOFTFAIL | NONE | FAIL | SUSPICIOUS | P2-HIGH | Reported as invalid invoice by AP; softfail SPF, missing DKIM, urgent payment demand. |
| E6 | deals@canadian-pharma-discount.org | 90% OFF Viagra, Cialis, Xanax — No prescription needed!!! | SOFTFAIL | NONE | FAIL | SPAM | P4-LOW | Unsolicited pharmaceutical spam message with failed authentication. |
| E7 | hr-notifications@meddefense-benefits.org | Open Enrollment closes TOMORROW — action required | FAIL | NONE | FAIL | SUSPICIOUS | P2-HIGH | Unsolicited HR alert reported by user; spoofed domain with failed authentication. |
| E8 | HC3@hhs.gov | [HC3 ALERT — TLP:CLEAR] Active phishing campaign targeting regional healthcare | PASS | PASS | PASS | LEGITIMATE | P3-MEDIUM | Authentic government threat intelligence advisory from official hhs.gov domain. |

## Triage Summary
- SPAM: 2
- SUSPICIOUS: 4
- LEGITIMATE: 2
- Highest priority: E2 (P1-URGENT - User Diane Marsh clicked link)
