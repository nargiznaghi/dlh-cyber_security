# Social Engineering Analysis for MedDefense

## Scenario 1
* **Vector Type:** Brand Impersonation / Phishing
* **Target:** IT Director (Sarah Park). Vulnerable due to her ultimate accountability for core infrastructure security, making her reactive to critical perimeter threat warnings.
* **Psychological Lever:** Fear / Urgency
* **Red Flags:** * The sender domain `fortinet-support.net` is a non-official external domain instead of the official `fortinet.com` brand domain.
    * An extreme artificial timeline ("within 24 hours") combined with a threat of administrative penalty ("service termination").
    * A high-stakes directive forcing the download of an unverified attachment/patch directly via an email link rather than using an official support portal login.
* **Technical Control:** Deploy an Email Security Gateway (SEG) configured with strict SPF, DKIM, and DMARC enforcement alongside domain typosquatting protection to flag or drop external emails mimicking key vendors.
* **Administrative Control:** Implement an Asset and Patch Management Policy requiring all firmware updates to be cross-verified and retrieved directly from the vendor's authenticated portal, never via hyperlinks in inbound emails.

---

## Scenario 2
* **Vector Type:** Business Email Compromise (BEC) / Impersonation
* **Target:** CFO (Robert Kim). Vulnerable because he controls financial disbursements and is susceptible to direct, authoritative instructions from executive leadership.
* **Psychological Lever:** Authority / Urgency
* **Red Flags:**
    * A subtle variation or typo in the sender's email address compared to the CEO's legitimate corporate address.
    * An explicit command to bypass standard financial verification workflows and maintain secrecy ("Do not discuss with anyone").
    * An unnatural operational channel request ("email only" due to being "in meetings all day") for a high-value, out-of-band transaction.
* **Technical Control:** Configure internal mail server rules to append an external email warning banner to all incoming messages originating from outside the corporate network.
* **Administrative Control:** Establish a strict Dual-Authorization Financial Policy requiring voice verification or face-to-face secondary sign-off for any wire transfer exceeding a designated financial threshold, regardless of who requests it.

---

## Scenario 3
* **Vector Type:** Vishing / Pretexting
* **Target:** Clinical Nurse. Vulnerable due to a professional predisposition to be helpful during emergencies, combined with ongoing workplace stress and lack of dedicated technical validation training.
* **Psychological Lever:** Urgency / Helpfulness
* **Red Flags:**
    * An inbound telephone caller directly asking for plaintext authentication credentials over the phone line.
    * An unverified external or internal caller asserting authority by referencing a recent security incident to induce panic.
    * An unexpected, un-ticketed "emergency security audit" bypass that deviates from standard IT support communication channels.
* **Technical Control:** Implement an internal phone directory system with caller ID validation, and deploy a secure identity verification system within the IT service desk platform to push confirmation tokens to employees' mobile devices before discussing account details.
* **Administrative Control:** Mandate a comprehensive Clean Desk and Credential Protection Policy explicitly stating that IT support personnel will never request an employee's password via phone, email, or text, paired with an explicit verification callback procedure.

---

## Scenario 4
* **Vector Type:** Smishing
* **Target:** All MedDefense Employees. Vulnerable because parking permits represent a near-universal daily requirement, making them likely to react hastily to avoid immediate logistical disruption.
* **Psychological Lever:** Fear / Urgency
* **Red Flags:**
    * Receiving an operational corporate notification concerning facility management via an unprompted, generic SMS message on a personal or mobile device.
    * An urgent punitive consequence ("avoid towing") slated to occur within an aggressively short window ("tomorrow").
    * A hyperlink in an SMS message redirecting users to an unverified external URL rather than an internal corporate domain.
* **Technical Control:** Deploy an Enterprise Mobility Management solution on corporate mobile endpoints featuring web-content filtering to block known malicious or newly registered domains.
* **Administrative Control:** Enact an Acceptable Use Policy establishing that all official employee benefits, HR management updates, and facilities operations must occur through verified internal portals, explicitly banning SMS for official operations.

---

## Scenario 5
* **Vector Type:** Watering Hole Attack
* **Target:** MedDefense Physicians. Vulnerable because they regularly use this trusted professional industry website to maintain mandatory continuing medical education compliance.
* **Psychological Lever:** Familiarity / Trust
* **Red Flags:**
    * Unusual or unprompted browser behavior, such as unexpected redirects, lingering loading indicators, or pop-up boxes when viewing a familiar, trusted site.
    * Local endpoint security software or browser extensions throwing alerts about malicious scripts running on a normally benign page.
    * Unexpected prompts to update browser plug-ins, execute extensions, or clear cookies when accessing standard continuing education dashboards.
* **Technical Control:** Implement robust Endpoint Detection and Response (EDR) with integrated web protection and real-time browser isolation capabilities to block silent drive-by downloads and script exploits.
* **Administrative Control:** Maintain a rigorous Patch Management Policy ensuring all corporate endpoints run the latest secure versions of web browsers, operating systems, and security extensions to neutralize vulnerabilities.

---

## Scenario 6
* **Vector Type:** Typosquatting / Brand Impersonation
* **Target:** Patients and Staff. Vulnerable due to habitual reliance on search engines rather than bookmarks, combined with a lack of visual attention to minor regional spelling variants ("defence" vs. "defense").
* **Psychological Lever:** Familiarity / Trust
* **Red Flags:**
    * The search engine result is marked with an "Ad" or "Sponsored" tag and positioned above organic institutional results.
    * The domain suffix or text contains a foreign or alternative spelling (`meddefence-portal.com`) that contradicts the hospital's official branding (`meddefense.org`).
    * A password manager fails to auto-fill credentials on what visually appears to be the legitimate corporate login page.
* **Technical Control:** Implement phishing-resistant Multi-Factor Authentication (FIDO2 / WebAuthn) so that even if users input credentials into a fake site, the authentication handshake will fail because the domain does not match.
* **Administrative Control:** Engage a digital brand protection or threat intelligence service to monitor registry databases for typosquatting domains and proactively initiate legal takedowns of fraudulent sites mimicking MedDefense.

---

## Scenario 7
* **Vector Type:** Impersonation / Tailgating
* **Target:** Physical Security / Badged IT Personnel. Vulnerable due to cultural pressure within healthcare to accommodate peers, a natural desire to be helpful, and physical distractions in restricted areas.
* **Psychological Lever:** Helpfulness / Familiarity
* **Red Flags:**
    * An individual utilizing a social engineering prop (scrubs, stethoscope, coffee cup) to cultivate a false sense of clinical identity near an IT-specific restricted zone.
    * An employee attempting to enter a high-security zone without actively scanning their own access badge, offering a convenience excuse ("badge is in my locker").
    * A visitor badge that is partially concealed from direct line-of-sight or reveals an expired validation date upon closer observation.
* **Technical Control:** Install physical access control mechanisms such as turnstiles, mantraps, or anti-tailgating smart sensors at high-security access points to physically restrict multi-person entries on a single badge swipe.
* **Administrative Control:** Formulate a strict Physical Security Policy mandating that all employees actively challenge anyone attempting to tailgate behind them, backed by a mandatory badging protocol that penalizes badge-sharing or credential bypasses.
