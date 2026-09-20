## Email 2 — meddefense-portal.com

### Header Evidence
- From: "MedDefense IT Security" <noreply@meddefense-portal.com>
- Return-Path: <noreply@meddefense-portal.com>
- Sending IP: 91.234.99.107
- X-Mailer: PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)
- Message-ID: <PHP-5D7E2F4A@meddefense-portal.com>

### Received Chain Summary
1. Received: from localhost (localhost [127.0.0.1]) by mail.meddefense-portal.com (PHPMailer 6.6.0) id PHP-5D7E2F4A; Mon, 14 Apr 2026 19:47:48 +0000
2. Received: from mail.meddefense-portal.com ([91.234.99.107]) by mx01.meddefense.com with ESMTP id 6E4A1B23 for <dmarsh@meddefense.com>; Mon, 14 Apr 2026 14:47:51 -0500
3. Received: from mx01.meddefense.com ([10.10.1.20]) by inbound-relay.meddefense.com with ESMTP id 7F8D3C9B for <dmarsh@meddefense.com>; Mon, 14 Apr 2026 14:47:52 -0500

### Anomalies
- [HIGH] Spoofed lookalike domain (`meddefense-portal.com`) designed to impersonate internal IT security portal.
- [HIGH] Failed SPF authentication (Sender IP 91.234.99.107 is not authorized for `meddefense-portal.com`).
- [HIGH] Missing DKIM signature (`dkim=none`).
- [MEDIUM] Mailer is open-source PHPMailer script on generic infrastructure rather than official enterprise gateway.

### Conclusion
Email 2 is an impersonation phishing attack originating from unauthorized external server IP `91.234.99.107` using a lookalike domain to harvest internal user credentials.

---

## Email 3 — outlook-protection.com

### Header Evidence
- From: "Microsoft Account Protection" <security@outlook-protection.com>
- Return-Path: <security@outlook-protection.com>
- Sending IP: 51.38.42.17
- X-Mailer: PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)
- Message-ID: <PHP-9F2D7E1B@outlook-protection.com>

### Received Chain Summary
1. Received: from wp-admin.outlook-protection.com (localhost [127.0.0.1]) by mail.outlook-protection.com (PHPMailer 6.6.0) id PHP-9F2D7E1B; Tue, 15 Apr 2026 14:13:40 +0000
2. Received: from mail.outlook-protection.com ([51.38.42.17]) by mx01.meddefense.com with ESMTPS (TLS1.2:ECDHE-RSA-AES128-GCM-SHA256) id 5D7A2B1C for <rmendez@meddefense.com>; Tue, 15 Apr 2026 09:13:43 -0500
3. Received: from mx01.meddefense.com ([10.10.1.20]) by inbound-relay.meddefense.com with ESMTP id 8A2B4E7C for <rmendez@meddefense.com>; Tue, 15 Apr 2026 09:13:44 -0500

### Anomalies
- [HIGH] Brand impersonation using lookalike domain (`outlook-protection.com`) instead of legitimate Microsoft domain (`accountprotection.microsoft.com`).
- [MEDIUM] Generated via local web script (PHPMailer on `wp-admin.outlook-protection.com`) rather than Microsoft infrastructure.
- [MEDIUM] DKIM key and domain pass authentication for attacker-controlled domain (`outlook-protection.com`), showing valid authentication on a malicious domain.

### Conclusion
Email 3 is a sophisticated brand impersonation credential phishing email that passes technical authentication (SPF/DKIM/DMARC) on an attacker-owned domain registered to imitate Microsoft Account Protection.

---

## Email 5 — medequip-supplies.net

### Header Evidence
- From: "MedEquip Supplies Billing" <invoices@medequip-supplies.net>
- Return-Path: <invoices@medequip-supplies.net>
- Sending IP: 185.176.43.22
- X-Mailer: PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)
- Message-ID: <PHP-7C2D4E1A@medequip-supplies.net>

### Received Chain Summary
1. Received: from billing-svc.medequip-supplies.net (localhost [127.0.0.1]) by mail.medequip-supplies.net (PHPMailer 6.6.0) id PHP-7C2D4E1A; Wed, 16 Apr 2026 16:28:35 +0000
2. Received: from mail.medequip-supplies.net ([185.176.43.22]) by mx01.meddefense.com with ESMTP id 1E4F2B8D for <arivera@meddefense.com>; Wed, 16 Apr 2026 11:28:37 -0500
3. Received: from mx01.meddefense.com ([10.10.1.20]) by inbound-relay.meddefense.com with ESMTP id 6B3E7A2C for <arivera@meddefense.com>; Wed, 16 Apr 2026 11:28:39 -0500

### Anomalies
- [HIGH] SPF result is `softfail` (Sending IP `185.176.43.22` is not explicitly permitted for `medequip-supplies.net`).
- [HIGH] Missing DKIM signature and DMARC verification failure.
- [MEDIUM] Uses PHPMailer bulk-sending script to deliver financial invoice attachments.

### Conclusion
Email 5 represents a targeted business email compromise (BEC) / fraudulent invoice lure originating from unverified infrastructure `185.176.43.22` with failing authentication headers.

---

## Email 7 — meddefense-benefits.org

### Header Evidence
- From: "MedDefense HR Benefits" <hr-notifications@meddefense-benefits.org>
- Return-Path: <hr-notifications@meddefense-benefits.org>
- Sending IP: 164.90.218.73
- X-Mailer: PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)
- Message-ID: <PHP-2E4A7B1C@meddefense-benefits.org>

### Received Chain Summary
1. Received: from wp-portal.meddefense-benefits.org (localhost [127.0.0.1]) by mail.meddefense-benefits.org (PHPMailer 6.6.0) id PHP-2E4A7B1C; Thu, 16 Apr 2026 20:22:02 +0000
2. Received: from mail.meddefense-benefits.org ([164.90.218.73]) by mx01.meddefense.com with ESMTP id 7D2F4B9A for <lpatterson@meddefense.com>; Thu, 16 Apr 2026 15:22:05 -0500
3. Received: from mx01.meddefense.com ([10.10.1.20]) by inbound-relay.meddefense.com with ESMTP id 3C8E4A7B for <lpatterson@meddefense.com>; Thu, 16 Apr 2026 15:22:07 -0500

### Anomalies
- [HIGH] Spoofed internal HR communications via lookalike domain (`meddefense-benefits.org`).
- [HIGH] Complete authentication breakdown (SPF `fail`, DKIM `none`, DMARC `fail`).
- [MEDIUM] Generated from WordPress environment (`wp-portal.meddefense-benefits.org`) using PHPMailer on DigitalOcean VPS IP `164.90.218.73`.

### Conclusion
Email 7 is an open-enrollment phishing lure sent from unauthorized cloud host `164.90.218.73` designed to capture user login details by masquerading as internal HR systems.
