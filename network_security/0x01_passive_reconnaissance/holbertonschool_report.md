# Passive Reconnaissance Notes
**Project:** Passive Reconnaissance   
**Tool Used:** Shodan  

---

## Target 1 — 18.154.101.76

### General Information

| Field | Value |
|-------|-------|
| Hostname | `server-18-154-101-76.den52.r.cloudfront.net` |
| Domain | `cloudfront.net` |
| Cloud Provider | Amazon |
| Cloud Region | GLOBAL |
| Cloud Service | CloudFront |
| Country | United States |
| City | Aetna Estates |
| Organization | Amazon.com, Inc. |
| ISP | Amazon.com, Inc. |
| ASN | AS16509 |

### Open Ports

| Port | Protocol | Response | Notes |
|------|----------|----------|-------|
| 80 | TCP | 403 Forbidden | CloudFront httpd — direct IP access blocked; requires valid `Host` header matching a configured distribution |

### Web Technologies

| Category | Technology |
|----------|-----------|
| CDN | Amazon CloudFront |
| PaaS | Amazon Web Services |

### HTTP Response Details (Port 80)

```
HTTP/1.1 403 Forbidden
Server: CloudFront
Date: Wed, 27 May 2026 11:38:17 GMT
Content-Type: text/html
Content-Length: 915
Connection: keep-alive
X-Cache: Error from cloudfront
Via: 1.1 4bb08411ba89edb53d3520e2681c55f2.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: DEN52-P3
X-Amz-Cf-Id: I3iZ26X0u0Ary6FoZFTwa-3Zh59v8VmopjnStkpDp7RWM-0NDfwrKA==
```

### Key Observations

- This is a **CloudFront edge node**, not an origin server.
- The 403 on port 80 is expected — CloudFront rejects requests without a valid `Host` header tied to a distribution.
- **PoP:** DEN52-P3 (Denver, CO edge location).
- The actual origin (S3, EC2, ALB, etc.) is hidden behind CloudFront.
- To identify the application behind it: check certificate transparency logs (e.g. `crt.sh`), passive DNS, or reverse DNS for domains pointing to this distribution.

---

## Target 2 — 216.198.54.2

### General Information

| Field | Value |
|-------|-------|
| Hostname | `zendesk.com` |
| Domain | `zendesk.com` |
| Country | United States |
| City | San Francisco |
| Organization | Zendesk, Inc. |
| ISP | Cloudflare London, LLC |
| ASN | AS209242 |
| Shodan Tags | `ai` |
| Last Seen | 2026-05-27 |

### Infrastructure Stack

| Category | Technology |
|----------|-----------|
| CDN | Cloudflare |
| Web Server | Nginx |
| Reverse Proxy | Nginx |
| PaaS | Amazon Web Services |

### Open Ports — Full Breakdown

| Port | Protocol | Response Code | Banner / Notes |
|------|----------|---------------|----------------|
| 80 | TCP | 301 Moved Permanently | Redirects to `https://aventura.zendesk.com`; sets Cloudflare cookies |
| 443 | TCP | 429 Too Many Requests | Cloudflare bot protection / Turnstile challenge active |
| 2052 | TCP | 403 Forbidden | **LM Studio** identified — possible local LLM inference server exposed |
| 2053 | TCP | 400 Bad Request | Cloudflare HTTPS alt port — plain HTTP sent to HTTPS port |
| 2082 | TCP | 403 Forbidden | Cloudflare alt port |
| 2083 | TCP | 400 Bad Request | Cloudflare HTTPS alt port |
| 2086 | TCP | 403 Forbidden | Cloudflare alt port |
| 2087 | TCP | 400 Bad Request | Cloudflare HTTPS alt port |
| 2095 | TCP | 403 Forbidden | Cloudflare alt port |
| 2096 | TCP | 400 Bad Request | Cloudflare HTTPS alt port |
| 6443 | TCP | 400 Bad Request | **mTLS required** — `No required SSL certificate was sent`; possible Kubernetes API server; leaks internal CF-BCK-Digest routing metadata |
| 8080 | TCP | 403 Forbidden | Cloudflare alt port |
| 8443 | TCP | 400 Bad Request | Cloudflare HTTPS alt port |
| 8880 | TCP | 403 Forbidden | Cloudflare error code 1003 — access denied |

### HTTP Response Details

#### Port 80 — Redirect
```
HTTP/1.1 301 Moved Permanently
Location: https://aventura.zendesk.com/
Server: cloudflare
CF-RAY: a025b20ca8c28c7a-AMS
Cache-Control: max-age=3600
Set-Cookie: __cf_bm=[...]; domain=.zendesk.com; HttpOnly
```

#### Port 443 — Bot Challenge
```
HTTP/1.1 429 Too Many Requests
cf-mitigated: challenge
cross-origin-embedder-policy: require-corp
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
permissions-policy: accelerometer=(), browsing-topics=(), camera=(), ...
content-security-policy: default-src 'none'; script-src 'nonce-...' 'unsafe-eval'
  https://challenges.cloudflare.com; ...
Server: cloudflare
CF-RAY: a025b212efdc1eef-BLR
```

#### Port 2052 — LM Studio
```
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=UTF-8
Content-Length: 16
Server: cloudflare
CF-RAY: 9fb897a0ad6ed498-LAX
Banner: LM Studio
```

#### Port 6443 — mTLS Endpoint (Internal Metadata Leak)
```
HTTP/1.1 400 Bad Request
Server: cloudflare-nginx
CF-Bck-Ctrl-1: {"ob_enable":false}
CF-BCK-Digest: {
  "req_start": 1778546435.688,
  "proxy_port": 80,
  "cache_server": "1231c112",
  "cache_ip": "216.198.54.2",
  "backend_used": "nginx",
  "status_code": 400,
  "number_of_origin_ips": 0
}
```

#### Port 8880 — Error Code 1003
```
HTTP/1.1 403 Forbidden
error code: 1003
Server: cloudflare
CF-RAY: a01e3ee91a0c67aa-DFW
```

### SSL Certificate (Port 443)

| Field | Value |
|-------|-------|
| Issuer | Let's Encrypt — CN=E8 |
| Valid From | Apr 30, 2026 15:26:51 GMT |
| Valid Until | Jul 29, 2026 15:26:50 GMT |
| Subject | `CN=zendesk.com` |
| SANs | `*.zendesk.com`, `zendesk.com` |
| Algorithm | ECDSA with SHA384 |
| Key | EC 256-bit / P-256 |
| CA | FALSE (end-entity cert) |
| OCSP | via Let's Encrypt E8 |

### Key Observations

- **Port 2052 — LM Studio:** The presence of an LM Studio banner (local LLM inference server) on a Zendesk IP is notable. This aligns with Shodan's `ai` tag and likely relates to Zendesk's AI product development. Even returning 403, the service fingerprint is visible.
- **Port 6443 — Kubernetes / mTLS:** Port 6443 is the standard Kubernetes API server port. The `400 No required SSL certificate was sent` response confirms mTLS is enforced. The `CF-BCK-Digest` header leaks internal Cloudflare routing metadata: cache server IDs, proxy port, origin IP confirmation, and backend stack.
- **Port 443 — Hardened:** Active Cloudflare bot protection with Turnstile challenge, strict CSP, extensive `permissions-policy`, and `cf-mitigated: challenge` headers. Well-hardened surface.
- **Port 80 — Redirect:** Redirects to `aventura.zendesk.com` — this subdomain may be worth enumerating further.
- **Cookie Leak:** Multiple Cloudflare `__cf_bm` and `_cfuvid` session cookies visible in response headers from Shodan banners.

---

## Target 3 — 198.202.211.1

### General Information

| Field | Value |
|-------|-------|
| Hostname | `securview.com` |
| Domain | `securview.com` |
| Country | Germany |
| City | Berlin |
| Organization | Webflow, Inc. |
| ISP | Cloudflare London, LLC |
| ASN | AS209242 |
| Last Seen | 2026-05-27 |

### Infrastructure Stack

| Category | Technology |
|----------|-----------|
| CDN | Cloudflare |
| Web Server | Nginx |
| Reverse Proxy | Nginx |
| Hosting Platform | Webflow |
| Backend Region | AWS us-east-1 |

### Open Ports — Full Breakdown

| Port | Protocol | Response Code | Banner / Notes |
|------|----------|---------------|----------------|
| 80 | TCP | 403 Forbidden | **"DNS points to prohibited IP"** — Yandex/CDEK/Sber domain flagged in banner |
| 443 | TCP | 200 OK | **Live SecurView app** — Webflow hosted; leaks internal lambda ID and surrogate keys |
| 2052 | TCP | 403 Forbidden | Cloudflare alt port |
| 2053 | TCP | 400 Bad Request | Cloudflare HTTPS alt port |
| 2082 | TCP | 403 Forbidden | Cloudflare alt port |
| 2083 | TCP | 400 Bad Request | Cloudflare HTTPS alt port |
| 2086 | TCP | 403 Forbidden | Cloudflare alt port |
| 2087 | TCP | 400 Bad Request | Cloudflare alt port |
| 2095 | TCP | 403 Forbidden | Cloudflare alt port |
| 6443 | TCP | 400 Bad Request | **mTLS required** — leaks CF-BCK-Digest with `cache_ip: 198.202.211.1`; same pattern as Target 2 |
| 8080 | TCP | 403 Forbidden | Cloudflare alt port |
| 8443 | TCP | 400 Bad Request | Cloudflare HTTPS alt port |
| 8880 | TCP | 403 Forbidden | Cloudflare alt port |

### HTTP Response Details

#### Port 80 — Prohibited IP Flag
```
HTTP/1.1 403 Forbidden
Banner: DNS points to prohibited IP |
        cdek.sbermegamarket.yandex.nalozhka.xhousingprod1.ellington.com | Cloudflare
Server: cloudflare
cf-cache-status: DYNAMIC
CF-RAY: a025bd8c9b4f656b-AMS
```

#### Port 443 — Live Application (200 OK)
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Server: cloudflare
CF-Cache-Status: HIT
Age: 89456
Last-Modified: Wed, 27 May 2026 06:31:31 GMT
Strict-Transport-Security: max-age=31536000
surrogate-control: max-age=2147483647
surrogate-key: www.securview.com 691b808f441dad2217f7106d pageId:691b808f441dad2217f710e0
x-lambda-id: d95e3644-223c-4c69-9f92-5ec1099b7f49
x-wf-region: us-east-1
alt-svc: h3=":443"; ma=86400
```

#### Port 6443 — mTLS Endpoint (Internal Metadata Leak)
```
HTTP/1.1 400 Bad Request
Server: cloudflare-nginx
CF-BCK-Digest: {
  "req_start": 1778547627.657,
  "proxy_port": 80,
  "cache_server": "465c170",
  "cache_ip": "198.202.211.1",
  "backend_used": "nginx",
  "status_code": 400,
  "number_of_origin_ips": 0
}
```

### SSL Certificate (Port 443)

| Field | Value |
|-------|-------|
| Issuer | Google Trust Services — CN=WE1 |
| Valid From | May 17, 2026 09:02:49 GMT |
| Valid Until | Aug 15, 2026 10:02:43 GMT |
| Subject | `CN=securview.com` |
| SANs | `securview.com` (no wildcard) |
| Algorithm | ECDSA with SHA256 |
| Key | EC 256-bit / P-256 |
| CA | FALSE (end-entity cert) |
| OCSP | `http://o.pki.goog/s/we1/AhQ` |

### Key Observations

- **Port 80 — Russian Domain Collision:** The Cloudflare banner explicitly flags `cdek.sbermegamarket.yandex.nalozhka.xhousingprod1.ellington.com` as pointing to a prohibited IP. CDEK is a major Russian logistics company; Sber MegaMarket is a Russian e-commerce platform. This suggests a DNS misconfiguration, shared IP collision, or possible domain fronting abuse. Warrants further investigation.
- **Port 443 — Webflow Internal Headers Leaked:**
  - `x-lambda-id` exposes a Webflow serverless function identifier.
  - `surrogate-key` leaks Webflow internal page and content IDs.
  - `x-wf-region: us-east-1` confirms Webflow backend runs on AWS us-east-1.
  - `CF-Cache-Status: HIT` with `Age: 89456` — content heavily cached at edge.
- **Port 6443 — mTLS (same pattern as Target 2):** Identical CF-BCK-Digest behavior confirms this is consistent Cloudflare infrastructure behavior across AS209242, not target-specific. Origin IP `198.202.211.1` confirmed in the digest.
- **No wildcard SAN:** The SSL cert only covers `securview.com` — no subdomains protected, unlike Zendesk's wildcard cert.

---

## Cross-Target Analysis

### Shared Infrastructure Patterns

| Pattern | Target 2 (216.198.54.2) | Target 3 (198.202.211.1) |
|---------|------------------------|--------------------------|
| ASN | AS209242 | AS209242 |
| ISP | Cloudflare London, LLC | Cloudflare London, LLC |
| CDN | Cloudflare | Cloudflare |
| Web Server | Nginx | Nginx |
| Port 6443 mTLS | Yes — CF-BCK-Digest leak | Yes — CF-BCK-Digest leak |
| Alt ports (2052–2096) | Yes | Yes |
| Bot protection on 443 | Yes (429 challenge) | No (200 OK) |

### Port 6443 — CF-BCK-Digest Leak (Both Targets)

Both 216.198.54.2 and 198.202.211.1 expose internal Cloudflare routing metadata via the `CF-BCK-Digest` header on port 6443. This is a consistent behavior of Cloudflare's infrastructure on AS209242 when an mTLS-protected endpoint receives a plain HTTP probe. The digest includes:

- `cache_server` — internal Cloudflare cache node ID
- `cache_ip` — confirms the actual IP being probed
- `backend_used` — confirms Nginx as the backend
- `proxy_port` — internal proxy port (80)
- `number_of_origin_ips` — 0 (no origin reached, request rejected at edge)

### Notable Unique Findings

| Finding | Target | Significance |
|---------|--------|-------------|
| LM Studio on port 2052 | 216.198.54.2 (Zendesk) | AI inference server fingerprinted; aligns with Shodan `ai` tag |
| Russian domain collision on port 80 | 198.202.211.1 (SecurView) | DNS misconfiguration or domain fronting; Russian e-commerce domains (CDEK, Sber) flagged as prohibited |
| Webflow internal IDs in headers | 198.202.211.1 (SecurView) | `x-lambda-id`, `surrogate-key`, `x-wf-region` leaked |
| CloudFront origin hiding | 18.154.101.76 | True origin IP/service not discoverable via direct probe |
| `aventura.zendesk.com` redirect | 216.198.54.2 (Zendesk) | Subdomain worth enumerating |

---

## Recommended Next Steps

1. **18.154.101.76 (CloudFront):** Search `crt.sh` for certificates issued to domains resolving to this IP. Check passive DNS (SecurityTrails, RiskIQ) for domains fronted by this distribution. Use the `Via` header CF distribution ID for further pivoting.

2. **216.198.54.2 (Zendesk):** Enumerate `aventura.zendesk.com` and other subdomains. Investigate LM Studio on port 2052 further — check if any API endpoints are accessible with proper Host headers. Review CF-BCK-Digest cache server `1231c112` for cross-target correlation.

3. **198.202.211.1 (SecurView):** Investigate the Russian domain (`cdek.sbermegamarket.yandex.nalozhka.xhousingprod1.ellington.com`) DNS collision. Use the leaked `x-lambda-id` and `surrogate-key` values for Webflow-specific recon. Check if `*.securview.com` subdomains exist (not covered by the cert SAN).

4. **AS209242 (Cloudflare London):** Both Zendesk and SecurView share this ASN. Consider expanding recon across this ASN for related infrastructure.

---

*Notes generated from Shodan passive reconnaissance. No active scanning performed.*
