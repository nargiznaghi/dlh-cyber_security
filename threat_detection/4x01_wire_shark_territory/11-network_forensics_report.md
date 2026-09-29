# Network Forensics Investigation Report

## Executive Summary
Between April 14 and April 15, 2026, MedDefense experienced a multi-stage network compromise initiated via a targeted spear-phishing email sent to clinical user dmarsh. The attacker harvested credentials through a spoofed web portal, established encrypted C2 beaconing, and subsequently pivoted into the internal network using stolen VPN credentials. Utilizing Remote Desktop Protocol (RDP) and Server Message Block (SMB), the attacker moved laterally from clinical workstation WS-NURSE-04 to internal servers, including billing-srv-01 and NAS-01. Over a 30-minute window on April 15, approximately 120 anomalous DNS TXT queries were used to exfiltrate structured healthcare records over an encrypted DNS tunnel. Internal network segmentation restricted attacker access to secondary production subnets, but clinical credential exposure and exfiltration of billing data present severe regulatory and business impact.

## Investigation Scope
This investigation analyzed six primary Packet Capture (PCAP) files provided in the incident repository covering activities from April 14, 2026, 14:45 UTC to April 15, 2026, 23:00 UTC:
* `4x00 email evidence` (Email context logs)
* `phishing_click.pcap`
* `c2_beaconing.pcap`
* `dns_exfil.pcap`
* `lateral_movement.pcap`
* `full_timeline.pcap`

Primary analysis tools included `tshark`, `wireshark`, `Zeek`, `mergecap`, and standard Unix text processing utilities. Endpoint process execution logs, SIEM telemetry, host-based memory dumps, and VPN authentication service logs were unavailable during this network packet analysis phase.

## Methodology
The investigation followed a multi-tiered network forensic methodology:
1. **Baseline Establishment:** Profiling normal internal IP ranges (10.10.0.0/16), default DNS queries, and legitimate administrative protocol traffic.
2. **Known-IOC Search:** Querying captures for previously identified malicious IP addresses (91.234.99.107) and domain indicators (`meddefense-portal.com`).
3. **DNS Analysis:** Examining query frequency, record types (TXT, A, AAAA), subdomain label entropy, and record length anomalies.
4. **TLS Metadata Analysis:** Inspecting Server Name Indication (SNI) extensions, TLS handshake metrics, and certificate parameters without decrypting payloads.
5. **Timing & Behavioral Analysis:** Calculating connection intervals, delta times, and statistical variance to identify automated C2 beaconing.
6. **Cross-PCAP Correlation:** Reconstructing the master attack timeline across individual PCAP fragments into a unified chronological sequence.

## Findings by Attack Phase

### Phase 1: Initial Access
* **Description:** Spear-phishing email delivered to `dmarsh@meddefense.com` containing a link to a credential harvesting site.
* **Evidence Citation:** 4x00 email evidence, Email 2 (2026-04-14 14:47:12 UTC).
* **MITRE ATT&CK Mapping:** T1566.002 (Spearphishing Link).
* **Confidence Level:** High (Context supported).
* **Proof:** Email header metadata proves delivery; packet capture not applicable for this phase.

### Phase 2: Credential Harvesting Session
* **Description:** User clicked the phishing link, resulting in DNS resolution and TLS session establishment with the malicious portal.
* **Evidence Citation:** `phishing_click.pcap` (2026-04-14 15:02:33 to 15:03:20 UTC).
* **MITRE ATT&CK Mapping:** T1056.003 (Web Portal Capture).
* **Confidence Level:** High (Confirmed via packets & metadata).
* **Proof:** Proves DNS lookup for `meddefense-portal.com` -> `91.234.99.107` and encrypted HTTP POST volume (487 bytes) at 15:02:58 UTC.

### Phase 3: Beaconing
* **Description:** Automated C2 beaconing initiated from internal workstation WS-NURSE-04 (`10.10.2.15`) to the attacker server.
* **Evidence Citation:** `c2_beaconing.pcap` (2026-04-15 02:00:00 to 03:55:00 UTC).
* **MITRE ATT&CK Mapping:** T1071.001 (Application Layer Protocol: Web Protocols).
* **Confidence Level:** Confirmed.
* **Proof:** Proves 24 regular HTTPS connections at ~300-second intervals with low jitter (<15% variance).

### Phase 4: External Access / VPN Pivot
* **Description:** Attacker established an external SSL-VPN session targeting the corporate gateway using compromised user credentials (`dmarsh`).
* **Evidence Citation:** `full_timeline.pcap` (2026-04-15 13:45:22 UTC).
* **MITRE ATT&CK Mapping:** T1133 (External Remote Services).
* **Confidence Level:** High (Strong inference from metadata).
* **Proof:** Proves incoming TLS session from Nigerian IP `154.118.42.89:49872` to VPN endpoint `10.10.0.1:443`, assigning internal IP `10.10.2.200`.

### Phase 5: Lateral Movement
* **Description:** Attacker initiated an RDP connection from WS-NURSE-04 to `billing-srv-01`.
* **Evidence Citation:** `lateral_movement.pcap` (2026-04-15 14:30:12 UTC).
* **MITRE ATT&CK Mapping:** T1021.001 (Remote Services: Remote Desktop Protocol).
* **Confidence Level:** Confirmed.
* **Proof:** Proves RDP protocol handshake and traffic stream from `10.10.2.15` to `10.10.1.10`.

### Phase 6: Discovery
* **Description:** SMB network enumeration and directory listing attempted across internal file servers and NAS devices.
* **Evidence Citation:** `lateral_movement.pcap` (2026-04-15 14:35:00 to 14:42:00 UTC).
* **MITRE ATT&CK Mapping:** T1135 (Network Share Discovery), T1083 (File and Directory Discovery).
* **Confidence Level:** Confirmed.
* **Proof:** Proves SMB2 Tree Connect requests to `NAS-01`, with specific share queries returning success and restricted subnets returning TCP RST / Access Denied.

### Phase 7: Exfiltration
* **Description:** Encrypted data exfiltration conducted via high-frequency DNS TXT queries with encoded subdomains.
* **Evidence Citation:** `dns_exfil.pcap` (2026-04-15 22:15:00 to 22:45:00 UTC).
* **MITRE ATT&CK Mapping:** T1048.003 (Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Non-Application Protocol).
* **Confidence Level:** Confirmed.
* **Proof:** Proves 120 anomalous DNS TXT requests targeting subdomains of `data-sync.meddefense-portal.com` containing base64-encoded labels >40 characters.

## Network-Level IOC Table

| Type | Value | Source | Confidence | Detection Utility |
|---|---|---|---|---|
| Domain | `meddefense-portal.com` | `phishing_click.pcap` | High | High (Block DNS / SNI) |
| Domain | `data-sync.meddefense-portal.com` | `dns_exfil.pcap` | High | High (DNS Sinkhole) |
| IPv4 | `91.234.99.107` | `phishing_click.pcap` / `c2_beaconing.pcap` | High | High (Perimeter Firewall Block) |
| IPv4 | `154.118.42.89` | `full_timeline.pcap` | High | Medium (GeoIP / VPN Block) |
| Subdomain Pattern | `*.data-sync.meddefense-portal.com` | `dns_exfil.pcap` | High | High (DNS Tunneling Rule) |

## Impact Assessment
* **Data Likely Exfiltrated:** Structured patient billing and medical records staged during SMB discovery and exfiltrated over DNS TXT tunnel (~120 payloads).
* **Systems Involved:** WS-NURSE-04 (`10.10.2.15`), VPN Endpoint (`10.10.0.1`), Billing Server `billing-srv-01` (`10.10.1.10`), and NAS Storage `NAS-01` (`10.10.1.20`).
* **Systems Protected/Not Reached:** Restrictive ACLs successfully blocked access attempts to core EMR databases and administrative domain controllers (refused TCP connection resets recorded).
* **Credential Exposure:** Account `dmarsh` fully compromised across Active Directory, VPN, and RDP environments.
* **Regulatory/Business Concerns:** Potential HIPAA breach requiring mandatory notifications due to exfiltration of Protected Health Information (PHI).

## Detection Gap Analysis
1. **Email Gateway & Phishing Filter Gap:** Lookalike domain `meddefense-portal.com` was not flagged upon initial user delivery or click.
2. **C2 Beaconing Visibility Gap:** Lack of automated network session profiling permitted 24 periodic HTTPS connections to go unnoticed over 2+ hours.
3. **VPN Anomaly Gap:** Absence of GeoIP velocity or unusual ASN login detection allowed connection from Lagos, Nigeria (`AS37148`) without alerting.
4. **Cross-Role Lateral Movement Gap:** No behavioral alerting for clinical workstation accounts establishing RDP sessions directly to billing server subnets.
5. **DNS Tunneling Gap:** Absence of payload length and record-type frequency monitoring permitted 120 high-length TXT queries to egress freely.

## Detection Rules Recommended

| Rule Name | Data Source Required | Attack Phase Detected | False Positive Considerations |
|---|---|---|---|
| C2 Beaconing Frequency Alert | Zeek `conn.log` / NetFlow | Phase 3 (C2 Beaconing) | Legitimate software update services or cloud sync agents |
| DNS Query Label Length Anomaly | DNS Resolver Logs / PCAP | Phase 7 (Exfiltration) | Complex DKIM/TXT record lookups or security agents |
| VPN Geographic/ASN Anomaly | VPN Authentication Logs | Phase 4 (VPN Pivot) | Legitimate international travel or commercial VPN users |
| Cross-Role RDP Session Alert | Windows Security Event Logs / Network TAP | Phase 5 (Lateral Movement) | Authorized IT maintenance or emergency clinical access |
| High-Volume DNS TXT Pattern | NetFlow / DNS Logs | Phase 7 (Exfiltration) | High-volume email authentication validation tools |

## Recommendations

### Immediate (Next 24 Hours)
* Isolate host WS-NURSE-04 (`10.10.2.15`) and disconnect compromised session `10.10.2.200`.
* Perform mandatory password reset and revoke active tokens for user `dmarsh`.
* Block IP indicators (`91.234.99.107`, `154.118.42.89`) and domain `meddefense-portal.com` on edge firewalls and DNS resolvers.
* Preserve full memory and disk images of `10.10.2.15` and `10.10.1.10`.

### Short-term (Next 7 Days)
* Deploy behavioral DNS tunneling detection rules on core resolvers.
* Audit all active VPN sessions for geographic and ASN anomalies.
* Restrict egress DNS traffic so internal hosts can only query internal resolvers.
* Perform environment-wide hunting for secondary C2 indicators or persistence mechanisms.

### Medium-term (Next 30 Days)
* Implement strict Multi-Factor Authentication (MFA) with conditional access (location/device health) for all VPN users.
* Enforce network segmentation preventing clinical VLANs from directly establishing RDP sessions to server subnets.
* Conduct a formal HIPAA breach impact assessment based on exfiltrated record volume.

## Evidence Chain

| PCAP File | Purpose | Capture Time Window | Storage Location / Notes |
|---|---|---|---|
| `phishing_click.pcap` | Capture credential harvesting web interaction | 2026-04-14 15:02 - 15:03 UTC | Incident Repo (`/threat_detection/4x01_wire_shark_territory`) |
| `c2_beaconing.pcap` | Capture automated HTTPS C2 communications | 2026-04-15 02:00 - 03:55 UTC | Incident Repo (`/threat_detection/4x01_wire_shark_territory`) |
| `full_timeline.pcap` | Capture VPN pivot session and master network events | 2026-04-15 13:45 - 15:00 UTC | Incident Repo (`/threat_detection/4x01_wire_shark_territory`) |
| `lateral_movement.pcap` | Capture RDP session and SMB share discovery | 2026-04-15 14:30 - 14:45 UTC | Incident Repo (`/threat_detection/4x01_wire_shark_territory`) |
| `dns_exfil.pcap` | Capture anomalous DNS TXT tunneling traffic | 2026-04-15 22:15 - 22:45 UTC | Incident Repo (`/threat_detection/4x01_wire_shark_territory`) |

## Continuity with 4x00
This network forensics investigation directly validates and expands the findings established in investigation 4x00:
1. **Credential Exposure:** Upgraded from "suspected compromised" to **confirmed exploited**, evidenced by successful VPN authentication and RDP movement using `dmarsh` context.
2. **Timeline Precision:** Established exact timestamps for post-click attacker behavior, bridging the gap between April 14 phishing and April 15 exfiltration.
3. **Infrastructure Linkage:** Associated phishing domain `meddefense-portal.com` directly to C2 IP `91.234.99.107` and subsequent DNS exfiltration endpoints.
4. **Impact Expansion:** Expanded the incident scope from a local email click to a multi-system network compromise culminating in data exfiltration over DNS.
