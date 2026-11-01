# Containment Execution Record: IR-2026-0420-01

- **Execution Window:** 2026-04-20T20:00Z – 2026-04-20T20:30Z
- **Lead Lead:** Nargiz Naghiyeva (IR Lead)
- **Strategy:** Option B (Targeted EDR Host Isolation & Selective Credential Revocation)

---

## Step-by-Step Execution Log

### Step 1: Perimeter Firewall Egress Block
- **Timestamp (UTC):** 2026-04-20T20:02Z
- **Actor:** Mike Torres (Network Engineer)
- **Action:** Applied perimeter firewall drop rules for external C2 IP `193.42.100.77` and DNS sinkholing for squatted CDN domains.
- **Expected Outcome:** Immediate termination of outbound HTTPS C2 traffic from all internal hosts.
- **Observed Outcome:** Firewall logs confirmed zero outbound connections traversing the perimeter to `193.42.100.77`.
- **Deviation Notes:** None.

### Step 2: Host Isolation — `CS-WS-101`
- **Timestamp (UTC):** 2026-04-20T20:08Z
- **Actor:** Nargiz Naghiyeva (IR Lead)
- **Action:** Applied EDR isolate policy to `CS-WS-101`, blocking all network traffic except management SSH/WinRM from IR jumpbox (`10.0.99.15`).
- **Expected Outcome:** Host isolated from intranet and external networks; IR jumpbox session maintained.
- **Observed Outcome:** EDR confirmed isolated status; active C2 process handles dropped.
- **Deviation Notes:** Executed after memory capture (ART-001) completed.

### Step 3: Host Isolation — `CS-WS-104` & `CS-WS-107`
- **Timestamp (UTC):** 2026-04-20T20:15Z
- **Actor:** Nargiz Naghiyeva (IR Lead)
- **Action:** Issued parallel EDR host isolation commands for `CS-WS-104` and `CS-WS-107`.
- **Expected Outcome:** Active Cobalt Strike service `WinHealthSvc` network sockets severed across both workstations.
- **Observed Outcome:** NetFlow logs showed complete drop in inbound/outbound packets for both IPs.
- **Deviation Notes:** Memory dumps acquired immediately prior to isolation step.

### Step 4: Host Isolation — `CS-WS-112`
- **Timestamp (UTC):** 2026-04-20T20:20Z
- **Actor:** Nargiz Naghiyeva (IR Lead)
- **Action:** Applied EDR isolate policy to `CS-WS-112`.
- **Expected Outcome:** Prevent lateral SMB pivot or secondary beacon activation on `CS-WS-112`.
- **Observed Outcome:** Isolation confirmed successfully by EDR console.
- **Deviation Notes:** None.

### Step 5: File Server Access Containment — `FILE-SVR-01`
- **Timestamp (UTC):** 2026-04-20T20:24Z
- **Actor:** Mike Torres (Network Engineer)
- **Action:** Applied IP restricted ACLs on `FILE-SVR-01` SMB shares, disconnecting sessions originating from `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, and `CS-WS-112`.
- **Expected Outcome:** Active SMB sessions from compromised workstations terminated; legitimate read access from clinical VLAN maintained.
- **Observed Outcome:** SMB session table cleared for compromised IPs; 0 active unauthorized share handles remaining.
- **Deviation Notes:** None.

### Step 6: Active Directory Credential Revocation
- **Timestamp (UTC):** 2026-04-20T20:28Z
- **Actor:** James Chen (SOC Lead)
- **Action:** Force-reset passwords and revoked active Kerberos/NTLM tokens for all user accounts logged into compromised workstations during the 72-hour window (including clinical coordinator and administrative service accounts). Initiated first KRBTGT password reset.
- **Expected Outcome:** Invalidation of stolen NTLM hashes and Golden/Silver Ticket TGTs.
- **Observed Outcome:** Kerberos ticket cache cleared across domain controllers; affected accounts prompted for re-authentication.
- **Deviation Notes:** Second KRBTGT reset scheduled for +24 hours per standard AD remediation procedures.

### Step 7: C2 Severance Verification
- **Timestamp (UTC):** 2026-04-20T20:30Z
- **Actor:** Nargiz Naghiyeva (IR Lead)
- **Action:** Executed NetFlow telemetry audit and EDR socket verification across all affected subnets.
- **Expected Outcome:** Proof of zero active C2 beacon traffic or unauthorized SMB activity across the enterprise.
- **Observed Outcome:** 100% C2 severance verified. No outbound connections to `193.42.100.77` or C2 domains detected.
- **Deviation Notes:** None.
