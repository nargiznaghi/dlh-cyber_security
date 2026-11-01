# Containment Strategy Decision: IR-2026-0420-01

## Strategic Options Analysis

### Option A: Complete Subnet Shutdown & Hard Power-Off
- **Action:** Pull power cables on `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, `CS-WS-112`, and `FILE-SVR-01`, and disable the Site A clinical core switch.
- **Effect on Attacker:** Immediately severs all active C2 channels, prevents lateral movement, and eliminates ransomware execution risk.
- **Effect on Patient Care:** Catastrophic. Halts all ED charge desk operations, blocks access to patient records, and disrupts acute clinical care.
- **Evidence Preserved/Destroyed:** Preserves disk state; destroys volatile RAM across all uncaptured hosts and clears running network socket tables.
- **Time to Execute:** ~2 minutes.
- **Reversibility:** Low (requires lengthy filesystem integrity checks, server reboots, and service re-initialization).

### Option B: Targeted EDR Host Isolation & Selective Credential Revocation (Chosen Strategy)
- **Action:** Execute software-based network isolation via EDR/firewall rules on `CS-WS-101`, `CS-WS-104`, `CS-WS-107`, and `CS-WS-112` (allowing IR jumpbox access), block external C2 egress IPs at the perimeter, restrict `FILE-SVR-01` access, and reset compromised credentials.
- **Effect on Attacker:** Neutralizes Cobalt Strike beaconing, prevents lateral movement, and blocks staged ransomware activation while keeping host memory accessible for acquisition.
- **Effect on Patient Care:** Moderate / Managed. Disables 4 specific clinical workstations; clinical staff switch to secondary workstation pools and paper contingency workflows while `FILE-SVR-01` remains available for read-only clinical access under strict IP filtering.
- **Evidence Preserved/Destroyed:** Preserves full volatile memory and disk state across all hosts; zero forensic destruction.
- **Time to Execute:** ~5–10 minutes.
- **Reversibility:** High (isolation rules can be instantly modified or reverted via EDR/firewall policy).

### Option C: Passive Monitoring & Perimeter Sinkholing
- **Action:** Redirect C2 domain DNS to internal sinkhole; leave workstations fully connected to preserve attacker operational context.
- **Effect on Attacker:** Partially disrupts C2 egress, but leaves local persistence (`WinHealthSvc`) and lateral NTLM paths active inside the intranet.
- **Effect on Patient Care:** Zero immediate impact, but exposes clinical operations to high risk of unmitigated ransomware deployment.
- **Evidence Preserved/Destroyed:** Preserves memory and disk state; exposes live system to further tampering or wiper activation.
- **Time to Execute:** ~15 minutes.
- **Reversibility:** High.

---

## Chosen Strategy & Trade-off Rationale

**Declared Strategy:** Option B (Targeted EDR Host Isolation & Selective Credential Revocation)

Option B balances clinical continuity with complete containment of the active threat. Hard power-off (Option A) would cripple Emergency Department operations and destroy critical volatile evidence, whereas passive sinkholing (Option C) leaves MedDefense vulnerable to automated ransomware execution from staged scripts. Targeted EDR isolation immediately severs Cobalt Strike C2 communication (`193.42.100.77`) and stops lateral movement, while preserving live memory for forensic acquisition and allowing clinical teams to maintain patient care via backup terminals.

- **Authorizing Role:** Dr. Patricia Morales (CISO / Incident Commander)
- **Rollback Trigger:** Unexpected failure of secondary clinical workstation pools causing critical patient safety impairment, or loss of emergency file server access required for acute patient intervention.
