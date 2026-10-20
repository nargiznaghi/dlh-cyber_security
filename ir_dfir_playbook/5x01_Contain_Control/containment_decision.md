# Containment Decision: IR-2026-0414-01

## Candidate strategies

### A. Network isolation (quarantine VLAN)
- action: move WST-WS-031 to VLAN 999, block all outbound, allow IR jumpbox access only
- attacker effect: C2 severed; attacker on-host observation paused
- evidence effect: volatile state preserved
- patient care effect: one lab workstation unavailable; site has four spare workstations available
- time to execute: ~5 min
- reversibility: fully reversible

### B. Host power-off
- action: immediate hard power-off/unplug of host WST-WS-031
- attacker effect: immediate termination of attacker processes, persistence execution, and C2 session
- evidence effect: completely destructive to volatile memory (RAM) and active network socket states
- patient care effect: immediate abrupt workstation disruption; potential loss of unsaved patient intake data
- time to execute: immediate (< 1 min)
- reversibility: non-reversible for volatile state loss; host power-on required

### C. Selective process kill + egress block
- action: terminate process MSBuild.exe (PID 8104) and powershell.exe (PID 7812); block IP 185.220.101.47 on perimeter firewall
- attacker effect: pauses active payload execution, but leaves underlying persistence mechanisms active
- evidence effect: alters memory state of running processes; preserves disk artifacts
- patient care effect: minimal impact; non-malicious clinical apps continue running
- time to execute: ~3 min
- reversibility: partially reversible; killed processes must be restarted manually

## Chosen: A
Rationale: preserves volatile evidence for later forensic analysis, severs C2 immediately, remains fully reversible, and bounds the clinical impact because spare workstations are available in the lab. Option B destroys volatile evidence. Option C risks missed processes and does not address persistence.

## Execution window
- Evidence preservation end: 03:14Z
- Containment execution start: 03:16Z

## Approval
- Action authorized by James Chen, IR Commander, at 03:10Z

## Rollback plan
- If lab operations are blocked and spare workstations are unavailable, revert VLAN assignment within five minutes and fall back to Option C.
