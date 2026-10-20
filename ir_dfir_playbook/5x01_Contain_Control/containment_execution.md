# Containment Execution: IR-2026-0414-01

- 2026-04-14T03:16:04Z | James Chen | switchport VLAN reassign WST-WS-031 -> VLAN 999 | host reachable only from jumpbox | confirmed via ping from SOC jumpbox; timeout from user VLAN | no deviation
- 2026-04-14T03:17:21Z | James Chen | firewall deny outbound ip 185.220.101.47 and 91.234.99.107 | egress traffic blocked; netflow records zero packets/bytes | verified via siem/netflow.json (packets: 0, bytes: 0) | no deviation
- 2026-04-14T03:19:02Z | James Chen | endpoint device containment flag SET on WST-WS-031 | only analyst tooling permitted outbound | confirmed in endpoint console and EDR status | no deviation
- 2026-04-14T10:12:00Z | James Chen | host rebuild from clean baseline image | host wiped and restored to clean state; zero PowerShell->MSBuild lineage | verified via endpoint/processtree/WST-WS-031.json | no deviation
