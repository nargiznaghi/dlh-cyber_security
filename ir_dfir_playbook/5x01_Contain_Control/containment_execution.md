# Containment Execution: IR-2026-0414-01

- 2026-04-14T03:16:04Z | Nargiz Naghiyeva | switchport VLAN reassign WST-WS-031 -> VLAN 999 | host reachable only from jumpbox | confirmed via ping from SOC jumpbox; timeout from user VLAN | no deviation
- 2026-04-14T03:17:21Z | Nargiz Naghiyeva | firewall deny outbound ip 185.220.101.47 | no new netflow to 185.220.101.47 after 03:17 | netflow confirmed zero packets to 185.220.101.47 from 03:17:21Z onward | no deviation
- 2026-04-14T03:19:02Z | Nargiz Naghiyeva| endpoint device containment flag SET on WST-WS-031 | only analyst tooling permitted outbound | confirmed in endpoint console | no deviation
- 2026-04-14T03:22:04Z | Nargiz Naghiyeva | verify isolation | ping from user VLAN fails, ping from jumpbox succeeds | verified | no deviation
