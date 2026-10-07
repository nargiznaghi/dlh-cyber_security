#!/usr/bin/env bash
# File: threat_detection/4x05_attack_reconstruction/0-evidence_index.sh
# Purpose: Catalog evidence sources, build coverage matrix, and identify analytical gaps for HEALTHBANE reconstruction.
# Author: Nargiz Naghiyeva
# Date: 2026-10-07

set -euo pipefail

CURRENT_HOST=$(hostname)
CURRENT_DATE=$(date "+%Y-%m-%d %H:%M:%S")

echo "================================================================"
echo "   EVIDENCE INVENTORY - HEALTHBANE Reconstruction"
echo "   Analyst: ${CURRENT_HOST}    Date: ${CURRENT_DATE}"
echo "================================================================"
echo "SOURCE CATALOG:"

cat << 'EOF_CAT'
  [01] 4x00_phishing_summary.txt
       Phase: 4x00 (Phishing Dissection)
       Type: Email analysis findings
       Coverage: Week 11 (initial campaign detection)
       Reliability: MEDIUM (derived summary, not raw evidence)
       Key content: 8 emails analyzed, 3 confirmed malicious,
                    campaign domains, SPF/DKIM failures, credential
                    exposure for Diane (WS-RECV-03 user)

  [02] 4x01_network_timeline.txt
       Phase: 4x01 (Network Forensics)
       Type: PCAP-derived findings
       Coverage: 48h window surrounding phishing incident
       Reliability: MEDIUM (derived timeline, not raw PCAPs)
       Key content: C2 beaconing (5-min intervals), DNS tunneling,
                    lateral movement traces

  [03] 4x02_malware_analysis.txt
       Phase: 4x02 (Reverse Engineering)
       Type: Malware analysis report
       Coverage: Execution and payload staging window
       Reliability: MEDIUM (derived report)
       Key content: Analysis of svchost_update.exe and debug_tool.exe (Mimikatz fork)

  [04] 4x03_forensic_timeline.txt
       Phase: 4x03 (Endpoint Forensics)
       Type: Host artifact timeline
       Coverage: Endpoint activity across infection lifecycle
       Reliability: MEDIUM (derived timeline)
       Key content: MFT timestamps, Defender exclusion changes, local process executions

  [05] 4x04_hunting_report.txt
       Phase: 4x04 (Enterprise Threat Hunting)
       Type: SIEM hunting findings
       Coverage: Enterprise-wide activity
       Reliability: MEDIUM (correlated analytics)
       Key content: PsExec lateral movement, assessment of WS-RECV-04 and WS-RECV-07

  [06] firewall_sessions_ws_recv_03.json
       Phase: 4x01 / 4x04 (Network Analysis)
       Type: Raw firewall logs
       Coverage: Full session telemetry
       Reliability: HIGH (raw traffic records)
       Key content: Complete connection logs for WS-RECV-03, C2 sessions, exfiltration volume

  [07] memory_artifacts.txt
       Phase: 4x02 / 4x03 (Memory Forensics)
       Type: Memory dump extraction
       Coverage: Live memory capture
       Reliability: HIGH (volatile artifact data)
       Key content: Volatility analysis, svchost_update process memory, injected code, C2 IPs

  [08] phishing_email_raw.eml
       Phase: 4x00 (Initial Access)
       Type: Raw email message
       Coverage: Initial delivery event
       Reliability: HIGH (raw message capture)
       Key content: Original spearphishing email delivered to Diane Marsh

  [09] mitre_attack_mapping.json
       Phase: 4x05-IR (Threat Intelligence)
       Type: ATT&CK framework mapping
       Coverage: Reference framework
       Reliability: HIGH (standardized intelligence)
       Key content: Technique IDs and taxonomy for standardized reporting

  [10] previous_findings/summary_all.txt
       Phase: 4x00 - 4x04 (Multi-Phase Consolidation)
       Type: Aggregated report summary
       Coverage: Cumulative investigation
       Reliability: MEDIUM (consolidated findings)
       Key content: Synthesis of previous phase outputs and preliminary attack chain

  [11] ir_team_notes.txt
       Phase: 4x05-IR (Incident Response)
       Type: Preliminary observations
       Coverage: WS-RECV-03 capture (Week 16-17)
       Reliability: LOW (preliminary, some unverified)
       Key content: Observations requiring analyst validation
EOF_CAT

echo ""
echo "TEMPORAL COVERAGE MATRIX:"
cat << 'EOF_MATRIX'
  Week 11  [EMAIL][NETWORK][--------][--------][--------][--------]
  Week 12  [------][--------][INTEL---][--------][--------][--------]
  Week 13  [------][--------][--------][MALWARE-][--------][--------]
  Week 14  [------][--------][--------][--------][SIEM----][--------]
  Week 15  [------][--------][--------][--------][SIEM----][--------]
  Week 16  [------][--------][--------][--------][SIEM----][IR------]

  GAP: No network capture data after Week 11 48h window
  GAP: No endpoint telemetry before Week 14 SIEM collection
  GAP: Memory/disk evidence only for WS-RECV-03, not other hosts
EOF_MATRIX

echo ""
echo "CRITICAL QUESTIONS FOR RECONSTRUCTION:"
cat << 'EOF_QUESTIONS'
  [Q1] Does the new firewall evidence confirm or contradict the
       4x01 network timeline for WS-RECV-03 ?
  [Q2] What is the unknown IP in firewall sessions -- secondary
       C2 or unrelated traffic ?
  [Q3] Did the data staging succeed in exfiltrating patient data,
       or was it interrupted by the hunt ?
  [Q4] Are there additional persistence mechanisms beyond the
       scheduled task found on WS-RECV-03 ?
  [Q5] What ATT&CK techniques remain unmapped after integrating
       all evidence sources ?
EOF_QUESTIONS

echo "================================================================"
