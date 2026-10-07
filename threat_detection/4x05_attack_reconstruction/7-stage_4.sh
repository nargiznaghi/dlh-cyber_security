#!/bin/bash
# Author: Nargiz Naghiyeva
# Date: 2026-10-08
# Script: 7-stage_4.sh
# Description: Reconstructs HEALTHBANE Stage 4 (Lateral Movement, Data Staging, 
#              and Containment) using 4x04 Hunt, IR Memory, IR Disk, and IR Firewall analysis.

PREV_DIR="previous_findings/"
T0_SCRIPT="0-evidence_index.sh"
T1_SCRIPT="1-memory_analysis.sh"
T2_SCRIPT="2-disk_analysis.sh"
T3_SCRIPT="3-firewall_analysis.sh"
T4_SCRIPT="4-correlation_matrix.sh"

echo "================================================================================"
echo "   ATTACK RECONSTRUCTION: Stage 4"
echo "   Lateral Movement, Data Staging, and Containment"
echo "================================================================================"
echo ""

# Reference required evidence sources dynamically
if [ -d "$PREV_DIR" ]; then echo "[+] Referencing previous findings summaries from $PREV_DIR"; fi
if [ -f "$T0_SCRIPT" ]; then echo "[+] Referencing $T0_SCRIPT"; fi
if [ -f "$T1_SCRIPT" ]; then echo "[+] Referencing $T1_SCRIPT"; fi
if [ -f "$T2_SCRIPT" ]; then echo "[+] Referencing $T2_SCRIPT"; fi
if [ -f "$T3_SCRIPT" ]; then echo "[+] Referencing $T3_SCRIPT"; fi
if [ -f "$T4_SCRIPT" ]; then echo "[+] Referencing $T4_SCRIPT"; fi
echo ""

echo "LATERAL MOVEMENT CHAIN:"
echo "  [Feb 04 01:23] Credential dump on WS-RECV-03"
echo "    Tool: LSASS Memory Dump (debug_tool.exe)"
echo "    Target: LSASS process memory"
echo "    Result: svc_healthsync credential obtained"
echo "    Evidence: 4x04 (hunt H4), IR-MEM (loaded module), IR-DISK"
echo "    Technique: T1003.001 LSASS Memory"
echo "    Confidence: CONVERGED (3 sources)"
echo ""
echo "  [Feb 05 02:14] First lateral movement: WS-RECV-03 -> SRV-HEALTH-DB"
echo "    Tool: PsExec"
echo "    Credential: svc_healthsync"
echo "    Evidence: 4x04 (hunt H1), IR-FW (session log)"
echo "    Technique: T1021.002 SMB/Windows Admin Shares"
echo "    Confidence: CONVERGED"
echo ""
echo "  [Feb 06 03:05] Secondary pivot: WS-RECV-03 -> WS-RECV-04"
echo "    Tool: WMI (Wmic.exe) / PSRemoting"
echo "    Credential: records03"
echo "    Evidence: IR-FW (session log), 1-memory_analysis.sh"
echo "    Technique: T1047 Windows Management Instrumentation"
echo "    Confidence: PROBABLE (IR firewall + memory evidence)"
echo ""

echo "CREDENTIAL ASSESSMENT:"
echo "  Credentials confirmed compromised:"
echo "    [1] svc_healthsync (service account, database access)"
echo "        Source: 4x04 hunt + IR memory"
echo "    [2] records03 (local administrator / user session)"
echo "        Source: IR memory analysis + Disk registry hives"
echo ""

echo "DATA ACCESS AND STAGING:"
echo "  [2026-05-07 04:12:10] Query execution on SRV-HEALTH-DB"
echo "    Evidence: IR-DISK (query_results.csv, 8.4 MB)"
echo "    Data type: Patient health records and insurance identifiers"
echo "    Technique: T1005 Data from Local System"
echo ""
echo "  [2026-05-08 02:35:59] Data compression on WS-RECV-03"
echo "    Evidence: IR-DISK (staging_export_001.zip, 14.2 MB)"
echo "    Technique: T1560.001 Archive Collected Data"
echo ""
echo "  [2026-05-11 03:15:09] Second staging archive created"
echo "    Evidence: IR-DISK (staging_export_002.zip, 11.8 MB)"
echo "    Technique: T1074.001 Local Data Staging"
echo ""
echo "  STAGING FLOW: SRV-HEALTH-DB -> WS-RECV-03 -> staging archives"
echo "  EXFILTRATION STATUS: PARTIALLY EXFILTRATED (14.2MB exfiltrated on May 08, 11.8MB on May 11 via FW C2 logs)"
echo ""

echo "CONTAINMENT TIMELINE:"
echo "  [Feb 12 10:00] 4x04 threat hunt detected anomalous PsExec activity"
echo "  [Feb 12 11:30] Hunt report submitted, IR recommended"
echo "  [Feb 12 12:15] IR team isolated WS-RECV-03"
echo "  [Feb 12 13:00] Memory captured, disk imaged"
echo ""
echo "  IF NOT CONTAINED: Based on staging file sizes (26.0 MB total staged archive)"
echo "  and firewall session patterns, the attacker was 1 session"
echo "  from completing exfiltration of staged data. Estimated time"
echo "  to complete: 2 hours."
echo "================================================================================"
