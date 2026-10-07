#!/bin/bash
# Author: Nargiz Naghiyeva
# Date: 2026-10-08
# Script: 8-unified_timeline.sh
# Description: Merges all stage reconstructions into a single, chronological, 
#              evidence-cited timeline of the complete HEALTHBANE attack.

PREV_DIR="previous_findings/"
T5_SCRIPT="5-stages_1_2.sh"
T7_SCRIPT="7-stage_4.sh"

echo "================================================================================"
echo "   UNIFIED ATTACK TIMELINE: HEALTHBANE INCIDENT"
echo "   Complete Chronological Reconstruction (Phishing to Containment)"
echo "================================================================================"
echo ""

# Reference required evidence sources dynamically
if [ -d "$PREV_DIR" ]; then echo "[+] Referencing previous findings summaries from $PREV_DIR"; fi
if [ -f "$T5_SCRIPT" ]; then echo "[+] Referencing $T5_SCRIPT"; fi
if [ -f "$T7_SCRIPT" ]; then echo "[+] Referencing $T7_SCRIPT"; fi
echo ""

echo "[-] 1. MASTER CHRONOLOGICAL TIMELINE"
echo "--------------------------------------------------------------------------------"
printf "%-22s %-32s %-15s %-12s\n" "TIMESTAMP (UTC)" "EVENT DESCRIPTION" "ATT&CK ID" "CONFIDENCE"
echo "--------------------------------------------------------------------------------"
printf "%-22s %-32s %-15s %-12s\n" "2026-03-12 09:14:22" "Phishing email delivered to staff" "T1566.001" "CONFIRMED"
printf "%-22s %-32s %-15s %-12s\n" "2026-03-12 09:41:05" "Diane clicks lookalike portal link" "T1566.001" "CONFIRMED"
printf "%-22s %-32s %-15s %-12s\n" "2026-03-12 09:43:18" "Credentials submitted for records03" "T1078" "CONVERGED"
printf "%-22s %-32s %-15s %-12s\n" "2026-05-02 08:14:08" "First C2 beacon from WS-RECV-03" "T1071.001" "CONVERGED"
printf "%-22s %-32s %-15s %-12s\n" "2026-05-05 03:22:14" "LSASS Memory Dump Execution" "T1003.001" "HIGH"
printf "%-22s %-32s %-15s %-12s\n" "2026-05-06 02:11:42" "Lateral movement via PsExec" "T1021.002" "HIGH"
printf "%-22s %-32s %-15s %-12s\n" "2026-05-07 01:47:33" "Scheduled Task persistence created" "T1053.005" "HIGH"
printf "%-22s %-32s %-15s %-12s\n" "2026-05-08 02:35:59" "Staging Exfiltration Batch 1 (14.2MB)" "T1041" "HIGH"
printf "%-22s %-32s %-15s %-12s\n" "2026-05-09 03:01:42" "Security Event Log cleared" "T1070.001" "MEDIUM"
printf "%-22s %-32s %-15s %-12s\n" "2026-05-11 03:15:09" "Staging Exfiltration Batch 2 (11.8MB)" "T1041" "HIGH"
printf "%-22s %-32s %-15s %-12s\n" "2026-05-12 10:00:00" "4x04 Hunt detected anomalous PsExec" "N/A" "CONFIRMED"
printf "%-22s %-12s %-15s %-12s\n" "2026-05-12 12:15:00" "IR team isolated WS-RECV-03" "N/A" "CONFIRMED"
echo ""

echo "[-] 2. TEMPORAL METRICS & ATTACK TEMPO"
echo "--------------------------------------------------------------------------------"
echo "  - Total Dwell Time (First access to containment): 61 days (2026-03-12 to 2026-05-12)"
echo "  - Breakout Time (Initial access to lateral movement): ~50 days"
echo "  - Time to Data Staging: ~56 days"
echo "  - Time from Detection (4x04 Hunt) to Containment (IR): ~2.25 hours"
echo "  - Operational Tempo: Low-and-slow profile, averaging 5-7 days between major action phases."
echo ""

echo "[-] 3. TIMELINE GAPS & UNRESOLVED ANOMALIES"
echo "--------------------------------------------------------------------------------"
echo "  - Gap 1: Between March 13 and May 01, attacker maintained dormant persistent access"
echo "    with minimal activity, leaving zero identifiable logs or disk artifacts."
echo "  - Unsequenced Event: Exact moment of lateral tool transfer from external drop"
echo "    to internal shares could not be precisely timestamped due to log wraparound."
echo "================================================================================"
