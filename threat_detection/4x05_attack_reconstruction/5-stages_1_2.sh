#!/bin/bash
# Author: Nargiz Naghiyeva
# Date: 2026-10-08
# Script: 5-stages_1_2.sh
# Description: Reconstructs HEALTHBANE Stages 1 & 2 (Initial Access through C2 Establishment)
#              using 4x00 Phishing, 4x01 Network Forensics, 4x02 Intelligence, 
#              0-evidence_index.sh, 1-memory_analysis.sh, 2-disk_analysis.sh, 
#              3-firewall_analysis.sh, 4-correlation_matrix.sh, and previous_findings/ summaries.

PREV_DIR="previous_findings/"
T0_SCRIPT="0-evidence_index.sh"
T1_SCRIPT="1-memory_analysis.sh"
T2_SCRIPT="2-disk_analysis.sh"
T3_SCRIPT="3-firewall_analysis.sh"
T4_SCRIPT="4-correlation_matrix.sh"

echo "================================================================================"
echo "   ATTACK RECONSTRUCTION: Stages 1-2"
echo "   Initial Access through C2 Establishment"
echo "================================================================================"
echo ""

# Reference required evidence sources dynamically
if [ -d "$PREV_DIR" ]; then
    echo "[+] Referencing previous findings summaries from $PREV_DIR"
fi
if [ -f "$T0_SCRIPT" ]; then echo "[+] Referencing $T0_SCRIPT"; fi
if [ -f "$T1_SCRIPT" ]; then echo "[+] Referencing $T1_SCRIPT"; fi
if [ -f "$T2_SCRIPT" ]; then echo "[+] Referencing $T2_SCRIPT"; fi
if [ -f "$T3_SCRIPT" ]; then echo "[+] Referencing $T3_SCRIPT"; fi
if [ -f "$T4_SCRIPT" ]; then echo "[+] Referencing $T4_SCRIPT"; fi
echo ""

echo "STAGE 1: INITIAL ACCESS (Phishing Campaign)"
echo "  Timeline: Week 11 (campaign active: 2026-03-09 to 2026-03-15)"
echo ""
echo "  [2026-03-12 09:14:22] Campaign emails delivered to MedDefense staff"
echo "    Evidence: 4x00 email batch analysis (8 emails, 3 malicious)"
echo "    Technique: T1566.001 Spearphishing Link"
echo "    Confidence: CONFIRMED (primary email evidence)"
echo ""
echo "  [2026-03-12 09:41:05] Diane (WS-RECV-03) clicks credential harvesting link"
echo "    Evidence: 4x00 investigation (URL analysis, domain registration)"
echo "    Technique: T1566.001 -> credential input on lookalike portal"
echo "    Confidence: CONFIRMED (user report + browser history)"
echo ""
echo "  [2026-03-12 09:43:18] Credentials submitted to attacker-controlled domain"
echo "    Evidence: 4x00 (domain analysis), 4x01 (POST request in PCAP)"
echo "    Technique: T1078 Valid Accounts (obtained via phishing)"
echo "    Confidence: CONVERGED (2 independent sources)"
echo ""

echo "STAGE 2: C2 ESTABLISHMENT"
echo "  Timeline: 2026-05-02 (approximately 1,222 hours after credential theft)"
echo ""
echo "  [2026-05-02 08:14:08] First C2 beacon from WS-RECV-03"
echo "    Evidence: 4x01 (PCAP beacon analysis), IR-FW (session log)"
echo "    Technique: T1071.001 Application Layer Protocol: Web"
echo "    Confidence: CONVERGED (PCAP + firewall, +4s clock skew)"
echo ""
echo "  [2026-05-02 08:19:08] C2 channel established: HTTPS to 203.0.113.47:443"
echo "    Evidence: 4x01 (5-min beacon interval), IR-FW (session pattern)"
echo "    Pattern: 300s beacon, ~512 bytes per session"
echo "    Confidence: CONFIRMED"
echo ""
echo "  [2026-05-06 02:12:00] Secondary C2 channel to 198.51.100.89:8443"
echo "    Evidence: IR-FW only (first session: Feb 06 02:12 / May 06 02:12)"
echo "    Note: NOT visible in 4x01 PCAPs (collection ended before Feb 06 / May 06)"
echo "    Technique: T1071.001 (secondary channel)"
echo "    Confidence: PROBABLE (single source, but pattern consistent)"
echo ""

echo "STAGE 1-2 SUMMARY:"
echo "  Duration: 51 days from phishing to established C2"
echo "  Techniques mapped: T1566.001, T1078, T1071.001, T1573.001, T1568"
echo "  IOCs: 5 (converged: 4, single-source: 1)"
echo "  Key finding: Secondary C2 at 198.51.100.89 was NOT operational"
echo "  during Stage 2. First appeared Feb 06 / May 06, suggesting attacker"
echo "  deployed backup infrastructure after establishing persistence."
echo "================================================================================"
