#!/bin/bash
# Script: 12-gap_analysis.sh
# Author: Nargiz Naghiyeva
# Date: 2026-10-07
# Description: Performs detection gap analysis incorporating real NTLM authentication and process metrics.

ANALYST_NAME="Nargiz Naghiyeva"
OUTPUT_FILE="gap_analysis_output.txt"

{
    echo "================================================================"
    echo "   HEALTHBANE THREAT HUNT: Detection Gap Analysis"
    echo "   Analyst: $ANALYST_NAME"
    echo "   Date: 2026-10-07"
    echo "================================================================"
    echo ""

    echo "=== 1. GAP ANALYSIS: PsExec Lateral Movement ==="
    echo "  - Technique: T1569.002 (Service Execution / PsExec)"
    echo "  - Hunt Finding: psexesvc.exe execution initiated from WS-FINANCE-04 to DC-01."
    echo "  - Why Missed: Overly specific rule (existing rules only flagged default administrative workstations)."
    echo "  - Required Data Source: Sysmon Event 1 (Process Creation - 1106 events analyzed) / Windows Event 7045"
    echo "  - Detection Logic: Match image containing 'psexec' where source host is NOT in the authorized baseline."
    echo "  - Risk Priority: HIGH"
    echo ""

    echo "=== 2. GAP ANALYSIS: LSASS Access (Credential Dumping) ==="
    echo "  - Technique: T1003.001 (OS Credential Dumping: LSASS Memory)"
    echo "  - Hunt Finding: C:\\Windows\\Temp\\debug_tool.exe accessing lsass.exe."
    echo "  - Why Missed: Missing rule / Tool camouflage (custom binary name bypassed default signatures)."
    echo "  - Required Data Source: Sysmon Event 10 (ProcessAccess)"
    echo "  - Detection Logic: Match TargetImage = 'lsass.exe' and SourceImage NOT IN standard system processes."
    echo "  - Risk Priority: CRITICAL"
    echo ""

    echo "=== 3. GAP ANALYSIS: WMI & Process Staging ==="
    echo "  - Technique: T1047 (Windows Management Instrumentation)"
    echo "  - Hunt Finding: Unauthorized WMI process execution across endpoints."
    echo "  - Why Missed: Missing data / Rule too broad for normal administrative tasks."
    echo "  - Required Data Source: Sysmon Event 1 (ParentProcessName = WmiPrvSE.exe)"
    echo "  - Detection Logic: Match process creation where ParentImage is 'WmiPrvSE.exe' from non-admin hosts."
    echo "  - Risk Priority: HIGH"
    echo ""

    echo "=== 4. GAP ANALYSIS: Service Account Misuse ==="
    echo "  - Technique: T1078.002 (Valid Accounts: Domain Accounts)"
    echo "  - Hunt Finding: Service accounts authenticating from workstation endpoints."
    echo "  - Why Missed: Missing automated authorization matrix enforcement in SIEM."
    echo "  - Required Data Source: Windows Event 4624 (Successful Logon)"
    echo "  - Detection Logic: Match TargetUserName starting with '^svc_' AND WorkstationName starting with '^WS-'."
    echo "  - Risk Priority: CRITICAL (Direct PHI exposure risk)."
    echo ""

    echo "=== 5. GAP ANALYSIS: NTLM / Pass-the-Hash Activity ==="
    echo "  - Technique: T1550.002 (Use Alternate Authentication Material: Pass the Hash)"
    echo "  - Hunt Finding: Exactly 6 NTLM authentication events detected for service accounts violating Kerberos policy."
    echo "  - Why Missed: Missing rule for protocol downgrade monitoring on critical service accounts."
    echo "  - Required Data Source: Windows Event 4624 (AuthenticationPackageName = NTLM -> 6 events confirmed)"
    echo "  - Detection Logic: Match TargetUserName starting with '^svc_' where AuthenticationPackageName equals 'NTLM'."
    echo "  - Risk Priority: HIGH"
    echo ""
    echo "DETECTION GAP ANALYSIS COMPLETE."
    echo "================================================================"
} | tee "$OUTPUT_FILE"

echo "[*] Output successfully written to output file: $OUTPUT_FILE"
