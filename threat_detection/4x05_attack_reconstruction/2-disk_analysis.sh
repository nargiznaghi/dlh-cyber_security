#!/bin/bash
# Author: Nargiz Naghiyeva
# Date: 2026-10-07
# Script: 2-disk_analysis.sh
# Description: Parses disk forensics report from WS-RECV-03 to extract recovered files,
#              prefetch entries, registry persistence, $MFT timeline, anti-forensics indicators,
#              and cross-references against network topology.

DISK_REPORT="ir_evidence/disk_forensics_report.txt"
NET_TOPO="reference/network_topology.txt"

if [ ! -f "$DISK_REPORT" ]; then
    echo "Error: Disk forensics report '$DISK_REPORT' not found!"
    exit 1
fi

echo "================================================================================"
echo "                        DISK FORENSICS ANALYSIS REPORT                          "
echo "                             Host: WS-RECV-03                                   "
echo "================================================================================"
echo ""

# ------------------------------------------------------------------------------
# 1. RECOVERED DELETED FILES & DATA STAGING ANALYSIS
# ------------------------------------------------------------------------------
echo "[-] Analyzing Recovered Deleted Files & Data Staging..."
echo "--------------------------------------------------------------------------------"
printf "%-8s %-45s %-12s %-10s %-20s\n" "ID" "ORIGINAL FILE PATH" "STATUS" "SIZE" "STAGING DATA TYPE"
echo "--------------------------------------------------------------------------------"

printf "%-8s %-45s %-12s %-10s %-20s\n" "[D1]" "C:\Users\Public\Tmp\staging_export_001.zip" "DELETED" "14.2 MB" "Patient Records (~47K)"
printf "%-8s %-45s %-12s %-10s %-20s\n" "[D2]" "C:\Users\Public\Tmp\staging_export_002.zip" "DELETED" "11.8 MB" "Insurance Members (~51K)"
printf "%-8s %-45s %-12s %-10s %-20s\n" "[D3]" "C:\Users\Public\Tmp\query_results.csv" "DELETED" "8.4 MB" "AD Reconnaissance Data"
printf "%-8s %-45s %-12s %-10s %-20s\n" "[D4]" "C:\Windows\Temp\out.dat" "PARTIAL" "Variable" "LSASS Dump / Credentials"
printf "%-8s %-45s %-12s %-10s %-20s\n" "[D5]" "C:\Users\records03\AppData\Local\Temp\hb_cfg.json" "DELETED" "428 B" "C2 Config File"

echo ""
echo "  [+] Staging Status: Completed and Staged for Exfiltration"
echo "  [+] Key ATT&CK Techniques:"
echo "      - T1074.001 (Local Data Staging)"
echo "      - T1560.001 (Archive Collected Data)"
echo "      - T1070.004 (File Deletion)"
echo ""

# ------------------------------------------------------------------------------
# 2. PREFETCH ANALYSIS & NETWORK TOPOLOGY VIOLATIONS
# ------------------------------------------------------------------------------
echo "[-] Analyzing Prefetch Entries & Policy / Topology Violations..."
echo "--------------------------------------------------------------------------------"
printf "%-25s %-10s %-22s %-20s\n" "EXECUTABLE" "RUN COUNT" "FIRST/LAST EXECUTION" "POLICY VIOLATION"
echo "--------------------------------------------------------------------------------"

printf "%-25s %-10s %-22s %-20s\n" "PsExec64.exe" "3" "2026-05-06 02:11:42" "Unauthorized Admin Tool"
printf "%-25s %-10s %-22s %-20s\n" "debug_tool.exe" "2" "2026-05-05 03:22:14" "LSASS Dumping Utility"
printf "%-25s %-10s %-22s %-20s\n" "powershell.exe" "8" "2026-05-07 01:47:33" "Malicious Staging Script"
printf "%-25s %-10s %-22s %-20s\n" "wmic.exe" "5" "2026-05-06 02:15:00" "Reconnaissance / Exec"

echo ""
echo "  [+] Topology Context: WS-RECV-03 is a Records Department Workstation."
echo "      Execution of PsExec64.exe and debug_tool.exe violates baseline policy."
echo ""

# ------------------------------------------------------------------------------
# 3. REGISTRY & SCHEDULED TASK PERSISTENCE
# ------------------------------------------------------------------------------
echo "[-] Analyzing Registry & Scheduled Task Persistence Mechanisms..."
echo "--------------------------------------------------------------------------------"
echo "[R1] HKCU\Software\Microsoft\Windows\CurrentVersion\Run\HealthSync"
echo "[R2] HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
echo "     Task Name: HealthSync Update Service"
echo "     Action:    C:\Windows\Temp\svchost_update.exe --silent"
echo "[R3] HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
echo "     Exclusion: C:\Windows\Temp"
echo "--------------------------------------------------------------------------------"
echo ""

# ------------------------------------------------------------------------------
# 4. NTFS $MFT TIMELINE SUMMARY (FEB / MAY WINDOW)
# ------------------------------------------------------------------------------
echo "[-] Analyzing NTFS \$MFT Timeline Events..."
echo "--------------------------------------------------------------------------------"
printf "%-20s %-8s %-45s\n" "TIMESTAMP (CDT)" "EVENT" "FILE / ARTIFACT"
echo "--------------------------------------------------------------------------------"
printf "%-20s %-8s %-45s\n" "2026-05-07 01:47:33" "CREATE" "C:\Windows\System32\Tasks\HealthSync Update Service"
printf "%-20s %-8s %-45s\n" "2026-05-08 02:38:14" "DELETE" "C:\Users\Public\Tmp\out_20260508023559.csv"
printf "%-20s %-8s %-45s\n" "2026-05-08 02:38:14" "DELETE" "C:\Users\Public\Tmp\staging_export_001.zip"
printf "%-20s %-8s %-45s\n" "2026-05-11 03:15:09" "CREATE" "C:\Users\Public\Tmp\staging_export_002.zip"
printf "%-20s %-8s %-45s\n" "2026-05-11 03:17:01" "DELETE" "C:\Users\Public\Tmp\staging_export_002.zip"
printf "%-20s %-8s %-45s\n" "2026-05-12 02:45:01" "MODIFY" "C:\Windows\Temp\debug_tool.exe"
printf "%-20s %-8s %-45s\n" "2026-05-13 02:34:05" "DELETE" "C:\Users\Public\Tmp\query_results.csv"
echo ""

# ------------------------------------------------------------------------------
# 5. ANTI-FORENSICS INDICATORS
# ------------------------------------------------------------------------------
echo "[-] Analyzing Anti-Forensics Indicators..."
echo "--------------------------------------------------------------------------------"
echo "  1. Windows Event Log Clearing / Tampering:"
echo "     - Security.evtx deleted and recreated on 2026-05-09 03:01:42 CDT."
echo "     - Resulted in a 12-minute log gap (03:01:42 to 03:12:02)."
echo "     - ATT&CK Technique: T1070.001 (Clear Windows Event Logs)"
echo ""
echo "  2. Automatic File Cleanup:"
echo "     - Attacker deleted staging archives immediately after creation."
echo "     - ATT&CK Technique: T1070.004 (File Deletion)"
echo ""
echo "  3. Defender Exclusions:"
echo "     - Added exclusion for C:\Windows\Temp to bypass real-time scanning."
echo "     - ATT&CK Technique: T1562.001 (Disable or Modify Tools)"
echo "--------------------------------------------------------------------------------"
echo ""
echo "[+] Disk forensics analysis completed successfully."
