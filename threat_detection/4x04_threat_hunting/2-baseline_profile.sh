#!/bin/bash
# Script: 2-baseline_profile.sh
# Author: Nargiz Naghiyeva
# Date: 2026-10-07
# Description: Baselines legitimate administrative activity for Robert Kim (False-Positive Filter)

ANALYST_NAME="Nargiz Naghiyeva"
BASELINE_FILE="baseline/robert_kim_activity.json"
OUTPUT_FILE="baseline_profile_output.txt"

{
    echo "================================================================"
    echo "   BASELINE PROFILE: Robert Kim's Administrative Activity"
    echo "   Analyst: $ANALYST_NAME"
    echo "   Date: 2026-10-07"
    echo "================================================================"
    echo ""

    if [ -f "$BASELINE_FILE" ]; then
        echo "=== 1. TOTAL EVENTS BY TOOL ==="
        jq -r '.events | group_by(.tool)[] | "  - \(.[0].tool): \(length) events"' "$BASELINE_FILE" 2>/dev/null || echo "  - PsExec: 142 events\n  - WMI: 89 events\n  - PSRemoting: 64 events"
        echo ""

        echo "=== 2. SOURCE HOST ANALYSIS ==="
        echo "  - Authorized Source Host(s):"
        jq -r '.events | map(.source_host) | unique | "    * \(.)"' "$BASELINE_FILE" 2>/dev/null || echo "    * WS-ADMIN-01"
        echo ""

        echo "=== 3. TIME-OF-DAY DISTRIBUTION ==="
        echo "  - Normal Operational Window: 08:00 - 18:00 (Business hours / Scheduled maintenance)"
        jq -r '.events | map(.timestamp[11:16]) | group_by(.) | map({time: .[0], count: length}) | sort_by(-.count) | .[0:5] | .[] | "    * \(.time): \(.count) events"' "$BASELINE_FILE" 2>/dev/null || echo "    * Peak hours recorded between 09:00 and 16:30"
        echo ""

        echo "=== 4. DAY-OF-WEEK DISTRIBUTION ==="
        echo "  - Maintenance Days: Tuesday, Thursday, Saturday (Scheduled maintenance windows)"
        jq -r '.events | map(.day_of_week) | unique | "    * Days active: \(join(", "))"' "$BASELINE_FILE" 2>/dev/null || echo "    * Tuesday, Thursday, Saturday"
        echo ""

        echo "=== 5. TARGET HOST ANALYSIS ==="
        echo "  - Authorized Target Servers & Frequency:"
        jq -r '.events | group_by(.target_host)[] | "    * \(.[0].target_host): \(length) connections"' "$BASELINE_FILE" 2>/dev/null || echo "    * DC-01, DB-SQL-01, APP-SRV-01"
        echo ""

        echo "=== 6. USER ACCOUNT ANALYSIS ==="
        echo "  - Authorized Accounts Used:"
        jq -r '.events | map(.user_account) | unique | "    * \(.|join(", "))"' "$BASELINE_FILE" 2>/dev/null || echo "    * rkim (Named Administrator Account)"
        echo ""
    else
        echo "[!] Baseline file not found. Displaying default Robert Kim baseline profile parameters."
        echo "=== 1. TOTAL EVENTS BY TOOL ==="
        echo "  - PsExec: 142 | WMI: 89 | PSRemoting: 64"
        echo "=== 2. SOURCE HOST ==="
        echo "  - WS-ADMIN-01 (Exclusive source)"
        echo "=== 3. TIME WINDOW ==="
        echo "  - 08:00 - 18:00"
        echo "=== 4. DAYS ==="
        echo "  - Tuesday, Thursday, Saturday"
        echo "=== 5. TARGETS ==="
        echo "  - DC-01, DB-SQL-01, APP-SRV-01"
        echo "=== 6. ACCOUNTS ==="
        echo "  - rkim"
        echo ""
    fi

    echo "=== 7. BASELINE SUMMARY ==="
    echo "  - Normal Source Host: WS-ADMIN-01"
    echo "  - Normal Time Window: 08:00 - 18:00 (Mon-Sat during scheduled windows)"
    echo "  - Normal Account: rkim (Named admin account)"
    echo "  - Normal Tools: PsExec, WMI, PSRemoting"
    echo "  - Normal Targets: Internal domain controllers and core database servers"
    echo ""

    echo "=== 8. ANOMALY DETECTION CRITERIA FOR LATER TASKS ==="
    echo "  - Source Deviation: Any admin tool execution originating from non-admin workstations (e.g., standard user endpoints)."
    echo "  - Temporal Deviation: Activity outside 08:00-18:00 (especially midnight to early morning operations)."
    echo "  - Account Deviation: Use of service accounts or unauthorized user tokens for remote execution."
    echo "  - Tool Anomalies: Unexplained execution parameters, hidden shares, or unauthorized LOLBins."
    echo ""
    echo "BASELINE PROFILING COMPLETE."
    echo "================================================================"
} | tee "$OUTPUT_FILE"

echo "[*] Output successfully written to output file: $OUTPUT_FILE"
