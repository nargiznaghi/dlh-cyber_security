#!/bin/bash
set -euo pipefail

# Define files and paths
INCIDENT_LOG="incident_sysmon.jsonl"
CLEAN_LOG="clean_sysmon.jsonl"

SIGMA_RULES=(
    "sigma_powershell_msbuild_lolbin.yml"
)

# Check if log files exist
if [[ ! -f "$INCIDENT_LOG" || ! -f "$CLEAN_LOG" ]]; then
    echo "Error: Required log files ($INCIDENT_LOG or $CLEAN_LOG) not found."
    exit 1
fi

TOTAL_INCIDENT_EVENTS=$(wc -l < "$INCIDENT_LOG" | tr -d ' ')
TOTAL_CLEAN_EVENTS=$(wc -l < "$CLEAN_LOG" | tr -d ' ')

echo "=== RULE VALIDATION START ==="
echo "Total Incident Log Events: $TOTAL_INCIDENT_EVENTS"
echo "Total Clean Log Events:    $TOTAL_CLEAN_EVENTS"
echo "----------------------------------------"

for RULE in "${SIGMA_RULES[@]}"; do
    if [[ ! -f "$RULE" ]]; then
        echo "Warning: Rule file $RULE not found, skipping."
        continue
    fi

    echo "Testing Rule: $RULE"

    # Test against Incident Logs
    # Matching PowerShell parent spawning MSBuild/CSC/VBC/JSC
    INCIDENT_MATCHES=$(grep -i -E '"ParentImage":.*\\(powershell|pwsh|wscript|cscript)\.exe' "$INCIDENT_LOG" | grep -i -E '"Image":.*\\(MSBuild|csc|vbc|jsc)\.exe' | wc -l | tr -d ' ')
    
    if [ "$TOTAL_INCIDENT_EVENTS" -gt 0 ]; then
        INCIDENT_PCT=$(python3 -c "print(f'{($INCIDENT_MATCHES / $TOTAL_INCIDENT_EVENTS) * 100:.2f}')")
    else
        INCIDENT_PCT="0.00"
    fi

    echo "  [Incident Sample] Matches: $INCIDENT_MATCHES ($INCIDENT_PCT%)"

    # Test against Clean Logs
    CLEAN_MATCHES=$(grep -i -E '"ParentImage":.*\\(powershell|pwsh|wscript|cscript)\.exe' "$CLEAN_LOG" | grep -i -E '"Image":.*\\(MSBuild|csc|vbc|jsc)\.exe' | wc -l | tr -d ' ')
    
    if [ "$TOTAL_CLEAN_EVENTS" -gt 0 ]; then
        CLEAN_PCT=$(python3 -c "print(f'{($CLEAN_MATCHES / $TOTAL_CLEAN_EVENTS) * 100:.2f}')")
    else
        CLEAN_PCT="0.00"
    fi

    echo "  [Clean Sample]    Matches: $CLEAN_MATCHES ($CLEAN_PCT%)"

    if [ "$CLEAN_MATCHES" -gt 0 ]; then
        echo "  [Clean False Positives Summary]:"
        grep -i -E '"ParentImage":.*\\(powershell|pwsh|wscript|cscript)\.exe' "$CLEAN_LOG" | grep -i -E '"Image":.*\\(MSBuild|csc|vbc|jsc)\.exe' | head -n 5
    else
        echo "  [Clean False Positives Summary]: No false positives detected."
    fi
    echo "----------------------------------------"
done

echo "=== RULE VALIDATION COMPLETE ==="
