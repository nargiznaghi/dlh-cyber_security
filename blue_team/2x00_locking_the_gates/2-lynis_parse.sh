#!/bin/bash
set -euo pipefail

# Check argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <path-to-lynis-report.dat>" >&2
    exit 1
fi

REPORT_FILE="$1"

if [ ! -f "$REPORT_FILE" ]; then
    echo "Error: File '$REPORT_FILE' not found." >&2
    exit 1
fi

# Extract Hardening Index
HARDENING_INDEX=$(grep "^hardening_index=" "$REPORT_FILE" | cut -d'=' -f2 || echo "0")
if [ -z "$HARDENING_INDEX" ]; then
    HARDENING_INDEX=0
fi

# Prepare temporary file for JSON array construction
TMP_FINDINGS=$(mktemp)
trap 'rm -f "$TMP_FINDINGS"' EXIT

echo "[]" > "$TMP_FINDINGS"

# Parse warning[], suggestion[], and manual_check[] lines
grep -E "^(warning|suggestion|manual_check)\[\]=" "$REPORT_FILE" | while IFS= read -r line; do
    # Extract severity (warning, suggestion, manual_check)
    SEVERITY=$(echo "$line" | cut -d'[' -f1)
    
    # Extract right side after '='
    VALUE=$(echo "$line" | cut -d'=' -f2-)
    
    # Extract test_id and message (Format: TEST-ID|Message text|...)
    TEST_ID=$(echo "$VALUE" | cut -d'|' -f1)
    MESSAGE=$(echo "$VALUE" | cut -d'|' -f2)
    
    # Fallback if message or test_id is empty
    if [ -z "$MESSAGE" ]; then
        MESSAGE="$TEST_ID"
        TEST_ID="LYNIS"
    fi

    # Append parsed object to JSON array using jq
    jq --arg sev "$SEVERITY" \
       --arg tid "$TEST_ID" \
       --arg msg "$MESSAGE" \
       '. += [{"severity": $sev, "test_id": $tid, "message": $msg}]' \
       "$TMP_FINDINGS" > "${TMP_FINDINGS}.tmp" && mv "${TMP_FINDINGS}.tmp" "$TMP_FINDINGS"
done

# Output final structured JSON
jq -n \
   --argjson index "$HARDENING_INDEX" \
   --argjson findings "$(cat "$TMP_FINDINGS")" \
   '{hardening_index: $index, findings: $findings}'
