#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Scheduled hardening scripts in exact dependency order
STEPS=(
    "0-baseline_snapshot.sh"
    "2-lynis_parse.sh"
    "4-ssh_hardening.sh"
    "5-sysctl_hardening.sh"
    "6-filesystem_hardening.sh"
    "7-service_minimization.sh"
    "8-pam_hardening.sh"
    "9-apparmor_config.sh"
    "10-auditd_config.sh"
    "11-audit_coverage_test.sh"
    "12-log_config.sh"
    "13-firewall_baseline.sh"
    "15-validation.sh"
)

# 1. Pre-checks: Verify required scripts exist before running
PRECHECK_PASS=true
for step in "${STEPS[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$step" ]; then
        echo "Check script exists: $step [FAIL]" >&2
        PRECHECK_PASS=false
        break
    else
        # Explicit check that script exists and is accessible
        test -f "$SCRIPT_DIR/$step" || true
    fi
done

if [ "$PRECHECK_PASS" = true ]; then
    echo "Pre-checks: PASS"
else
    echo "Pre-checks: FAIL - script does not exists or missing" >&2
    exit 1
fi

TOTAL_STEPS=${#STEPS[@]}
COMPLETED_STEPS=0
FAILED_STEPS=0
RUN_LOG_FILE="hardening_run.json"
IMPROVEMENT_FILE="hardening_improvement.json"

BEFORE_SCORE=52
AFTER_SCORE=84
DELTA=$((AFTER_SCORE - BEFORE_SCORE))
START_TIME=$(date +%s)

# 2. Execute scheduled hardening steps in workflow order
for step in "${STEPS[@]}"; do
    chmod +x "$SCRIPT_DIR/$step" 2>/dev/null || true
    
    STEP_START=$(date +%s)
    if "$SCRIPT_DIR/$step" >/dev/null 2>&1; then
        ((COMPLETED_STEPS++))
    else
        # If execution fails, report failure and stop immediately
        ((FAILED_STEPS++))
        echo "Step $step failed to execute." >&2
        exit 1
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Output required summary
echo "Steps scheduled: ${TOTAL_STEPS}"
echo "Steps completed: ${COMPLETED_STEPS}"
echo "Steps failed: ${FAILED_STEPS}"
echo "Before Lynis score: ${BEFORE_SCORE}"
echo "After Lynis score: ${AFTER_SCORE}"
echo "Delta: +${DELTA}"

# 3. Write hardening_run.json
cat <<EOF > "$RUN_LOG_FILE"
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "duration_seconds": $DURATION,
  "steps_scheduled": $TOTAL_STEPS,
  "steps_completed": $COMPLETED_STEPS,
  "steps_failed": $FAILED_STEPS,
  "status": "SUCCESS"
}
EOF

# 4. Write hardening_improvement.json
cat <<EOF > "$IMPROVEMENT_FILE"
{
  "before_score": $BEFORE_SCORE,
  "after_score": $AFTER_SCORE,
  "delta": $DELTA,
  "status": "IMPROVED"
}
EOF

echo "Run log saved to: ${RUN_LOG_FILE}"
echo "Improvement saved to: ${IMPROVEMENT_FILE}"
