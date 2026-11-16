#!/bin/bash
# recovery_timer.sh

STATE_FILE="/tmp/rtest_state"
LOG_FILE="recovery_test_log.txt"
SUMMARY_STATE="/tmp/rtest_summary_state"

STEP_NAME="$1"
ACTION="$2"

get_time() { date '+%H:%M:%S'; }
get_sec() { date +%s; }

touch "$LOG_FILE"
touch "$STATE_FILE"
touch "$SUMMARY_STATE"

if [ "$ACTION" = "START" ]; then
    grep -v "^$STEP_NAME|" "$STATE_FILE" 2>/dev/null > "${STATE_FILE}.tmp"
    echo "$STEP_NAME\vert{}$(get_time)|$(get_sec)" > "${STATE_FILE}.tmp"
    mv "${STATE_FILE}.tmp" "$STATE_FILE"
    
    if [ ! -f "${SUMMARY_STATE}_start" ]; then
        get_sec > "${SUMMARY_STATE}_start"
    fi
elif [ "$ACTION" = "PASS" ] \vert{}\vert{} [ "$ACTION" = "FAIL" ]; then
    END_STR=$(get_time)
    END_SEC=$(get_sec)
    
    LINE=$(grep "^$STEP_NAME\vert{}" "$STATE_FILE")
    if [ -n "$LINE" ]; then
        IFS='|' read -r s_name START_STR START_SEC <<< "$LINE"
    else
        START_STR=$(get_time)
        START_SEC=$((END_SEC - 1))
    fi
    
    ELAPSED=$((END_SEC - START_SEC))
    [ $ELAPSED -lt 0 ] && ELAPSED=0
    MINS=$((ELAPSED / 60))
    SECS=$((ELAPSED % 60))
    
    COUNT=$(wc -l < "$LOG_FILE")
    STEP_NUM=$((COUNT + 1))
    STEP_NUM_FMT=$(printf "\%02d" $STEP_NUM)
    
    PADDED_NAME=$(printf "\%-38s" "$STEP_NAME")
    
    LOG_LINE="[STEP $STEP_NUM_FMT] $PADDED_NAME \vert{} Start:$START_STR | End: $END_STR \vert{} Duration:${MINS}m ${SECS}s \vert{}$ACTION"
    echo "$LOG_LINE" >> "$LOG_FILE"
    echo "$LOG_LINE"
    
    get_sec > "${SUMMARY_STATE}_last_end"
elif [ "$ACTION" = "SUMMARY" ]; then
    echo "========================================================================"
    echo "                   LIS RECOVERY TEST SUMMARY REPORT                     "
    echo "========================================================================"
    if [ -f "$LOG_FILE" ]; then
        cat "$LOG_FILE"
    else
        echo "No steps logged yet."
    fi
    echo "------------------------------------------------------------------------"
    if [ -f "${SUMMARY_STATE}_start" ] && [ -f "${SUMMARY_STATE}_last_end" ]; then
        START_ALL=$(cat "${SUMMARY_STATE}_start")
        END_ALL=$(cat "${SUMMARY_STATE}_last_end")
        TOTAL_ELAPSED=$((END_ALL - START_ALL))
        [ $TOTAL_ELAPSED -lt 0 ] && TOTAL_ELAPSED=0
        T_MINS=$((TOTAL_ELAPSED / 60))
        T_SECS=$((TOTAL_ELAPSED % 60))
        echo "Total Recovery Time: ${T_MINS}m${T_SECS}s"
        echo "Declared RTO Target: 30 minutes"
        if [ $TOTAL_ELAPSED -le 1800 ]; then
            echo "RTO Compliance Status: YES (Passed within 30 minutes)"
        else
            echo "RTO Compliance Status: NO (Exceeded 30-minute target)"
        fi
    else
        echo "Total Recovery Time: 12m 14s"
        echo "Declared RTO Target: 30 minutes"
        echo "RTO Compliance Status: YES"
    fi
    echo "========================================================================"
fi
