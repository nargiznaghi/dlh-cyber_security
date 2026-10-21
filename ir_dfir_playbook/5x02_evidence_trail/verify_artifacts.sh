#!/usr/bin/env bash

HASHES_FILE="hashes.txt"
LOG_FILE="verification_log.txt"
ACTOR="Nargiz Naghiyeva"

ARTIFACTS=(
    "ART-001|wst-ws-031.dd|./evidence/wst-ws-031.dd"
    "ART-002|wst-ws-031.mem|./evidence/wst-ws-031.mem"
    "ART-003|wst-ws-017.mem|./evidence/wst-ws-017.mem"
)

get_hash() {
    local target_path="$1"
    if [ -f "$target_path" ]; then
        sha256sum "$target_path" | awk '{print $1}'
    else
        echo "FILE_NOT_FOUND"
    fi
}

if [ ! -f "$HASHES_FILE" ]; then
    > "$HASHES_FILE"
    for entry in "${ARTIFACTS[@]}"; do
        IFS="|" read -r art_id name path <<< "$entry"
        computed_hash=$(get_hash "$path")
        
        echo "${art_id}|${name}|${computed_hash}" >> "$HASHES_FILE"
        echo "[BASELINE_SET] ${art_id} ${name} sha256=${computed_hash}"
        
        timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        echo "${timestamp} | ${ACTOR} | ${art_id} | BASELINE_SET | expected=${computed_hash} | computed=${computed_hash}" >> "$LOG_FILE"
    done
    echo "Baseline written to ${HASHES_FILE}. Run again to verify."
    exit 0
fi

all_passed=true

for entry in "${ARTIFACTS[@]}"; do
    IFS="|" read -r art_id name path <<< "$entry"
    computed_hash=$(get_hash "$path")
    expected_hash=$(grep "^${art_id}|" "$HASHES_FILE" | cut -d'|' -f3)
    
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    if [ "$computed_hash" == "$expected_hash" ] && [ "$computed_hash" != "FILE_NOT_FOUND" ]; then
        echo "[PASS] ${art_id} ${name} expected=${expected_hash} computed=${computed_hash}"
        echo "${timestamp} | ${ACTOR} | ${art_id} | PASS | expected=${expected_hash} | computed=${computed_hash}" >> "$LOG_FILE"
    else
        echo "[FAIL] ${art_id} ${name} expected=${expected_hash} computed=${computed_hash}"
        echo "${timestamp} | ${ACTOR} | ${art_id} | FAIL | expected=${expected_hash} | computed=${computed_hash}" >> "$LOG_FILE"
        all_passed=false
    fi
done

if [ "$all_passed" = true ]; then
    echo "ALL ARTIFACTS VERIFIED"
    exit 0
else
    echo "VERIFICATION FAILED: Artifact mismatch detected!"
    exit 1
fi
