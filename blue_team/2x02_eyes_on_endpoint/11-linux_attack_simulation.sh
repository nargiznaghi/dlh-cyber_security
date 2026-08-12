#!/bin/bash
# name: 11-linux_attack_simulation.sh
# purpose: Execute simulated attack steps on Linux and generate ground truth log
# author: Nargiz Naghiyeva

set -e
set -o pipefail
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Must run as root (sudo)." >&2
    exit 1
fi

OUTPUT="linux_attack_log.json"
NOW_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[*] Executing Linux attack simulation..."

# Simulating actions and recording timestamps
TIMESTAMP1=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
useradd -m -s /bin/bash testattacker 2>/dev/null || true

TIMESTAMP2=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "testattacker ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/backdoor

TIMESTAMP3=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cp /bin/ls /tmp/suspicious_bin 2>/dev/null || true
/tmp/suspicious_bin >/dev/null 2>&1 || true

TIMESTAMP4=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
nc -z -w 1 127.0.0.1 4444 2>/dev/null || true

TIMESTAMP5=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "* * * * * root /tmp/suspicious_bin" > /etc/cron.d/persistence_test

TIMESTAMP6=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cat /etc/shadow >/dev/null 2>&1 || true

cat << JSON_OUT > "$OUTPUT"
{
  "platform": "linux",
  "generated_at": "$NOW_TS",
  "total_actions": 6,
  "actions": [
    { "action_number": 1, "description": "Create user", "timestamp": "$TIMESTAMP1" },
    { "action_number": 2, "description": "Modify sudoers", "timestamp": "$TIMESTAMP2" },
    { "action_number": 3, "description": "Execute from /tmp", "timestamp": "$TIMESTAMP3" },
    { "action_number": 4, "description": "Reverse shell", "timestamp": "$TIMESTAMP4" },
    { "action_number": 5, "description": "Cron persistence", "timestamp": "$TIMESTAMP5" },
    { "action_number": 6, "description": "Access /etc/shadow", "timestamp": "$TIMESTAMP6" }
  ]
}
JSON_OUT

echo "[+] Attack simulation finished. Ground truth saved to: $OUTPUT"
