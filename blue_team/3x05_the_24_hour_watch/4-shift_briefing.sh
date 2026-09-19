#!/bin/bash
set -eo pipefail

fail() {
  echo "[ERROR] $1" >&2
  exit 1
}

# Workspace və Assets qovluqlarının təyini
if [[ -z "$SHIFT_WORKSPACE" ]]; then
  SHIFT_WORKSPACE="./workspace"
fi

if [[ -z "$ASSETS_DIR" ]]; then
  ASSETS_DIR="./assets"
fi

echo -n "[brief] checking input files... "

# Tələb olunan faylların siyahısı
ADVISORY_FILE="$ASSETS_DIR/hc_red7_advisory.md"
IOC_FEED_FILE="$ASSETS_DIR/ioc_feed.json"
CHANGE_TICKETS_FILE="$ASSETS_DIR/change_tickets.json"
PRIOR_SHIFT_NOTES_FILE="$ASSETS_DIR/prior_shift_notes.md"
BASELINE_RUN_FILE="$SHIFT_WORKSPACE/runtime/baseline_run.json"
SHIFT_START_FILE="$SHIFT_WORKSPACE/runtime/shift_start.json"

REQUIRED_FILES=(
  "$ADVISORY_FILE"
  "$IOC_FEED_FILE"
  "$CHANGE_TICKETS_FILE"
  "$PRIOR_SHIFT_NOTES_FILE"
  "$BASELINE_RUN_FILE"
)

for file in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$file" || ! -s "$file" ]]; then
    echo "FAIL"
    fail "Required input file missing or empty: $file"
  fi
done
echo "OK"

# 1. Advisory MD faylından Cluster ID və MITRE Taktikalarının/Texnikalarının oxunması
CLUSTER_ID=$(grep -oE 'HC-RED7[A-Za-z0-9_-]*' "$ADVISORY_FILE" | head -n 1 || echo "HC-RED7")
if [[ -z "$CLUSTER_ID" ]]; then
  CLUSTER_ID="HC-RED7"
fi
echo "[brief] cluster $CLUSTER_ID loaded"

TACTICS_ARRAY_JSON=$(grep -oE 'T1[0-9]{3}' "$ADVISORY_FILE" | sort -u | jq -R . | jq -s .)
TACTICS_STR=$(echo "$TACTICS_ARRAY_JSON" | jq -r 'join(" ")')
echo "[brief] tactics: $TACTICS_STR"

# 2. IOC Feed məlumatlarının çıxarılması
IOC_STATS=$(jq -c '
  if type == "array" then
    {
      ip: ([.[] | select(.type=="ip")] | length),
      domain: ([.[] | select(.type=="domain")] | length),
      hash: ([.[] | select(.type=="hash")] | length),
      account: ([.[] | select(.type=="account")] | length),
      service_name: ([.[] | select(.type=="service_name")] | length),
      port: ([.[] | select(.type=="port")] | length),
      total: length,
      values: [.[] | .value // .indicator // empty]
    }
  elif .iocs then
    {
      ip: ([.iocs[] | select(.type=="ip")] | length),
      domain: ([.iocs[] | select(.type=="domain")] | length),
      hash: ([.iocs[] | select(.type=="hash")] | length),
      account: ([.iocs[] | select(.type=="account")] | length),
      service_name: ([.iocs[] | select(.type=="service_name")] | length),
      port: ([.iocs[] | select(.type=="port")] | length),
      total: (.iocs | length),
      values: [.iocs[] | .value // .indicator // empty]
    }
  else
    {ip: 0, domain: 0, hash: 0, account: 0, service_name: 0, port: 0, total: 0, values: []}
  end
' "$IOC_FEED_FILE")

IP_CNT=$(echo "$IOC_STATS" | jq -r '.ip')
DOM_CNT=$(echo "$IOC_STATS" | jq -r '.domain')
HASH_CNT=$(echo "$IOC_STATS" | jq -r '.hash')
ACC_CNT=$(echo "$IOC_STATS" | jq -r '.account')
SVC_CNT=$(echo "$IOC_STATS" | jq -r '.service_name')
PORT_CNT=$(echo "$IOC_STATS" | jq -r '.port')
TOTAL_IOC=$(echo "$IOC_STATS" | jq -r '.total')
IOC_VALUES_JSON=$(echo "$IOC_STATS" | jq -c '.values')

echo "[brief] IOCs: ip=$IP_CNT domain=$DOM_CNT hash=$HASH_CNT account=$ACC_CNT service_name=$SVC_CNT port=$PORT_CNT total=$TOTAL_IOC"

# 3. Change Tickets oxunması
CHANGE_TICKETS_JSON=$(jq -c '
  if type == "array" then .
  elif .tickets then .tickets
  elif .change_tickets then .change_tickets
  else [] end
' "$CHANGE_TICKETS_FILE")

TICKETS_CNT=$(echo "$CHANGE_TICKETS_JSON" | jq 'length')
echo "[brief] active change tickets in window: $TICKETS_CNT"

# 4. Prior Shift Notes faylından Open Items hissəsinin parsing edilməsi
OPEN_ITEMS_JSON=$(awk '
  /Open Items/ {flag=1; next}
  /^#/ {flag=0}
  flag && /^[[:space:]]*[-*]/ {
    sub(/^[[:space:]]*[-*][[:space:]]*/, "");
    gsub(/"/, "\\\"");
    print
  }
' "$PRIOR_SHIFT_NOTES_FILE" | jq -R . | jq -s .)

OPEN_ITEMS_CNT=$(echo "$OPEN_ITEMS_JSON" | jq 'length')
echo "[brief] prior shift open items: $OPEN_ITEMS_CNT"

# 5. Baseline Run nəticələrindən Hot Hosts və Deviations məlumatlarının götürülməsi
HOT_HOSTS_JSON=$(jq -c '.hot_hosts // []' "$BASELINE_RUN_FILE")
HOT_HOSTS_CNT=$(echo "$HOT_HOSTS_JSON" | jq 'length')
HOSTS_WITH_DEV=$(jq -r '.hosts_with_deviations // 0' "$BASELINE_RUN_FILE")

echo "[brief] baseline hot hosts: $HOT_HOSTS_CNT"

# 6. Cluster ID Cross-Check yoxlanılması
if [[ -f "$SHIFT_START_FILE" ]]; then
  EXPECTED_CLUSTER_ID=$(jq -r '.advisory_cluster_id // empty' "$SHIFT_START_FILE" 2>/dev/null || true)
  if [[ -n "$EXPECTED_CLUSTER_ID" && "$EXPECTED_CLUSTER_ID" != "$CLUSTER_ID" ]]; then
    fail "Cluster ID cross-check failed! Advisory ($CLUSTER_ID) does not match shift_start.json ($EXPECTED_CLUSTER_ID)."
  fi
fi
echo "[brief] cluster ID cross-check: OK"

# 7. shift_briefing.json faylının formalaşdırılması
ALERTS_DIR="$SHIFT_WORKSPACE/alerts"
mkdir -p "$ALERTS_DIR"
BRIEFING_FILE="$ALERTS_DIR/shift_briefing.json"

cat <<JSON > "$BRIEFING_FILE"
{
  "cluster_id": "${CLUSTER_ID}",
  "cluster_tactics": ${TACTICS_ARRAY_JSON},
  "ioc_count": ${TOTAL_IOC},
  "ioc_by_type": {
    "ip": ${IP_CNT},
    "domain": ${DOM_CNT},
    "hash": ${HASH_CNT},
    "account": ${ACC_CNT},
    "service_name": ${SVC_CNT},
    "port": ${PORT_CNT}
  },
  "ioc_values": ${IOC_VALUES_JSON},
  "active_change_tickets": ${CHANGE_TICKETS_JSON},
  "prior_shift_open_items": ${OPEN_ITEMS_JSON},
  "baseline_hot_hosts": ${HOT_HOSTS_JSON},
  "hosts_with_deviations": ${HOSTS_WITH_DEV}
}
JSON

echo "[brief] shift_briefing.json written"
exit 0
