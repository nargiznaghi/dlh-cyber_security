#!/bin/bash
set -eo pipefail

fail() {
  echo "[ERROR] $1" >&2
  exit 1
}

# 1. PATH üzərindəki alətlərin yoxlanılması
check_binary() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    fail "Binary missing: $bin"
  fi
}

check_binary jq
check_binary python3
check_binary yq
check_binary sigma-cli
check_binary sha256sum

JQ_VER=$(jq --version 2>&1 | sed -E 's/jq-?//')
PYTHON_VER=$(python3 --version 2>&1 | awk '{print $2}')
YQ_VER=$(yq --version 2>&1 | awk '{print $NF}' | sed -E 's/^v//')
SIGMA_VER=$(sigma-cli --version 2>&1 | head -n 1 | awk '{print $NF}' | sed -E 's/^v//' || sigma --version 2>&1 | head -n 1 | awk '{print $NF}' | sed -E 's/^v//')

echo "[intake] jq ${JQ_VER} OK"
echo "[intake] python3 ${PYTHON_VER} OK"
echo "[intake] yq ${YQ_VER} OK"
echo "[intake] sigma-cli ${SIGMA_VER} OK"
echo "[intake] sha256sum OK"

# 2. Əvvəlki layihə fayllarının yoxlanılması
if [[ -z "$PIPELINE_BIN" || ! -x "$PIPELINE_BIN" ]]; then
  fail "PIPELINE_BIN ('$PIPELINE_BIN') executable file not found."
fi
echo "[intake] PIPELINE_BIN OK"

if [[ -z "$BASELINE_BIN" || ! -x "$BASELINE_BIN" ]]; then
  fail "BASELINE_BIN ('$BASELINE_BIN') executable file not found."
fi
echo "[intake] BASELINE_BIN OK"

if [[ -z "$CATALOG_DIR" || ! -d "$CATALOG_DIR" ]]; then
  fail "CATALOG_DIR ('$CATALOG_DIR') readable directory not found."
fi

YML_COUNT=$(find "$CATALOG_DIR" -maxdepth 1 \( -name "*.yml" -o -name "*.yaml" \) | wc -l)
if [[ "$YML_COUNT" -eq 0 ]]; then
  fail "CATALOG_DIR contains no .yml rules."
fi
echo "[intake] CATALOG_DIR OK (${YML_COUNT} rules)"

if [[ -z "$TRIAGE_BIN" || ! -x "$TRIAGE_BIN" ]]; then
  fail "TRIAGE_BIN ('$TRIAGE_BIN') executable file not found."
fi
echo "[intake] TRIAGE_BIN OK"

# 3. CAPSTONE_PACK yoxlanılması
if [[ -z "$CAPSTONE_PACK" || ! -d "$CAPSTONE_PACK" || -z "$(ls -A "$CAPSTONE_PACK" 2>/dev/null)" ]]; then
  fail "CAPSTONE_PACK ('$CAPSTONE_PACK') is missing, unreadable, or empty."
fi
echo "[intake] CAPSTONE_PACK OK"

# 4. ASSETS_DIR yoxlanılması
if [[ -z "$ASSETS_DIR" || ! -d "$ASSETS_DIR" ]]; then
  fail "ASSETS_DIR ('$ASSETS_DIR') missing or not set."
fi

ASSET_FILES=("assets.json" "ioc_feed.json" "hc_red7_advisory.md" "change_tickets.json" "prior_shift_notes.md")
for file in "${ASSET_FILES[@]}"; do
  if [[ ! -f "$ASSETS_DIR/$file" ]]; then
    fail "Missing required asset file: $file"
  fi
done
echo "[intake] ASSETS_DIR: 5 meta files OK"

# 5. WAZUH_EXPORTS yoxlanılması
if [[ -z "$WAZUH_EXPORTS" || ! -d "$WAZUH_EXPORTS" ]]; then
  fail "WAZUH_EXPORTS ('$WAZUH_EXPORTS') missing or not set."
fi

WAZUH_FILES=("incident_A_search_results.json" "incident_B_search_results.json" "incident_C_search_results.json" "campaign_dashboard_summary.md")
for file in "${WAZUH_FILES[@]}"; do
  if [[ ! -f "$WAZUH_EXPORTS/$file" ]]; then
    fail "Missing required Wazuh export file: $file"
  fi
done
echo "[intake] WAZUH_EXPORTS: 4 export files OK"

# 6. Məlumatların oxunması (IOC count və Cluster ID)
IOC_COUNT=$(jq '.iocs | length' "$ASSETS_DIR/ioc_feed.json")
echo "[intake] ioc_feed.json OK (${IOC_COUNT} entries)"

CLUSTER_ID=$(grep "HC-RED7" "$ASSETS_DIR/hc_red7_advisory.md" | head -n 1 | grep -o "HC-RED7[A-Za-z0-9_-]*" || echo "HC-RED7")
echo "[intake] advisory ${CLUSTER_ID} loaded"

# 7. Workspace strukturunun yaradılması
if [[ -z "$SHIFT_WORKSPACE" ]]; then
  SHIFT_WORKSPACE="./workspace"
fi

mkdir -p "$SHIFT_WORKSPACE"/{runtime,enriched,alerts,investigations,campaign,reports,response,handoff}

touch "$SHIFT_WORKSPACE/MANIFEST.json"
touch "$SHIFT_WORKSPACE/runtime/shift_start.json"
touch "$SHIFT_WORKSPACE/runtime/pipeline_stats.json"
touch "$SHIFT_WORKSPACE/runtime/baseline_stats.json"
touch "$SHIFT_WORKSPACE/runtime/triage_stats.json"

touch "$SHIFT_WORKSPACE/enriched/incident_A_events.json"
touch "$SHIFT_WORKSPACE/enriched/incident_B_events.json"
touch "$SHIFT_WORKSPACE/enriched/incident_C_events.json"
touch "$SHIFT_WORKSPACE/enriched/campaign_events.json"

touch "$SHIFT_WORKSPACE/alerts/incident_A_alerts.json"
touch "$SHIFT_WORKSPACE/alerts/incident_B_alerts.json"
touch "$SHIFT_WORKSPACE/alerts/incident_C_alerts.json"
touch "$SHIFT_WORKSPACE/alerts/campaign_alerts.json"

touch "$SHIFT_WORKSPACE/investigations/incident_A_findings.json"
touch "$SHIFT_WORKSPACE/investigations/incident_B_findings.json"
touch "$SHIFT_WORKSPACE/investigations/incident_C_findings.json"
touch "$SHIFT_WORKSPACE/investigations/campaign_findings.json"

touch "$SHIFT_WORKSPACE/campaign/campaign_assessment.json"

touch "$SHIFT_WORKSPACE/reports/incident_A_report.md"
touch "$SHIFT_WORKSPACE/reports/incident_B_report.md"
touch "$SHIFT_WORKSPACE/reports/incident_C_report.md"

touch "$SHIFT_WORKSPACE/response/incident_A_response.json"
touch "$SHIFT_WORKSPACE/response/incident_B_response.json"
touch "$SHIFT_WORKSPACE/response/incident_C_response.json"

touch "$SHIFT_WORKSPACE/handoff/shift_handoff.md"

echo "[intake] workspace layout created at $SHIFT_WORKSPACE"

# 8. shift_start.json faylının yazılması
SHIFT_ID="SHIFT-$(date -u +'%Y%m%d-%H%M')"
HOSTNAME_LAB=$(hostname)
STARTED_AT=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
RESOLVED_CAPSTONE=$(cd "$CAPSTONE_PACK" && pwd)

cat <<JSON > "$SHIFT_WORKSPACE/runtime/shift_start.json"
{
  "shift_id": "${SHIFT_ID}",
  "analyst_host": "${HOSTNAME_LAB}",
  "started_at": "${STARTED_AT}",
  "tools": {
    "jq": "${JQ_VER}",
    "python3": "${PYTHON_VER}",
    "yq": "${YQ_VER}",
    "sigma-cli": "${SIGMA_VER}",
    "sha256sum": "present"
  },
  "prior_project_bins": {
    "pipeline": true,
    "baseline": true,
    "catalog": true,
    "triage": true
  },
  "capstone_pack": "${RESOLVED_CAPSTONE}",
  "ioc_feed_count": ${IOC_COUNT},
  "advisory_cluster_id": "${CLUSTER_ID}",
  "wazuh_exports_verified": true
}
JSON

echo "[intake] shift_start.json written"
exit 0
