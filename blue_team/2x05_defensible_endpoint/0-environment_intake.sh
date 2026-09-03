#!/usr/bin/env bash
#
# Hawthorne capstone, Task 0 (Linux side): captures the raw, pre-hardening
# state of hawthorne-app-01 as a single deterministic JSON intake record.

set -euo pipefail

SCRIPT_NAME="0-environment_intake.sh"
SCRIPT_VERSION="1.0.0"
SCHEMA_VERSION="1.0"
RECORD_TYPE="environment_intake"
PHASE="pre_hardening"

ARTIFACT_SUBDIR="intake"
RECORD_BASENAME="environment_intake.json"

EXIT_OK=0
EXIT_FAIL=1
EXIT_ENV=2

COLLECTION_ERRORS=()

add_error() {
    local msg="$1"
    COLLECTION_ERRORS+=("$msg")
    echo "WARNING: $msg" >&2
}

# 1. Platform Verification
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: This script must run on Linux." >&2
    exit $EXIT_ENV
fi

# 2. Output Path Determination
OUTPUT_ROOT="${INTAKE_OUTPUT_ROOT:-./artifacts}"
for arg in "$@"; do
    case $arg in
        --output-root=*)
            OUTPUT_ROOT="${arg#*=}"
            shift
            ;;
        --allow-unprivileged)
            ALLOW_UNPRIVILEGED=1
            shift
            ;;
    esac
done

IS_ELEVATED=false
if [[ $EUID -eq 0 ]]; then
    IS_ELEVATED=true
else
    if [[ "${ALLOW_UNPRIVILEGED:-0}" -ne 1 ]]; then
        echo "WARNING: Must run as root. Re-run with sudo or pass --allow-unprivileged." >&2
        exit $EXIT_ENV
    fi
    add_error "run is not elevated, record is a lower bound only"
fi

# Dependency check
for cmd in dpkg-query ss systemctl sysctl find jq sha256sum; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: Required dependency missing: $cmd" >&2
        exit $EXIT_ENV
    fi
done

HOSTNAME=$(hostname -s 2>/dev/null || hostname)
UTCTIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# --- Data Collection ---

# Host Info
KERNEL_RELEASE=$(uname -r)
DISTRO_NAME="Unknown"
DISTRO_VERSION="Unknown"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_NAME="${NAME:-Linux}"
    DISTRO_VERSION="${VERSION_ID:-Unknown}"
fi

# Package Count
PKG_COUNT=$(dpkg-query -W -f='${Package}\n' 2>/dev/null | wc -l || echo 0)

# Listening Sockets
LISTENING_SOCKETS=$(ss -tulnpH 2>/dev/null | awk '{print $1, $5}' | jq -R 'split(" ") | {protocol: .[0], local_address: .[1]}' | jq -s '.' || echo "[]")

# Active Systemd Services
ACTIVE_SERVICES=$(systemctl list-units --type=service --state=active --no-legend 2>/dev/null | awk '{print $1}' | jq -R '.' | jq -s '.' || echo "[]")

# SSHD Config as Key-Value
SSHD_CONFIG_JSON="{}"
if [[ -f /etc/ssh/sshd_config ]]; then
    SSHD_CONFIG_JSON=$(grep -E '^^[A-Za-z0-9]' /etc/ssh/sshd_config 2>/dev/null | awk '{print $1, $2}' | jq -R 'split(" ") | {(.[0]): .[1]}' | jq -s 'add' || echo "{}")
else
    add_error "sshd_config: file /etc/ssh/sshd_config not found"
fi

# Sysctl Security Parameters
SYSCTL_JSON=$(sysctl -a 2>/dev/null | grep -E 'kernel\.(randomize_va_space|yama\.ptrace_scope)|net\.ipv4\.conf\.all\.(accept_redirects|send_redirects|ip_forward)' | jq -R 'split(" = ") | {(.[0]): .[1]}' | jq -s 'add' || echo "{}")

# SUID / SGID Count
SUID_SGID_COUNT=$(find / -perm /6000 -type f 2>/dev/null | wc -l || echo 0)

# World-Writable Files Count (Excluding /proc and /sys)
WORLD_WRITABLE_COUNT=$(find / -path /proc -prune -o -path /sys -prune -o -perm -0002 -type f -print 2>/dev/null | wc -l || echo 0)

# Firewall Ruleset Length (nftables)
NFT_RULESET_LEN=0
if command -v nft &>/dev/null; then
    NFT_RULESET_LEN=$(nft list ruleset 2>/dev/null | wc -l || echo 0)
else
    add_error "firewall: nft command not found"
fi

# Telemetry Presence
AUDITD_RUNNING=false
systemctl is-active --quiet auditd 2>/dev/null && AUDITD_RUNNING=true || true

RSYSLOG_RUNNING=false
systemctl is-active --quiet rsyslog 2>/dev/null && RSYSLOG_RUNNING=true || true

SYSMON_LINUX_PRESENT=false
if command -v sysmon 2>/dev/null || [[ -f /opt/sysmon/sysmon ]]; then
    SYSMON_LINUX_PRESENT=true
fi

# --- Construct JSON Output ---

ERRORS_JSON=$(printf '%s\n' "${COLLECTION_ERRORS[@]}" | jq -R '.' | jq -s '.' || echo "[]")

OUT_DIR="${OUTPUT_ROOT}/${ARTIFACT_SUBDIR}/${HOSTNAME}"
OUT_FILE="${OUT_DIR}/${RECORD_BASENAME}"

mkdir -p "${OUT_DIR}"

jq -n \
  --arg schema_version "$SCHEMA_VERSION" \
  --arg record_type "$RECORD_TYPE" \
  --arg phase "$PHASE" \
  --arg platform "linux" \
  --arg collected_at_utc "$UTCTIME" \
  --arg script "$SCRIPT_NAME" \
  --arg version "$SCRIPT_VERSION" \
  --argjson privileged "$IS_ELEVATED" \
  --arg hostname "$HOSTNAME" \
  --arg kernel_release "$KERNEL_RELEASE" \
  --arg distro_name "$DISTRO_NAME" \
  --arg distro_version "$DISTRO_VERSION" \
  --argjson pkg_count "$PKG_COUNT" \
  --argjson listening_sockets "$LISTENING_SOCKETS" \
  --argjson active_services "$ACTIVE_SERVICES" \
  --argjson sshd_config "$SSHD_CONFIG_JSON" \
  --argjson sysctl_params "$SYSCTL_JSON" \
  --argjson suid_sgid_count "$SUID_SGID_COUNT" \
  --argjson world_writable_count "$WORLD_WRITABLE_COUNT" \
  --argjson nft_ruleset_length "$NFT_RULESET_LEN" \
  --argjson auditd_running "$AUDITD_RUNNING" \
  --argjson rsyslog_running "$RSYSLOG_RUNNING" \
  --argjson sysmon_linux_present "$SYSMON_LINUX_PRESENT" \
  --argjson errors "$ERRORS_JSON" \
  '{
    schema_version: $schema_version,
    record_type: $record_type,
    phase: $phase,
    platform: $platform,
    collected_at_utc: $collected_at_utc,
    collector: {
      script: $script,
      version: $version,
      privileged: $privileged
    },
    host: {
      hostname: $hostname,
      kernel_release: $kernel_release,
      distribution: $distro_name,
      patch_level: $distro_version
    },
    packages: {
      installed_count: $pkg_count
    },
    sockets: $listening_sockets,
    services: {
      active_units: $active_services
    },
    sshd_config: $sshd_config,
    sysctl: $sysctl_params,
    filesystem: {
      suid_sgid_count: $suid_sgid_count,
      world_writable_count: $world_writable_count
    },
    firewall: {
      nft_ruleset_length: $nft_ruleset_length
    },
    telemetry: {
      auditd_running: $auditd_running,
      rsyslog_running: $rsyslog_running,
      sysmon_for_linux_present: $sysmon_linux_present
    },
    collection_errors: $errors
  }' > "${OUT_FILE}.tmp"

# Atomic move
mv "${OUT_FILE}.tmp" "${OUT_FILE}"

# SHA256 checksum generation
(cd "${OUT_DIR}" && sha256sum "${RECORD_BASENAME}" > "${RECORD_BASENAME}.sha256")

echo "${OUT_FILE}"

if [[ ${#COLLECTION_ERRORS[@]} -gt 0 ]]; then
    exit $EXIT_FAIL
fi

exit $EXIT_OK
