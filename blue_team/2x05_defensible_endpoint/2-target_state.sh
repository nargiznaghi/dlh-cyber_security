#!/usr/bin/env bash
#
# Script Name: 2-target_state.sh
# Description: Generates target_state.json for harden/audit benchmark validation.
#

set -euo pipefail

TARGET_DIR="capstone"
TARGET_FILE="${TARGET_DIR}/target_state.json"

# Print colored log outputs
log_info() { echo -e "\033[0;32m[INFO]\033[0m $1"; }
log_warn() { echo -e "\033[0;33m[WARN]\033[0m $1"; }
log_error() { echo -e "\033[0;31m[FATAL]\033[0m $1"; exit 1; }

# Function to validate the target_state.json structure
validate_schema() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_error "Validation failed: File '$file' does not exist."
    fi

    # Check if file is valid JSON and contains the required keys
    if jq -e '.controls | type == "array" and length > 0' "$file" >/dev/null 2>&1; then
        log_info "Validation SUCCESS: '$file' is valid JSON and contains required controls."
    else
        log_error "Validation FAILED: '$file' is invalid or missing 'controls' array."
    fi
}

# Parse Arguments
FORCE=0
VALIDATE_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --force)
            FORCE=1
            ;;
        --validate)
            VALIDATE_ONLY=1
            ;;
        *)
            echo "Usage: $0 [--force] [--validate]"
            exit 1
            ;;
    esac
done

if [[ "$VALIDATE_ONLY" -eq 1 ]]; then
    validate_schema "$TARGET_FILE"
    exit 0
fi

# Ensure output directory exists
mkdir -p "$TARGET_DIR"

# Handle existing file according to idempotency rules
if [[ -f "$TARGET_FILE" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        SUPERSEDED_FILE="${TARGET_FILE}.${TIMESTAMP}.superseded"
        log_warn "Target state exists. Backing up to '${SUPERSEDED_FILE}' due to --force flag."
        mv "$TARGET_FILE" "$SUPERSEDED_FILE"
    else
        log_info "Target state file '${TARGET_FILE}' already exists. Use --force to regenerate."
        exit 0
    fi
fi

log_info "Generating '${TARGET_FILE}'..."

# Write JSON output
cat << 'EOF' > "$TARGET_FILE"
{
  "schema_version": "1.0",
  "record_type": "target_state",
  "generated_at": "2026-09-03T23:27:00Z",
  "generated_by": "capstone_target_state_builder",
  "controls": [
    {
      "id": "LNX-SSH-01",
      "description": "SSH root login must be disabled",
      "os": "linux",
      "type": "file_pattern",
      "target_file": "/etc/ssh/sshd_config",
      "expected_value": "^[[:space:]]*PermitRootLogin[[:space:]]+no[[:space:]]*$",
      "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd.",
      "severity": "CRITICAL",
      "check_target": "grep -E '^[[:space:]]*PermitRootLogin[[:space:]]+no' /etc/ssh/sshd_config"
    },
    {
      "id": "LNX-SSH-02",
      "description": "SSH must refuse password authentication",
      "os": "linux",
      "type": "file_pattern",
      "target_file": "/etc/ssh/sshd_config",
      "expected_value": "^[[:space:]]*PasswordAuthentication[[:space:]]+no[[:space:]]*$",
      "remediation": "Set PasswordAuthentication no in /etc/ssh/sshd_config and restart sshd.",
      "severity": "HIGH",
      "check_target": "grep -E '^[[:space:]]*PasswordAuthentication[[:space:]]+no' /etc/ssh/sshd_config"
    },
    {
      "id": "LNX-SYSCTL-01",
      "description": "IPv4 forwarding must be disabled",
      "os": "linux",
      "type": "sysctl",
      "target_file": "/proc/sys/net/ipv4/ip_forward",
      "expected_value": "0",
      "remediation": "Execute sysctl -w net.ipv4.ip_forward=0 and persist in /etc/sysctl.conf.",
      "severity": "MEDIUM",
      "check_target": "test \"$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)\" = \"0\""
    },
    {
      "id": "LNX-AUDITD-01",
      "description": "Audit daemon service must be running",
      "os": "linux",
      "type": "service_status",
      "target_service": "auditd",
      "expected_value": "active",
      "remediation": "Enable and start the auditd daemon using systemctl enable --now auditd.",
      "severity": "HIGH",
      "check_target": "systemctl is-active --quiet auditd"
    },
    {
      "id": "LNX-APPARMOR-01",
      "description": "AppArmor enforcement framework must be active",
      "os": "linux",
      "type": "security_module",
      "expected_value": "enforcing",
      "remediation": "Ensure AppArmor is installed, enabled in bootloader, and running.",
      "severity": "HIGH",
      "check_target": "aa-status --enabled"
    },
    {
      "id": "LNX-LYNIS-01",
      "description": "Lynis security audit score must meet minimum threshold",
      "os": "linux",
      "type": "audit_metric",
      "expected_value": ">= 75",
      "remediation": "Resolve highlighted high/critical vulnerabilities identified during Lynis scan.",
      "severity": "MEDIUM",
      "check_target": "test $(lynis audit system --quick | grep -oP 'Hardening index : \\[\\K[0-9]+') -ge 75"
    },
    {
      "id": "WIN-FW-01",
      "description": "Windows Firewall Profiles must all be enabled",
      "os": "windows",
      "type": "firewall",
      "expected_value": "True",
      "remediation": "Execute Set-NetFirewallProfile -All -Enabled True via PowerShell.",
      "severity": "CRITICAL",
      "check_target": "Get-NetFirewallProfile | Where-Object { $_.Enabled -ne $true }"
    },
    {
      "id": "WIN-SYSMON-01",
      "description": "Sysmon telemetry logging service must be active",
      "os": "windows",
      "type": "service_status",
      "target_service": "Sysmon64",
      "expected_value": "Running",
      "remediation": "Install and start Sysmon with a baseline configuration scheme.",
      "severity": "HIGH",
      "check_target": "Get-Service -Name Sysmon64 | Where-Object { $_.Status -eq 'Running' }"
    },
    {
      "id": "LNX-PATCH-01",
      "description": "Zero security updates pending installation",
      "os": "linux",
      "type": "package_management",
      "expected_value": "0",
      "remediation": "Run system update commands (e.g., apt update && apt upgrade -y).",
      "severity": "HIGH",
      "check_target": "test $(apt-get -s upgrade | grep -ci 'security') -eq 0"
    },
    {
      "id": "LNX-NFTABLES-01",
      "description": "Nftables filtering engine must have configured rulesets",
      "os": "linux",
      "type": "firewall",
      "expected_value": "active",
      "remediation": "Enable nftables and apply baseline drop rulesets.",
      "severity": "HIGH",
      "check_target": "nft list ruleset | grep -q 'table'"
    }
  ]
}
EOF

log_info "Target state file written successfully to '${TARGET_FILE}'."

# Self-validate generated output
validate_schema "$TARGET_FILE"
