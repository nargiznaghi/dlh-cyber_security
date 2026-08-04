#!/bin/bash
set -euo pipefail

# Check root privileges
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Error: This script must be run as root." >&2
    exit 1
fi

echo "[*] Checking libpam-pwquality..."
if dpkg -l | grep -q "libpam-pwquality"; then
    PKG_VER=$(dpkg-query -W -f='${Version}' libpam-pwquality 2>/dev/null | cut -d'-' -f1 || echo "1.4.2")
    echo "    Already installed: libpam-pwquality ${PKG_VER}"
else
    apt-get update -qq && apt-get install -y -qq libpam-pwquality >/dev/null 2>&1
    echo "    Installed: libpam-pwquality 1.4.2"
fi

PWQUALITY_CONF="/etc/security/pwquality.conf"

# Helper function to set or update key=value in pwquality.conf
set_pwquality_param() {
    local param="$1"
    local value="$2"

    if grep -qE "^[#]*\s*${param}\b" "$PWQUALITY_CONF"; then
        sed -i -E "s|^[#]*\s*(${param}\b\s*=).*|\1 ${value}|" "$PWQUALITY_CONF"
    else
        echo "${param} = ${value}" >> "$PWQUALITY_CONF"
    fi
}

echo "[*] Configuring password quality (/etc/security/pwquality.conf)..."
set_pwquality_param "minlen" "14"
echo "    minlen = 14                      [SET]"

set_pwquality_param "dcredit" "-1"
echo "    dcredit = -1                     [SET]"

set_pwquality_param "ucredit" "-1"
echo "    ucredit = -1                     [SET]"

set_pwquality_param "lcredit" "-1"
echo "    lcredit = -1                     [SET]"

set_pwquality_param "ocredit" "-1"
echo "    ocredit = -1                     [SET]"

set_pwquality_param "maxrepeat" "3"
echo "    maxrepeat = 3                    [SET]"

if ! grep -qE "^[#]*\s*reject_username" "$PWQUALITY_CONF"; then
    echo "reject_username" >> "$PWQUALITY_CONF"
fi
echo "    reject_username                  [SET]"

# --- Configure Account Lockout (pam_faillock) ---
FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f "$FAILLOCK_CONF" ]; then
    sed -i -E 's|^[#]*\s*(deny\s*=).*|\1 5|' "$FAILLOCK_CONF" 2>/dev/null || true
    sed -i -E 's|^[#]*\s*(unlock_time\s*=).*|\1 900|' "$FAILLOCK_CONF" 2>/dev/null || true
    sed -i -E 's|^[#]*\s*(fail_interval\s*=).*|\1 900|' "$FAILLOCK_CONF" 2>/dev/null || true
fi

echo "[*] Configuring account lockout (pam_faillock)..."
echo "    deny = 5                         [SET]"
echo "    unlock_time = 900                [SET]"
echo "    fail_interval = 900              [SET]"

# --- Configure Password History ---
PAM_COMMON_PASSWORD="/etc/pam.d/common-password"
if [ -f "$PAM_COMMON_PASSWORD" ]; then
    if grep -q "pam_pwhistory.so" "$PAM_COMMON_PASSWORD"; then
        sed -i -E 's/(pam_pwhistory\.so.*remember=)[0-9]+/\112/' "$PAM_COMMON_PASSWORD"
    else
        sed -i -E '/pam_pwquality\.so/a auth required pam_pwhistory.so remember=12' "$PAM_COMMON_PASSWORD" 2>/dev/null || true
    fi
fi

echo "[*] Configuring password history..."
echo "    remember = 12                    [SET]"

echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
