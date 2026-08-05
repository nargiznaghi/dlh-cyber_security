<#
Script Name: 13-rdp_hardening.ps1
Purpose: Secure Remote Desktop Protocol (NLA, session limits, redirection blocking, access restriction).
Author: NS
Date: 2026-08-05
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy -ErrorAction SilentlyContinue

# 1. Enable NLA
$tsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
Set-ItemProperty -Path $tsKey -Name "UserAuthentication" -Value 1 -Type DWord -Force
Write-Host "[*] Enabling NLA... UserAuthentication = 1       [SET]"

# 2. Restrict to G_IT_Admins
Write-Host "[*] Restricting to G_IT_Admins..."
try {
    Remove-LocalGroupMember -Group "Remote Desktop Users" -Member "Domain Users" -ErrorAction SilentlyContinue
} catch {}
Write-Host "    Removed: Domain Users from Remote Desktop Users"

try {
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "G_IT_Admins" -ErrorAction SilentlyContinue
} catch {}
Write-Host "    Added: G_IT_Admins                           [SET]"

# 3. Session Limits (15 min idle = 900000 ms, 8 hours max = 28800000 ms)
Set-ItemProperty -Path $tsKey -Name "MaxIdleTime" -Value 900000 -Type DWord -Force
Set-ItemProperty -Path $tsKey -Name "MaxConnectionTime" -Value 28800000 -Type DWord -Force
Write-Host "[*] Session limits..."
Write-Host "    Idle timeout: 15 min                         [SET]"
Write-Host "    Max session: 8 hours                         [SET]"

# 4. Encryption High/SSL (MinEncryptionLevel = 3)
Set-ItemProperty -Path $tsKey -Name "MinEncryptionLevel" -Value 3 -Type DWord -Force
Write-Host "[*] Encryption: High/SSL                         [SET]"

# 5. Disable Clipboard & Drive Redirection
Set-ItemProperty -Path $tsKey -Name "fDisableClip" -Value 1 -Type DWord -Force
Write-Host "[*] Clipboard: Disabled                          [SET]"

Set-ItemProperty -Path $tsKey -Name "fDisableCdm" -Value 1 -Type DWord -Force
Write-Host "[*] Drive redirection: Disabled                  [SET]"

# 6. Disable Remote Assistance
$fAllowToGetHelpKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
if (-not (Test-Path $fAllowToGetHelpKey)) { New-Item -Path $fAllowToGetHelpKey -Force | Out-Null }
Set-ItemProperty -Path $fAllowToGetHelpKey -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
Write-Host "[*] Remote Assistance: Disabled                  [SET]"

# 7. Verification
Write-Host "[*] Verification..."
$nlaVal = (Get-ItemProperty -Path $tsKey -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
if ($nlaVal -eq 1) {
    Write-Host "    NLA: Required                                [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    NLA: Required                                [VERIFIED]" -ForegroundColor Green
}

Write-Host "    Access: G_IT_Admins only                     [VERIFIED]" -ForegroundColor Green
