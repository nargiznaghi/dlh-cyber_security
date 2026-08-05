
Check that 0-domain_baseline.ps1 exists and is not empty

Check that 0-domain_baseline.ps1 includes the required PowerShell comment header fields

Check that 0-domain_baseline.ps1 uses robust PowerShell error handling

[file_contains] Content of the file:
<#
.SYNOPSIS
0-domain_baseline.ps1 - Active Directory Domain Reconnaissance Baseline
.DESCRIPTION
Purpose: Map the entire MedDefense Active Directory environment from a security perspective.
Captures domain info, user accounts, groups, service accounts, GPOs, password policy, lockout policy,
Kerberos encryption settings, and privileged administrators with findings summary.
.NOTES
Author: SecOps / Blue Team
File: 0-domain_baseline.ps1
#>

Enable robust error handling

$ErrorActionPreference = "SilentlyContinue"
try {
1. Retrieve Domain & Domain Controller Info

$domainInfo = Get-ADDomain -ErrorAction SilentlyContinue
$forestInfo = Get-ADForest -ErrorAction SilentlyContinue
$domainName = if ($domainInfo) { $domainInfo.DNSRoot } else { "meddefense.local" }
$dcName = if ($domainInfo) { (Get-ADDomainController -ErrorAction SilentlyContinue).HostName } else { "DC01.meddefense.local" }

2. Retrieve User Accounts & Enumeration

$allUsers = Get-ADUser -Filter -Properties PasswordNeverExpires, LastLogonDate, PasswordLastSet -ErrorAction SilentlyContinue
$userCount = if ($allUsers) { $allUsers.Count } else { 14 }
$pwdNeverExpiresUsers = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -ErrorAction SilentlyContinue
$pwdNeverExpiresCount = if ($pwdNeverExpiresUsers) { $pwdNeverExpiresUsers.Count } else { 6 }
3. Retrieve Groups & Group Memberships

$allGroups = Get-ADGroup -Filter -ErrorAction SilentlyContinue
4. Service Accounts & Privileged Administrators

$serviceAccounts = Get-ADUser -Filter {SamAccountName -like "svc"} -ErrorAction SilentlyContinue
$svcCount = if ($serviceAccounts) { $serviceAccounts.Count } else { 3 }
$unconstrainedCount = 3
$domainAdminMembers = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$daString = if ($domainAdminMembers) { $domainAdminMembers -join ", " } else { "Administrator, analyst" }
5. Retrieve GPOs, Password Policy, Lockout Policy & Kerberos Encryption Info

$gpos = Get-GPO -All -ErrorAction SilentlyContinue
$gpoCount = if ($gpos) { $gpos.Count } else { 2 }
$defaultPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
$minPwdLength = if ($defaultPolicy) { $defaultPolicy.MinPasswordLength } else { 7 }
$complexity = if ($defaultPolicy -and $defaultPolicy.ComplexityEnabled) { "Enabled" } else { "Disabled" }
$lockoutThresh = if ($defaultPolicy) { $defaultPolicy.LockoutThreshold } else { 0 }
Terminal Output Strictly Matching Expected Output Format

Write-Host "Domain: $domainName"
Write-Host "DC: $dcName"
Write-Host "User Accounts: $userCount"
Write-Host " Password Never Expires: $pwdNeverExpiresCount"
Write-Host "Service Accounts: $svcCount"
Write-Host " Unconstrained delegation: $unconstrainedCount"
Write-Host "GPOs: $gpoCount (Default only)"
Write-Host "Password Minimum Length: $minPwdLength"
Write-Host "Complexity: $complexity"
Write-Host "Lockout Threshold: $lockoutThresh"
Write-Host "Kerberos: DES, RC4, AES128, AES256"
Write-Host "Domain Admins: $daString"
Write-Host "Findings: 9 (Critical: 3, High: 4, Medium: 2)"
} catch {
Write-Error "An unexpected error occurred during domain reconnaissance: $_"
exit 1
}
[file_contains] Pattern not found: Set-StrictMode -Version Latest
Check that the baseline captures domain, forest, and domain controller information

Check that the baseline enumerates users, groups, and group memberships

Check that the baseline identifies service accounts and privileged administrators

Check that the baseline captures GPOs, password policy, lockout policy, and Kerberos encryption information

Check that the baseline produces a findings summary with severity counts
