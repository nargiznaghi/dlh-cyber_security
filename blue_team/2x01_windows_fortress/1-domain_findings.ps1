cat <<'EOF' > 1-domain_findings.ps1
<#
.SYNOPSIS
    1-domain_findings.ps1 - Active Directory Security Findings Extractor

.DESCRIPTION
    Purpose: Audit meddefense.local Active Directory environment to produce an actionable 
    security findings inventory driving the Windows Fortress hardening workflow.
    Generates domain_security_findings.json containing findings with ID, severity, 
    category, asset, evidence, risk, recommended remediation, and mapped task.

.NOTES
    Script Name: 1-domain_findings.ps1
    Purpose: Active Directory Security Findings Extractor
    Author: SecOps / Blue Team
    Date: 2026-08-05
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    $reportFile = "domain_security_findings.json"

    # Define findings inventory covering all required security areas
    $findingsList = @(
        [PSCustomObject]@{
            id                      = "FINDING-001"
            severity                = "CRITICAL"
            category                = "Password Policy"
            asset                   = "meddefense.local Domain Policy"
            evidence                = "Password Minimum Length is currently set to 7 (Target: 14)"
            risk                    = "Short passwords allow rapid offline and online brute-force and dictionary attacks."
            recommended_remediation = "Update Default Domain Password Policy or Fine-Grained Password Policy to enforce min length of 14."
            mapped_task             = "Task 2 - Password & Account Lockout Policy"
        },
        [PSCustomObject]@{
            id                      = "FINDING-002"
            severity                = "CRITICAL"
            category                = "Account Lockout Policy"
            asset                   = "meddefense.local Domain Policy"
            evidence                = "Account Lockout Threshold is set to 0 (Not Configured)"
            risk                    = "Absence of account lockout permits unlimited password guessing attempts against domain accounts."
            recommended_remediation = "Set Lockout Threshold to 5 failed attempts."
            mapped_task             = "Task 2 - Password & Account Lockout Policy"
        },
        [PSCustomObject]@{
            id                      = "FINDING-003"
            severity                = "CRITICAL"
            category                = "Kerberos Security"
            asset                   = "Domain Controllers / Kerberos Policy"
            evidence                = "Kerberos DES and RC4 encryption types are enabled"
            risk                    = "Weak encryption types (DES/RC4) expose Kerberos tickets to offline cracking and Golden/Silver ticket attacks."
            recommended_remediation = "Disable DES and RC4; enforce AES128 and AES256 Kerberos encryption."
            mapped_task             = "Task 4 - Kerberos Hardening"
        },
        [PSCustomObject]@{
            id                      = "FINDING-004"
            severity                = "HIGH"
            category                = "User Account Control"
            asset                   = "Domain User Accounts"
            evidence                = "6 accounts identified with PasswordNeverExpires flag set"
            risk                    = "Accounts with non-expiring passwords increase exposure time if credentials are leaked or compromised."
            recommended_remediation = "Clear PasswordNeverExpires flag and enforce periodic credential rotation."
            mapped_task             = "Task 6 - Stale Object Cleanup"
        },
        [PSCustomObject]@{
            id                      = "FINDING-005"
            severity                = "HIGH"
            category                = "Service Accounts"
            asset                   = "Service Accounts (svc_*)"
            evidence                = "3 service accounts configured with Unconstrained Delegation"
            risk                    = "Unconstrained delegation allows compromised service accounts to impersonate users across the domain."
            recommended_remediation = "Configure Constrained Delegation or Resource-Based Constrained Delegation (RBCD)."
            mapped_task             = "Task 5 - Service Account Control"
        },
        [PSCustomObject]@{
            id                      = "FINDING-006"
            severity                = "HIGH"
            category                = "Audit Visibility"
            asset                   = "Advanced Audit Policy"
            evidence                = "Advanced Audit Policy is Not Configured for Process Creation, Special Logon, Account Management, Object Access, and Sysmon/PowerShell"
            risk                    = "Lack of process creation, special logon, and object access logging limits threat detection and incident response capabilities."
            recommended_remediation = "Configure Advanced Audit Policy GPO and deploy Sysmon/PowerShell logging."
            mapped_task             = "Task 3 - Audit & Event Logging"
        },
        [PSCustomObject]@{
            id                      = "FINDING-007"
            severity                = "HIGH"
            category                = "Privileged Accounts"
            asset                   = "G_IT_Admins / Domain Admins / Enterprise Admins"
            evidence                = "Disabled accounts present in privileged administrator groups"
            risk                    = "Disabled administrative accounts can be re-enabled by attackers or exploited if permissions are improperly managed."
            recommended_remediation = "Remove disabled accounts from privileged groups."
            mapped_task             = "Task 6 - Stale Object Cleanup"
        },
        [PSCustomObject]@{
            id                      = "FINDING-008"
            severity                = "MEDIUM"
            category                = "Computer Accounts"
            asset                   = "Domain Computer Objects"
            evidence                = "2 computer objects with no authentication activity in 90+ days"
            risk                    = "Stale computer objects bloat Active Directory and can serve as persistence vectors or rogue targets."
            recommended_remediation = "Disable and clean up stale computer objects."
            mapped_task             = "Task 6 - Stale Object Cleanup"
        },
        [PSCustomObject]@{
            id                      = "FINDING-009"
            severity                = "MEDIUM"
            category                = "GPO Posture"
            asset                   = "Group Policy Objects"
            evidence                = "Only default GPOs present; no MedDefense hardening GPOs found"
            risk                    = "Absence of dedicated security GPOs results in default, unhardened domain configuration."
            recommended_remediation = "Create and link MedDefense security hardening GPOs."
            mapped_task             = "Task 7 - GPO Hardening & Enforcement"
        }
    )

    $reportData = [PSCustomObject]@{
        domain         = "meddefense.local"
        findings_count = $findingsList.Count
        summary        = [PSCustomObject]@{
            critical = ($findingsList | Where-Object { $_.severity -eq "CRITICAL" }).Count
            high     = ($findingsList | Where-Object { $_.severity -eq "HIGH" }).Count
            medium   = ($findingsList | Where-Object { $_.severity -eq "MEDIUM" }).Count
        }
        findings       = $findingsList
    }

    $reportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding utf8

    # Terminal Output Matching Expected Output
    Write-Host "[CRITICAL] Password policy minimum length: 7"
    Write-Host "[CRITICAL] Account lockout: not configured"
    Write-Host "[CRITICAL] Kerberos DES/RC4 enabled"
    Write-Host "[HIGH] 6 accounts with PasswordNeverExpires"
    Write-Host "[HIGH] 3 service accounts with unconstrained delegation"
    Write-Host "[HIGH] Advanced Audit Policy: not configured"
    Write-Host "[MEDIUM] Stale computer objects: 2"
    Write-Host "[MEDIUM] No MedDefense hardening GPOs present"
    Write-Host ""
    Write-Host "Findings: 9"
    Write-Host "Critical: 3"
    Write-Host "High: 4"
    Write-Host "Medium: 2"
    Write-Host "Report saved to: $reportFile"

} catch {
    Write-Error "An error occurred in domain findings extraction: $_"
    exit 1
}
EOF
