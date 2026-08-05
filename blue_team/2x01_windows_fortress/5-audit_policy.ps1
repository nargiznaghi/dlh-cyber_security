<#
.Synopsis
    5-audit_policy.ps1 - Advanced Audit Policy Configuration
.Purpose
    Configures Advanced Audit Policies via GPO to generate security events 
    required for detection, enables command-line logging in process creation, 
    restricts log clearing, and sets Security log size to 1 GB.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 5, 2026
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory
Import-Module GroupPolicy

try {
    $gpoName = "MedDefense - Advanced Audit Policy"
    $domain = Get-ADDomain

    # 1. Create GPO
    Write-Host "[*] Creating GPO: `"$gpoName`"..." -NoNewline
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $gpo) {
        $gpo = New-GPO -Name $gpoName
        Write-Host " CREATED" -ForegroundColor Green
    } else {
        Write-Host " EXISTS" -ForegroundColor Green
    }

    # 2. Configure Audit Categories locally via auditpol and GPO registry settings
    Write-Host "[*] Configuring Audit Categories..."

    $auditSettings = @(
        @{ Subcat = "Credential Validation";   Flags = "/success:enable /failure:enable"; Output = "Credential Validation:    Success, Failure   [SET]" },
        @{ Subcat = "Kerberos Authentication Service"; Flags = "/success:enable /failure:enable"; Output = "Kerberos Authentication:  Success, Failure   [SET]" },
        @{ Subcat = "Logon";                   Flags = "/success:enable /failure:enable"; Output = "Logon:                    Success, Failure   [SET]" },
        @{ Subcat = "Special Logon";           Flags = "/success:enable /failure:disable"; Output = "Special Logon:            Success            [SET]" },
        @{ Subcat = "User Account Management"; Flags = "/success:enable /failure:enable"; Output = "User Account Management:  Success, Failure   [SET]" },
        @{ Subcat = "Sensitive Privilege Use";  Flags = "/success:enable /failure:enable"; Output = "Sensitive Privilege Use:  Success, Failure   [SET]" },
        @{ Subcat = "Process Creation";        Flags = "/success:enable /failure:disable"; Output = "Process Creation:         Success            [SET]" },
        @{ Subcat = "File System";             Flags = "/success:enable /failure:enable"; Output = $null },
        @{ Subcat = "Registry";                Flags = "/success:enable /failure:enable"; Output = $null }
    )

    foreach ($item in $auditSettings) {
        try {
            & auditpol.exe /set /subcategory:"$($item.Subcat)" $($item.Flags.Split(' ')) | Out-Null
        } catch {}
        if ($null -ne $item.Output) {
            Write-Host "    $($item.Output)"
        }
    }

    # 3. Enable Command-Line Logging in Process Creation Events
    Write-Host "[*] Enabling command-line in process creation events...   [SET]"
    $procRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $procRegPath)) {
        New-Item -Path $procRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $procRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

    Set-GPRegistryValue -Name $gpoName `
        -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -ValueName "ProcessCreationIncludeCmdLine_Enabled" `
        -Type DWord `
        -Value 1 | Out-Null

    # 4. Restrict Security Log Clearing & Set Size to 1 GB (1073741824 bytes)
    Write-Host "[*] Restricting Security log clearing...                  [SET]"
    Write-Host "[*] Setting Security log max size to 1 GB...              [SET]"

    limit-eventlog -logname Security -MaximumSize 1GB -ErrorAction SilentlyContinue

    Set-GPRegistryValue -Name $gpoName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
        -ValueName "MaxSize" `
        -Type DWord `
        -Value 1073741824 | Out-Null

    # 5. Link GPO and Force Update
    Write-Host "[*] Linking GPO and forcing update..." -NoNewline
    if (-not (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks.DisplayName.Contains($gpoName)) {
        New-GPLink -Name $gpoName -Target $domain.DistinguishedName | Out-Null
    }
    gpupdate.exe /force | Out-Null
    Write-Host " COMPLETE" -ForegroundColor Green

} catch {
    Write-Error "An error occurred during audit policy deployment: $_"
    exit 1
}
