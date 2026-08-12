<#
name: 9-windows_attack_sim.ps1
purpose: Execute controlled Windows attacker simulation and produce ground truth log.
author: Nargiz Naghiyeva
#>

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TargetUser      = 'support_update'
$TargetPassword  = ConvertTo-SecureString 'Sim-P@ss!2026xYz' -AsPlainText -Force
$TaskName        = 'SupportUpdateTask'
$StartupDir      = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
$StartupFile     = Join-Path $StartupDir 'support_update.bat'
$SafeIP          = '1.1.1.1'
$SafePort        = 443

$ScriptDir       = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$GroundTruthPath = Join-Path $ScriptDir 'windows_attack_log.json'

$GroundTruth = [System.Collections.Generic.List[object]]::new()

function Record-Action {
    param(
        [int]$Number,
        [string]$Description,
        [string]$Timestamp,
        [string]$DetectionSource,
        [string]$MitreTechnique,
        [string]$MitreId
    )
    $GroundTruth.Add([ordered]@{
        action_number      = $Number
        description        = $Description
        timestamp          = $Timestamp
        expected_detection = $DetectionSource
        mitre_technique    = $MitreTechnique
        mitre_id           = $MitreId
    })
}

Write-Host "[*] Running Windows attacker simulation..."

try {
    # 1. Create local user
    $ts1 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host ("    [1/6] Creating local user '$TargetUser'...      {0}" -f $ts1)
    New-LocalUser -Name $TargetUser -Password $TargetPassword -FullName 'Support Update' -Description 'Simulation account' -AccountNeverExpires | Out-Null
    Record-Action -Number 1 -Description "Created local user '$TargetUser'" -Timestamp $ts1 `
        -DetectionSource "Security 4720; Sysmon 1" -MitreTechnique "Create Account: Local Account" -MitreId "T1136.001"

    Start-Sleep -Seconds 1

    # 2. Add to Administrators
    $ts2 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host ("    [2/6] Adding to Administrators group...            {0}" -f $ts2)
    Add-LocalGroupMember -Group 'Administrators' -Member $TargetUser
    Record-Action -Number 2 -Description "Added '$TargetUser' to Administrators group" -Timestamp $ts2 `
        -DetectionSource "Security 4732; Sysmon 1" -MitreTechnique "Account Manipulation" -MitreId "T1098"

    Start-Sleep -Seconds 1

    # 3. Encoded PowerShell
    $ts3 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host ("    [3/6] Running encoded PowerShell...                {0}" -f $ts3)
    $payload = 'Write-Host "C2 beacon"'
    $bytes   = [System.Text.Encoding]::Unicode.GetBytes($payload)
    $encoded = [Convert]::ToBase64String($bytes)
    Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -enc $encoded" -WindowStyle Hidden -Wait
    Record-Action -Number 3 -Description "Ran encoded PowerShell" -Timestamp $ts3 `
        -DetectionSource "Sysmon 1; PowerShell 4104; Security 4688" -MitreTechnique "Command and Scripting Interpreter: PowerShell" -MitreId "T1059.001"

    Start-Sleep -Seconds 1

    # 4. Scheduled Task
    $ts4 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host ("    [4/6] Creating scheduled task...                   {0}" -f $ts4)
    schtasks /create /tn $TaskName /tr "powershell.exe -NoProfile -Command `"Write-Host persistence`"" /sc onlogon /rl highest /f | Out-Null
    Record-Action -Number 4 -Description "Created scheduled task '$TaskName'" -Timestamp $ts4 `
        -DetectionSource "Security 4698; Sysmon 1" -MitreTechnique "Scheduled Task/Job: Scheduled Task" -MitreId "T1053.005"

    Start-Sleep -Seconds 1

    # 5. Outbound Connection
    $ts5 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host ("    [5/6] Outbound network connection...               {0}" -f $ts5)
    Test-NetConnection -ComputerName $SafeIP -Port $SafePort -InformationLevel Quiet | Out-Null
    Record-Action -Number 5 -Description "Initiated outbound connection to $SafeIP:$SafePort" -Timestamp $ts5 `
        -DetectionSource "Sysmon 3" -MitreTechnique "Application Layer Protocol" -MitreId "T1071"

    Start-Sleep -Seconds 1

    # 6. Drop Startup file
    $ts6 = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Write-Host ("    [6/6] Dropping file in Startup...                  {0}" -f $ts6)
    "@echo off`r`necho simulation-artifact" | Out-File -FilePath $StartupFile -Encoding ASCII
    Record-Action -Number 6 -Description "Dropped file in Startup folder" -Timestamp $ts6 `
        -DetectionSource "Sysmon 11; Security 4663" -MitreTechnique "Boot or Logon Autostart Execution: Startup Folder" -MitreId "T1547.001"

}
finally {
    if ($GroundTruth.Count -gt 0) {
        $GroundTruth | ConvertTo-Json -Depth 4 | Out-File -FilePath $GroundTruthPath -Encoding UTF8
    }

    Write-Host "[*] Cleaning up artifacts..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    schtasks /delete /tn $TaskName /f 2>$null | Out-Null
    if (Test-Path $StartupFile) { Remove-Item $StartupFile -Force }
    if (Get-LocalUser -Name $TargetUser -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $TargetUser
    }
    Write-Host "    User removed, task deleted, file removed           [CLEAN]"
}

Write-Host "Actions executed: $($GroundTruth.Count)"
Write-Host "Ground truth saved to: windows_attack_log.json"

