<#
name: 10-windows_detection_proof.ps1
purpose: Correlate attack simulation log with Windows event logs and produce detection matrix.
author: Nargiz Naghiyeva
#>

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$InputPath  = Join-Path $ScriptDir 'windows_attack_log.json'
if (-not (Test-Path $InputPath)) {
    $alt = Join-Path $ScriptDir 'ground_truth.json'
    if (Test-Path $alt) { $InputPath = $alt }
}
$OutputPath = Join-Path $ScriptDir 'windows_detection_matrix.json'
$WindowSec  = 30

$Expectations = @(
    @{ Num=1; Label='Create user'; Sources=@(
        @{ Name='Security'; Log='Security'; Id=4720;
           KeyFields=@('TargetUserName','SubjectUserName');
           MatchField='TargetUserName'; MatchValue='support_update' } ) }

    @{ Num=2; Label='Add to Administrators'; Sources=@(
        @{ Name='Security'; Log='Security'; Id=4732;
           KeyFields=@('MemberName','TargetUserName','SubjectUserName');
           MatchField='TargetUserName'; MatchValue='Administrators' } ) }

    @{ Num=3; Label='Encoded PowerShell'; Sources=@(
        @{ Name='PS ScriptBlock'; Log='Microsoft-Windows-PowerShell/Operational'; Id=4104;
           KeyFields=@('ScriptBlockText');
           MatchField='ScriptBlockText'; MatchValue='C2 beacon' },
        @{ Name='Sysmon'; Log='Microsoft-Windows-Sysmon/Operational'; Id=1;
           KeyFields=@('CommandLine','Image','User');
           MatchField='CommandLine'; MatchValue='-enc' } ) }

    @{ Num=4; Label='Scheduled task'; Sources=@(
        @{ Name='Sysmon'; Log='Microsoft-Windows-Sysmon/Operational'; Id=1;
           KeyFields=@('CommandLine','Image');
           MatchField='CommandLine'; MatchValue='schtasks' } ) }

    @{ Num=5; Label='Outbound connection'; Sources=@(
        @{ Name='Sysmon'; Log='Microsoft-Windows-Sysmon/Operational'; Id=3;
           KeyFields=@('DestinationIp','DestinationPort','Image');
           MatchField='DestinationIp'; MatchValue='1.1.1.1' } ) }

    @{ Num=6; Label='Startup file drop'; Sources=@(
        @{ Name='Sysmon'; Log='Microsoft-Windows-Sysmon/Operational'; Id=11;
           KeyFields=@('TargetFilename','Image');
           MatchField='TargetFilename'; MatchValue='support_update.bat' } ) }
)

function Get-EventFieldMap {
    param($Event)
    $map = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) { $map[$d.Name] = [string]$d.'#text' }
        }
    } catch { }
    return $map
}

function Find-CorrelatedEvent {
    param($Source, [datetime]$Start, [datetime]$End)
    $events = @()
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $Source.Log
            Id        = $Source.Id
            StartTime = $Start
            EndTime   = $End
        } -ErrorAction Stop
    } catch {
        return $null
    }

    foreach ($ev in $events) {
        $fields = Get-EventFieldMap $ev
        $val    = $fields[$Source.MatchField]
        if ($val -and ($val -like "*$($Source.MatchValue)*")) {
            return [pscustomobject]@{ Event=$ev; Fields=$fields; Correlated=$true }
        }
    }
    if ($events.Count -gt 0) {
        $ev = $events[0]
        return [pscustomobject]@{ Event=$ev; Fields=(Get-EventFieldMap $ev); Correlated=$false }
    }
    return $null
}

function Get-DetailLevel {
    param($Fields, [string[]]$KeyFields, [bool]$Correlated)
    $present = @($KeyFields | Where-Object { $Fields[$_] -and $Fields[$_].Trim() })
    if ($present.Count -eq $KeyFields.Count -and $Correlated) { return 'Full' }
    if ($present.Count -gt 0) { return 'Partial' }
    return 'Partial'
}

if (-not (Test-Path $InputPath)) {
    throw "Ground truth file not found. Expected 'windows_attack_log.json' in $ScriptDir"
}
$GroundTruth = Get-Content $InputPath -Raw | ConvertFrom-Json
Write-Host ("[*] Loading ground truth ({0} actions)..." -f $GroundTruth.Count)
Write-Host "[*] Searching telemetry for each action..."
Write-Host ""

$matrix       = [System.Collections.Generic.List[object]]::new()
$capturedCnt  = 0
$multiSrcCnt  = 0

Write-Host ("{0,-27}{1,-15}{2,-11}{3,-10}{4}" -f 'Action','Source','Event ID','Detail','Status')
Write-Host ("{0,-27}{1,-15}{2,-11}{3,-10}{4}" -f '------','------','--------','------','------')

foreach ($action in $GroundTruth) {
    $exp = $Expectations | Where-Object { $_.Num -eq $action.action_number }
    if (-not $exp) { continue }

    $ts    = [datetime]::Parse($action.timestamp, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
    $start = $ts.AddSeconds(-$WindowSec)
    $end   = $ts.AddSeconds( $WindowSec)

    $sourceResults = [System.Collections.Generic.List[object]]::new()
    $hitCount = 0
    $firstRow = $true

    foreach ($src in $exp.Sources) {
        $found = Find-CorrelatedEvent -Source $src -Start $start -End $end

        if ($found) {
            $hitCount++
            $detail = Get-DetailLevel -Fields $found.Fields -KeyFields $src.KeyFields -Correlated $found.Correlated
            $status = '[CAPTURED]'
            $eventId = $src.Id
            $presentFields = @($src.KeyFields | Where-Object { $found.Fields[$_] })
        } else {
            $detail  = 'Missed'
            $status  = '[MISSED]'
            $eventId = $src.Id
            $presentFields = @()
        }

        $label = if ($firstRow) { $exp.Label } else { '' }
        Write-Host ("{0,-27}{1,-15}{2,-11}{3,-10}{4}" -f $label,$src.Name,$eventId,$detail,$status)
        $firstRow = $false

        $sourceResults.Add([ordered]@{
            source              = $src.Name
            log                 = $src.Log
            event_id            = $src.Id
            detail              = $detail
            status              = $status.Trim('[',']')
            key_fields_present  = $presentFields
        })
    }

    if ($hitCount -gt 0) { $capturedCnt++ }
    if ($hitCount -gt 1) { $multiSrcCnt++ }

    $matrix.Add([ordered]@{
        action_number = $action.action_number
        action        = $exp.Label
        description   = $action.description
        timestamp     = $action.timestamp
        mitre_id      = $action.mitre_id
        captured      = ($hitCount -gt 0)
        sources       = $sourceResults
    })
}

$total = $GroundTruth.Count
$pct   = if ($total) { [math]::Round(($capturedCnt / $total) * 100) } else { 0 }
Write-Host ""
Write-Host ("Actions: {0} | Captured: {1}/{0} ({2}%) | Multi-source: {3}" -f $total,$capturedCnt,$pct,$multiSrcCnt)

$report = [ordered]@{
    generated_at   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    total_actions  = $total
    captured       = $capturedCnt
    capture_rate   = "$pct%"
    multi_source   = $multiSrcCnt
    matrix         = $matrix
}
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host ("Report saved to: windows_detection_matrix.json")

$MdPath = Join-Path $ScriptDir 'windows_detection_matrix.md'
$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Windows Detection Matrix")
$md.Add("")
$md.Add("_Generated: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))_")
$md.Add("")
$md.Add("**Actions:** $total  |  **Captured:** $capturedCnt/$total ($pct%)  |  **Multi-source:** $multiSrcCnt")
$md.Add("")
$md.Add("| Action | Source | Event ID | Detail | Status | MITRE |")
$md.Add("|--------|--------|----------|--------|--------|-------|")
foreach ($row in $matrix) {
    $first = $true
    foreach ($s in $row.sources) {
        $actionCell = if ($first) { $row.action } else { '' }
        $mitreCell  = if ($first) { $row.mitre_id } else { '' }
        $md.Add("| $actionCell | $($s.source) | $($s.event_id) | $($s.detail) | $($s.status) | $mitreCell |")
        $first = $false
    }
}
$md -join "`r`n" | Out-File -FilePath $MdPath -Encoding UTF8
Write-Host ("Markdown saved to: windows_detection_matrix.md")

