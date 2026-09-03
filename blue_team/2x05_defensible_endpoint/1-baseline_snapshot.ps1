#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline Audit Snapshot for Windows (hawthorne-adm-01).
    Runs win_audit.ps1 CIS Level 1 checks and persists metrics to JSON.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$AuditScriptPath = "/home/analyst/MedDefense_Lab/capstone/win_audit.ps1",

    [Parameter()]
    [string]$BaselineDir = "capstone/baseline"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LogPath = Join-Path -Path $BaselineDir -ChildPath "windows_baseline.log"
$JsonPath = Join-Path -Path $BaselineDir -ChildPath "baseline_windows.json"

if (-not (Test-Path -Path $BaselineDir)) {
    $null = New-Item -Path $BaselineDir -ItemType Directory -Force
}

if (-not (Test-Path -Path $AuditScriptPath)) {
    Write-Warning "Audit helper script not found at $AuditScriptPath"
    exit 2
}

Write-Verbose "Executing Windows CIS audit helper: $AuditScriptPath"

# Run audit helper and record raw log
$auditOutput = & $AuditScriptPath
$auditOutput | Out-File -FilePath $LogPath -Encoding utf8 -Force

# Parse results
$passCount = @($auditOutput | Where-Object { $_ -match '\bPASS\b' }).Count
$failCount = @($auditOutput | Where-Object { $_ -match '\bFAIL\b' }).Count
$naCount   = @($auditOutput | Where-Object { $_ -match '\bNOT_APPLICABLE\b' }).Count
$total     = $passCount + $failCount + $naCount

$passRate = 0.0
if ($total -gt 0) {
    $passRate = [math]::Round(($passCount / $total) * 100, 2)
}

$record = [ordered]@{
    timestamp         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    hostname          = $env:COMPUTERNAME
    controls_total    = $total
    pass_count        = $passCount
    fail_count        = $failCount
    na_count          = $naCount
    pass_rate_percent = $passRate
    log_path          = $LogPath
}

$json = ($record | ConvertTo-Json -Depth 4) -replace "`r`n", "`n"
[System.IO.File]::WriteAllText((Resolve-Path $JsonPath -ErrorAction SilentlyContinue).Path, $json + "`n")

Write-Output "Windows baseline snapshot complete. Written to $JsonPath"
