<#
.SYNOPSIS
    5-telemetry_deploy.ps1 - Hawthorne capstone, Task 5 (Windows side)
.DESCRIPTION
    Verifies Sysmon and Script Block Logging, runs controlled test actions,
    verifies telemetry coverage across Sysmon, PowerShell, and Security logs
    within the last 10 minutes, and exports the last 30 minutes of events to JSON.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CapstoneRoot,

    [Parameter(Mandatory = $false)]
    [string]$SysmonConfig
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- 1. Dynamic Path Resolution ---
if ([string]::IsNullOrWhiteSpace($CapstoneRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($env:CAPSTONE_ROOT)) {
        $CapstoneRoot = $env:CAPSTONE_ROOT
    } else {
        if (Test-Path 'C:\MedDefense_Lab\capstone') {
            $CapstoneRoot = 'C:\MedDefense_Lab\capstone'
        } else {
            $CapstoneRoot = Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath '..')
        }
    }
}

$telemetryDir = Join-Path -Path $CapstoneRoot -ChildPath 'telemetry'
if (-not (Test-Path -LiteralPath $telemetryDir)) {
    New-Item -Path $telemetryDir -ItemType Directory -Force | Out-Null
}

$eventsFile = Join-Path -Path $telemetryDir -ChildPath 'windows_events.json'
$coverageFile = Join-Path -Path $telemetryDir -ChildPath 'windows_coverage.json'
$targetStateFile = Join-Path -Path $CapstoneRoot -ChildPath 'target_state.json'

$collectionErrors = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
    Write-Host "[$ts] $Message"
}

# --- 2. Admin Check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "ERROR: Script must run with Administrator privileges."
    exit 2
}

# --- 3. Target State Check ---
if (-not (Test-Path -LiteralPath $targetStateFile)) {
    Write-Log "FATAL: target state contract is missing: $targetStateFile"
    exit 2
}

# --- 4. Deployment & Registry Configuration ---
Write-Log "Verifying Sysmon service..."
$sysmonService = Get-Service -Name "Sysmon", "Sysmon64" -ErrorAction SilentlyContinue | Select-Object -First 1
$sysmonActive = $false
if ($null -ne $sysmonService -and $sysmonService.Status -eq 'Running') {
    $sysmonActive = $true
    Write-Log "INFO: Sysmon is running ($($sysmonService.Name))."
} else {
    $collectionErrors.Add("Sysmon service is not running or not installed.")
    Write-Log "WARN: Sysmon service is not active."
}

Write-Log "Configuring and verifying PowerShell Script Block Logging..."
$sblRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$sblActive = $false
try {
    if (-not (Test-Path -Path $sblRegistryPath)) {
        New-Item -Path $sblRegistryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $sblRegistryPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force | Out-Null
    $sblActive = $true
    Write-Log "INFO: Script Block Logging has been enabled in Registry."
} catch {
    $collectionErrors.Add("Failed to set Script Block Logging registry setting.")
    Write-Log "WARN: Could not enable Script Block Logging: $_"
}

# --- 5. Controlled Test Sequence ---
$runId = (Get-Date).ToString("yyMMddHHmmss")
$probeUser = "mdprobe$runId"
$probeTask = "mdprobe_task_$runId"
$probeService = "Spooler"

$actions = [System.Collections.Generic.List[PSCustomObject]]::new()

function Execute-And-Record {
    param(
        [string]$ActionName,
        [string]$Description,
        [scriptblock]$CommandBlock,
        [string]$CommandStr,
        [string]$Channel,
        [int]$ExpectedEventId
    )
    $rc = 0
    try {
        & $CommandBlock
    } catch {
        $rc = 1
        Write-Log "WARN: Action $ActionName failed: $_"
    }

    $actions.Add([PSCustomObject]@{
        action            = $ActionName
        description       = $Description
        command           = $CommandStr
        exit_code         = $rc
        expected_channel  = $Channel
        expected_event_id = $ExpectedEventId
        records_found     = 0
        first_record_time = $null
        verified          = $false
    })
}

Write-Log "Running controlled test sequence (run_id=$runId)..."

# Action 1: Create local user
Execute-And-Record -ActionName "create_user" -Description "create a local user" `
    -CommandBlock { net user $probeUser "P@ssword12345!" /add /y | Out-Null } `
    -CommandStr "net user $probeUser *** /add" `
    -Channel "Security" -ExpectedEventId 4720

# Action 2: Scheduled Task Creation & Run
Execute-And-Record -ActionName "scheduled_task" -Description "create and run a scheduled task" `
    -CommandBlock {
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo probe"
        Register-ScheduledTask -TaskName $probeTask -Action $action -User "SYSTEM" | Out-Null
        Start-ScheduledTask -TaskName $probeTask
        Start-Sleep -Seconds 2
        Unregister-ScheduledTask -TaskName $probeTask -Confirm:$false
    } `
    -CommandStr "Register-ScheduledTask $probeTask & Start-ScheduledTask" `
    -Channel "Microsoft-Windows-Sysmon/Operational" -ExpectedEventId 1

# Action 3: Start/Stop Service
Execute-And-Record -ActionName "service_action" -Description "start and stop a service" `
    -CommandBlock {
        Restart-Service -Name $probeService -Force
    } `
    -CommandStr "Restart-Service -Name $probeService" `
    -Channel "System" -ExpectedEventId 7036

# Action 4: Run PowerShell Command
Execute-And-Record -ActionName "powershell_cmd" -Description "run a short authorized PowerShell command" `
    -CommandBlock {
        powershell.exe -NoProfile -Command "Write-Output 'MedDefense-Telemetry-Probe-$runId'" | Out-Null
    } `
    -CommandStr "powershell.exe -Command Write-Output MedDefense-Probe" `
    -Channel "Microsoft-Windows-PowerShell/Operational" -ExpectedEventId 4104

# Cleanup Created User
try {
    net user $probeUser /delete | Out-Null
} catch {}

# --- 6. Verification Phase ---
Start-Sleep -Seconds 3
$verifyWindow = (Get-Date).AddMinutes(-10)

Write-Log "Verifying event log coverage (window: last 10 minutes)..."

$verifiedCount = 0
$failedCount = 0

foreach ($act in $actions) {
    $foundEvents = @()
    try {
        $filterHashtable = @{
            LogName   = $act.expected_channel
            Id        = $act.expected_event_id
            StartTime = $verifyWindow
        }
        $foundEvents = Get-WinEvent -FilterHashtable $filterHashtable -ErrorAction SilentlyContinue
    } catch {}

    $act.records_found = $foundEvents.Count
    if ($foundEvents.Count -gt 0) {
        $act.first_record_time = $foundEvents[0].TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        if ($act.exit_code -eq 0) {
            $act.verified = $true
            $verifiedCount++
            Write-Log "INFO: $($act.action) verified ($($foundEvents.Count) records found in $($act.expected_channel))."
        } else {
            $failedCount++
        }
    } else {
        $act.verified = $false
        $failedCount++
        Write-Log "WARN: $($act.action) failed verification (no events found for EventID $($act.expected_event_id))."
    }
}

# --- 7. Event Export (Last 30 Minutes) ---
Write-Log "Exporting last 30 minutes of Sysmon and PowerShell events..."
$exportWindow = (Get-Date).AddMinutes(-30)
$exportedEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

$channelsToExport = @("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational")

foreach ($chan in $channelsToExport) {
    try {
        $rawEvts = Get-WinEvent -FilterHashtable @{ LogName = $chan; StartTime = $exportWindow } -ErrorAction SilentlyContinue
        foreach ($e in $rawEvts) {
            $exportedEvents.Add([PSCustomObject]@{
                source     = $chan
                host       = $env:COMPUTERNAME
                timestamp  = $e.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                event_id   = $e.Id
                task_category = $e.TaskDisplayName
                raw        = $e.Message
            })
        }
    } catch {}
}

$eventsDoc = [PSCustomObject]@{
    schema_version      = "1.0"
    record_type         = "telemetry_export"
    platform            = "windows"
    hostname            = $env:COMPUTERNAME
    generated_at        = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    window_minutes      = 30
    sources             = $channelsToExport
    event_count         = $exportedEvents.Count
    events              = $exportedEvents
}

$eventsDoc | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $eventsFile -Encoding utf8

# --- 8. Coverage Output Generation ---
$resultStr = if ($failedCount -eq 0) { "pass" } else { "fail" }

$coverageDoc = [PSCustomObject]@{
    schema_version                = "1.0"
    record_type                   = "telemetry_coverage"
    platform                      = "windows"
    timestamp                     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    hostname                      = $env:COMPUTERNAME
    run_id                        = $runId
    collector                     = [PSCustomObject]@{
        script  = "5-telemetry_deploy.ps1"
        version = "1.0.0"
    }
    deployment                    = [PSCustomObject]@{
        sysmon_active  = $sysmonActive
        sbl_active     = $sblActive
    }
    actions                       = $actions
    actions_total                 = $actions.Count
    actions_verified              = $verifiedCount
    actions_failed                = $failedCount
    events_export_path            = "capstone/telemetry/windows_events.json"
    events_exported               = $exportedEvents.Count
    export_window_minutes         = 30
    verification_window_minutes   = 10
    coverage_path                 = "capstone/telemetry/windows_coverage.json"
    target_state_path             = "capstone/target_state.json"
    result                        = $resultStr
    collection_errors             = $collectionErrors
}

$coverageDoc | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $coverageFile -Encoding utf8

Write-Log "Coverage record written to $coverageFile"
Write-Log "Execution finished: $verifiedCount/$($actions.Count) verified."

if ($failedCount -eq 0) {
    exit 0
} else {
    exit 1
}
