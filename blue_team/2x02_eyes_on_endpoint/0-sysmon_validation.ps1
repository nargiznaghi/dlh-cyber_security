# name: 0-sysmon_validation.ps1
# purpose: Validate Sysmon telemetry event capture across key Event IDs
# author: Cyber Security Team

Set-StrictMode -Version Latest

Write-Host "[*] Running Sysmon telemetry validation..."

$actionsTested = 0
$actionsCaptured = 0

function Get-SysmonEvent {
    param (
        [int]$EventID,
        [datetime]$StartTime
    )
    
    Start-Sleep -Seconds 2
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = $EventID
            StartTime = $StartTime
        } -ErrorAction Stop
        return $events
    }
    catch {
        return $null
    }
}

# --- Task 1: Process Creation (Event ID 1) ---
Write-Host "    [1/5] Process creation (Event ID 1)..."
$actionsTested++
$startTime = Get-Date

cmd.exe /c whoami | Out-Null

$events = Get-SysmonEvent -EventID 1 -StartTime $startTime
$captured = $false

if ($events) {
    foreach ($evt in $events) {
        $msg = $evt.Message
        if ($msg -like "*cmd.exe*" -and $msg -like "*whoami*") {
            $captured = $true
            break
        }
    }
}

if ($captured) {
    Write-Host "          cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present   [PASS]"
    $actionsCaptured++
} else {
    Write-Host "          cmd.exe /c whoami -> Sysmon EID 1 NOT captured               [FAIL]"
}

# --- Task 2: Network Connection (Event ID 3) ---
Write-Host "    [2/5] Network connection (Event ID 3)..."
$actionsTested++
$startTime = Get-Date

$null = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -WarningAction SilentlyContinue

$events = Get-SysmonEvent -EventID 3 -StartTime $startTime
$captured = $false

if ($events) {
    foreach ($evt in $events) {
        $msg = $evt.Message
        if ($msg -like "*8.8.8.8*" -or $msg -like "*53*") {
            $captured = $true
            break
        }
    }
}

if ($captured) {
    Write-Host "          Outbound TCP -> Sysmon EID 3 captured, dest IP/port present   [PASS]"
    $actionsCaptured++
} else {
    Write-Host "          Outbound TCP -> Sysmon EID 3 NOT captured                     [FAIL]"
}

# --- Task 3: File Creation (Event ID 11) ---
Write-Host "    [3/5] File creation (Event ID 11)..."
$actionsTested++
$startTime = Get-Date
$testFilePath = "C:\Windows\Temp\test.txt"

Set-Content -Path $testFilePath -Value "Sysmon validation test" -Force

$events = Get-SysmonEvent -EventID 11 -StartTime $startTime
$captured = $false

if ($events) {
    foreach ($evt in $events) {
        $msg = $evt.Message
        if ($msg -like "*C:\Windows\Temp\test.txt*") {
            $captured = $true
            break
        }
    }
}

if ($captured) {
    Write-Host "          C:\Windows\Temp\test.txt -> Sysmon EID 11 captured            [PASS]"
    $actionsCaptured++
} else {
    Write-Host "          C:\Windows\Temp\test.txt -> Sysmon EID 11 NOT captured        [FAIL]"
}

# --- Task 4: Registry Modification (Event ID 13) ---
Write-Host "    [4/5] Registry modification (Event ID 13)..."
$actionsTested++
$startTime = Get-Date

New-ItemProperty -Path "HKCU:\Software" -Name "SysmonTest" -Value "1" -PropertyType String -Force | Out-Null

$events = Get-SysmonEvent -EventID 13 -StartTime $startTime
$captured = $false

if ($events) {
    foreach ($evt in $events) {
        $msg = $evt.Message
        if ($msg -like "*SysmonTest*") {
            $captured = $true
            break
        }
    }
}

if ($captured) {
    Write-Host "          HKCU\...\SysmonTest -> Sysmon EID 13 captured                 [PASS]"
    $actionsCaptured++
} else {
    Write-Host "          HKCU\...\SysmonTest -> Sysmon EID 13 NOT captured             [FAIL]"
}

# --- Task 5: DNS Query (Event ID 22) ---
Write-Host "    [5/5] DNS query (Event ID 22)..."
$actionsTested++
$startTime = Get-Date

$null = Resolve-DnsName -Name "example.com" -ErrorAction SilentlyContinue

$events = Get-SysmonEvent -EventID 22 -StartTime $startTime
$captured = $false

if ($events) {
    foreach ($evt in $events) {
        $msg = $evt.Message
        if ($msg -like "*example.com*") {
            $captured = $true
            break
        }
    }
}

if ($captured) {
    Write-Host "          nslookup example.com -> Sysmon EID 22 captured                [PASS]"
    $actionsCaptured++
} else {
    Write-Host "          nslookup example.com -> Sysmon EID 22 NOT captured            [FAIL]"
}

# --- Cleanup ---
Write-Host "[*] Cleanup: removing test artifacts..."
if (Test-Path -Path $testFilePath) {
    Remove-Item -Path $testFilePath -Force -ErrorAction SilentlyContinue
}
Remove-ItemProperty -Path "HKCU:\Software" -Name "SysmonTest" -Force -ErrorAction SilentlyContinue

$missed = $actionsTested - $actionsCaptured
Write-Host "Actions tested: $actionsTested | Captured: $actionsCaptured | Missed: $missed"

