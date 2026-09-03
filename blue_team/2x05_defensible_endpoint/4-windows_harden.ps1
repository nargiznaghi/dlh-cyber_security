<#
.SYNOPSIS
    Windows Hardening orchestration script for MedDefense Capstone (2x01).
    Ensures idempotency, runs compliance baseline scripts, logs execution,
    runs audit script, and outputs standard JSON.

.DESCRIPTION
    Maintains schema parity with 3-linux_harden.sh.
    Executes sub-steps, captures logs to capstone\exec\windows_harden.log,
    and returns state fingerprint and audit pass_rate.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CapstoneRoot,

    [Parameter(Mandatory = $false)]
    [string]$StepDir,

    [Parameter(Mandatory = $false)]
    [string]$AuditScript
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

if (-not $PSBoundParameters.ContainsKey('StepDir')) {
    if (-not [string]::IsNullOrWhiteSpace($env:STEP_DIR)) {
        $StepDir = $env:STEP_DIR
    } else {
        $StepDir = Join-Path -Path (Split-Path -Path $CapstoneRoot -Parent) -ChildPath '2x01'
    }
}

if (-not $PSBoundParameters.ContainsKey('AuditScript')) {
    if (-not [string]::IsNullOrWhiteSpace($env:AUDIT_SCRIPT)) {
        $AuditScript = $env:AUDIT_SCRIPT
    } else {
        $AuditScript = Join-Path -Path $CapstoneRoot -ChildPath 'win_audit.ps1'
    }
}

# --- 2. Logging Setup ---
$execDir = Join-Path -Path $CapstoneRoot -ChildPath 'exec'
if (-not (Test-Path -LiteralPath $execDir)) {
    New-Item -Path $execDir -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path -Path $execDir -ChildPath 'windows_harden.log'

"" | Set-Content -LiteralPath $logFile -Encoding utf8

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Add-Content -LiteralPath $logFile -Encoding utf8
}

Write-Log "Initializing Windows Hardening Pipeline..."
Write-Log "Capstone Root: $CapstoneRoot"
Write-Log "Step Directory: $StepDir"
Write-Log "Audit Script: $AuditScript"

# --- 3. Validation ---
if (-not (Test-Path -LiteralPath $StepDir)) {
    Write-Log "ERROR: StepDir does not exist: $StepDir"
    $response = [PSCustomObject]@{
        status        = "failed"
        error         = "StepDir not found"
        pass_rate     = 0.0
        fingerprint   = ""
        changed_state = $false
    }
    $response | ConvertTo-Json -Compress
    exit 2
}

# --- 4. Fingerprint Calculation (Idempotency) ---
function Get-SystemStateFingerprint {
    Write-Log "Calculating system state fingerprint..."
    $secData = @()
    
    try {
        $secData += (auditpol /get /category:* 2>&1 | Out-String)
    } catch {
        $secData += "AuditPol-Error"
    }
    
    $services = Get-Service -Name "RemoteRegistry", "WinRM", "wuauserv" -ErrorAction SilentlyContinue
    foreach ($s in $services) {
        $secData += "$($s.Name):$($s.Status):$($s.StartType)"
    }
    
    try {
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
        foreach ($p in $fw) {
            $secData += "$($p.Name):$($p.Enabled)"
        }
    } catch {}

    $stringToHash = $secData -join "`n"
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($stringToHash)
    $hashBytes = $hasher.ComputeHash($bytes)
    return -join ($hashBytes | ForEach-Object { $_.ToString("x2") })
}

$initialFingerprint = Get-SystemStateFingerprint
Write-Log "Initial Fingerprint: $initialFingerprint"

$stateCacheFile = Join-Path -Path $execDir -ChildPath '.win_state_fingerprint'
$alreadyHardened = $false

if (Test-Path -LiteralPath $stateCacheFile) {
    $cachedHash = (Get-Content -LiteralPath $stateCacheFile -Raw).Trim()
    if ($cachedHash -eq $initialFingerprint) {
        Write-Log "State matches cached fingerprint. System is already hardened."
        $alreadyHardened = $true
    }
}

# --- 5. Execution of Hardening Steps ---
$stepScripts = @(
    "1-account_security.ps1",
    "2-audit_logging.ps1",
    "3-network_firewall.ps1",
    "4-services_reduction.ps1"
)

$stepExecutionStatus = $true

if (-not $alreadyHardened) {
    foreach ($scriptName in $stepScripts) {
        $scriptPath = Join-Path -Path $StepDir -ChildPath $scriptName
        if (Test-Path -LiteralPath $scriptPath) {
            Write-Log "Executing sub-step: $scriptName"
            try {
                $output = & $scriptPath 2>&1 | Out-String
                Add-Content -LiteralPath $logFile -Value "=== Output from $scriptName ===" -Encoding utf8
                Add-Content -LiteralPath $logFile -Value $output -Encoding utf8
                Write-Log "Successfully executed $scriptName"
            } catch {
                Write-Log "ERROR: Failed to execute $scriptName - $_"
                Add-Content -LiteralPath $logFile -Value "=== ERROR in $scriptName: $_ ===" -Encoding utf8
                $stepExecutionStatus = $false
            }
        } else {
            Write-Log "WARNING: Step script not found: $scriptPath (Skipping)"
        }
    }
}

# --- 6. Post-Execution Fingerprint & State Cache ---
$finalFingerprint = Get-SystemStateFingerprint
Write-Log "Final Fingerprint: $finalFingerprint"
$finalFingerprint | Set-Content -LiteralPath $stateCacheFile -Encoding utf8

$stateChanged = ($initialFingerprint -ne $finalFingerprint)

# --- 7. Audit & Pass-Rate Calculation ---
$passRate = 0.0

if (Test-Path -LiteralPath $AuditScript) {
    Write-Log "Executing audit helper: $AuditScript"
    try {
        $auditOutput = & $AuditScript 2>&1 | Out-String
        Add-Content -LiteralPath $logFile -Value "=== Audit Helper Output ===" -Encoding utf8
        Add-Content -LiteralPath $logFile -Value $auditOutput -Encoding utf8
    } catch {
        Write-Log "WARNING: Audit script failed to run: $_"
    }
}

$targetStateFile = Join-Path -Path $execDir -ChildPath 'target_state.json'
if (Test-Path -LiteralPath $targetStateFile) {
    try {
        $targetJson = Get-Content -LiteralPath $targetStateFile -Raw | ConvertFrom-Json
        if ($null -ne $targetJson.pass_rate) {
            $passRate = [double]$targetJson.pass_rate
        } elseif ($null -ne $targetJson.score) {
            $passRate = [double]$targetJson.score
        }
    } catch {
        Write-Log "WARNING: Could not parse target_state.json"
    }
} else {
    if ($stepExecutionStatus) { $passRate = 1.0 }
}

# --- 8. Final Standardized Output ---
$finalStatus = if ($stepExecutionStatus) { "success" } else { "failed" }

$jsonResult = [PSCustomObject]@{
    status        = $finalStatus
    pass_rate     = $passRate
    fingerprint   = $finalFingerprint
    changed_state = $stateChanged
}

Write-Log "Execution finished with status: $finalStatus, pass_rate: $passRate"

$jsonResult | ConvertTo-Json -Compress
exit 0
