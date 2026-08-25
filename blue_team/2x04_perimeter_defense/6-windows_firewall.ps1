# 6-windows_firewall.ps1

$SegmentationFile = Join-Path $PSScriptRoot "segmentation_rules.json"
$OutputFile = Join-Path $PSScriptRoot "windows_firewall_rules.json"

Write-Host "[*] Reading segmentation_rules.json..."

if (-not (Test-Path $SegmentationFile)) {
    Write-Host "segmentation_rules.json not found"
    exit 1
}

$Data = Get-Content $SegmentationFile -Raw | ConvertFrom-Json

# -------------------------------------------------
# Set firewall profile defaults
# -------------------------------------------------

Write-Host "[*] Setting profile defaults..."

$Profiles = @("Domain", "Private", "Public")

foreach ($Profile in $Profiles) {
    Set-NetFirewallProfile -Name $Profile `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogBlocked True `
        -LogFileName "%systemroot%\system32\LogFiles\Firewall\meddefense.log"

    $PName = "$Profile" + ":"
    Write-Host ("  {0,-8} DefaultInboundAction=Block  LogBlocked=True   [SET]" -f $PName)
}

# -------------------------------------------------
# Remove old MedDefense rules
# -------------------------------------------------

Write-Host "[*] Clearing previous MedDefense-* rules..."

$OldRules = Get-NetFirewallRule -DisplayName "MedDefense-*" -ErrorAction SilentlyContinue
$RemovedCount = 0

if ($OldRules) {
    $RemovedCount = @($OldRules).Count
    $OldRules | Remove-NetFirewallRule
}

Write-Host ("  [{0} removed]" -f $RemovedCount)

# -------------------------------------------------
# Find zone CIDRs
# -------------------------------------------------

$ZoneCIDRs = @{}
foreach ($Zone in $Data.zones) {
    $ZoneCIDRs[$Zone.name] = $Zone.cidr
}

# -------------------------------------------------
# Create inbound firewall rules
# -------------------------------------------------

Write-Host "[*] Creating rules from flow matrix..."

$CreatedRules = @()

foreach ($Flow in $Data.flows) {
    if ($Flow.action -eq "allow") {
        $SrcZone = $Flow.src_zone
        $Protocol = $Flow.proto.ToLower()
        $Port = $Flow.dport
        
        $RemoteAddress = $ZoneCIDRs[$SrcZone]
        if (-not $RemoteAddress -and $SrcZone -eq "ALL") {
            $RemoteAddress = "Any"
        }
        
        if (-not $RemoteAddress) { continue }

        $DisplayName = "MedDefense-$SrcZone-$($Flow.proto.ToUpper())-$Port"

        New-NetFirewallRule `
            -DisplayName $DisplayName `
            -Direction Inbound `
            -Action Allow `
            -Protocol $Protocol `
            -LocalPort $Port `
            -RemoteAddress $RemoteAddress `
            -Profile Any | Out-Null

        Write-Host ("  {0,-28} Inbound Allow {1,-3} {2,-5} [CREATED]" -f $DisplayName, $Protocol, $Port)

        $CreatedRules += [PSCustomObject]@{
            DisplayName   = $DisplayName
            Direction     = "Inbound"
            Action        = "Allow"
            Protocol      = $Protocol
            LocalPort     = $Port
            RemoteAddress = $RemoteAddress
            Profile       = "Any"
            SourceZone    = $SrcZone
        }
    }
}

# -------------------------------------------------
# Export rules as JSON
# -------------------------------------------------

$Result = [PSCustomObject]@{
    generated_at = (Get-Date).ToString("o")
    hostname     = $env:COMPUTERNAME
    rules        = $CreatedRules
    summary      = [PSCustomObject]@{
        rule_count = $CreatedRules.Count
    }
}

$Result | ConvertTo-Json -Depth 5 | Set-Content $OutputFile
