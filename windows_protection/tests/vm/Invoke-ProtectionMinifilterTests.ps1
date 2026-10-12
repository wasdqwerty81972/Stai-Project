<#
.SYNOPSIS
    Preflight gate for the STAI minifilter VM integration suite.

.DESCRIPTION
    The Windows service host and packaging source are present, but this
    repository does not contain a WDK-built driver package, signed test rule
    package, or end-to-end VM test host. This script checks for required
    artifacts and exits as BLOCKED instead of reporting fabricated passes.
#>

[CmdletBinding()]
param(
    [string]$VmName = "STAI-AV-Test",
    [string]$DriverPackagePath,
    [string]$ServicePackagePath,
    [string]$SignedTestRulePackagePath,
    [string]$TestHostPath,
    [string]$BenignFixturePath
)

$ErrorActionPreference = "Stop"
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($DriverPackagePath)) {
    $DriverPackagePath = Join-Path $scriptDirectory "..\..\driver\x64\Debug"
}
if ([string]::IsNullOrWhiteSpace($BenignFixturePath)) {
    $BenignFixturePath = Join-Path $scriptDirectory "benign-marker.exe"
}
$missing = [System.Collections.Generic.List[string]]::new()

foreach ($name in @("StaiProtection.sys", "StaiProtection.inf", "StaiProtection.cat")) {
    $candidate = Join-Path $DriverPackagePath $name
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $missing.Add("driver package file: $candidate")
    }
}

foreach ($entry in @(
    @{ Name = "service package"; Path = $ServicePackagePath },
    @{ Name = "signed test rule package"; Path = $SignedTestRulePackagePath },
    @{ Name = "VM test host"; Path = $TestHostPath },
    @{ Name = "benign fixture"; Path = $BenignFixturePath }
)) {
    if ([string]::IsNullOrWhiteSpace($entry.Path) -or
        -not (Test-Path -LiteralPath $entry.Path -PathType Leaf)) {
        $missing.Add("$($entry.Name): $($entry.Path)")
    }
}

Write-Host "STAI minifilter VM integration suite: BLOCKED" -ForegroundColor Yellow
Write-Host "Target VM: $VmName"

if ($missing.Count -gt 0) {
    Write-Host "Required artifacts are missing:" -ForegroundColor Yellow
    foreach ($item in $missing) {
        Write-Host "  - $item"
    }
}

Write-Host "The service host exists; the driver package, signed test rules, and VM test host needed to exercise enforcement are still missing." -ForegroundColor Yellow
Write-Host "No VM actions were run and no test results are claimed." -ForegroundColor Yellow
exit 2
