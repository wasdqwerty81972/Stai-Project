[CmdletBinding()]
param(
    [string]$Python = (Get-Command python.exe -ErrorAction Stop).Source
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

$serviceName = 'STAIProtection'
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    & $Python -m cyber_os.protection.windows_service install
    if ($LASTEXITCODE -ne 0) {
        throw "Installing $serviceName failed with exit code $LASTEXITCODE."
    }
} else {
    & $Python -m cyber_os.protection.windows_service update
    if ($LASTEXITCODE -ne 0) {
        throw "Updating $serviceName failed with exit code $LASTEXITCODE."
    }
}

& sc.exe config $serviceName start= auto | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Configuring $serviceName for automatic startup failed with exit code $LASTEXITCODE."
}

Start-Service -Name $serviceName
$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if ($service.StartMode -ne 'Auto') {
    throw "$serviceName is installed, but its start mode is '$($service.StartMode)' instead of 'Auto'."
}

Write-Host "$serviceName is installed and configured for automatic startup."
Write-Host "Stop:   Stop-Service -Name $serviceName"
Write-Host "Remove: & `"$Python`" -m cyber_os.protection.windows_service remove"
