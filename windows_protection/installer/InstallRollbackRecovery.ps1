$ErrorActionPreference = "Stop"
$taskName = "STAI Protection Install Rollback Recovery"
$dataRoot = Join-Path $env:ProgramData "STAI\Protection"
$markerPath = Join-Path $dataRoot ".stai-install-in-progress"
$driverName = "StaiProtection"
$serviceName = "STAIProtection"
$sc = Join-Path $env:windir "System32\sc.exe"
$fltmc = Join-Path $env:windir "System32\fltmc.exe"

function Remove-RecoveryTask {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Test-ServiceRegistration([string] $Name) {
    & $sc query $Name *> $null
    return $LASTEXITCODE -eq 0
}

function Remove-ServiceRegistration([string] $Name) {
    if (-not (Test-ServiceRegistration $Name)) { return }
    & $sc delete $Name *> $null
    if ($LASTEXITCODE -ne 0 -and (Test-ServiceRegistration $Name)) {
        throw "Windows could not remove the '$Name' service registration."
    }
    if (Test-ServiceRegistration $Name) {
        throw "The '$Name' service registration is still pending removal."
    }
}

if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
    Remove-RecoveryTask
    exit 0
}
$markerState = (Get-Content -LiteralPath $markerPath -Raw).Trim()
if ($markerState -eq "committed") {
    Remove-Item -LiteralPath $markerPath -Force
    Remove-RecoveryTask
    exit 0
}
if ($markerState -ne "installing") {
    throw "The install recovery marker has an unknown state; automatic service and driver cleanup was refused."
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne "Stopped") {
    & $sc stop $serviceName *> $null
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        Start-Sleep -Milliseconds 250
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    } while ($service -and $service.Status -ne "Stopped" -and [DateTime]::UtcNow -lt $deadline)
}
if ($service -and $service.Status -ne "Stopped") {
    foreach ($name in @($serviceName, $driverName)) {
        if (Test-ServiceRegistration $name) {
            & $sc config $name start= disabled *> $null
            if ($LASTEXITCODE -ne 0) { throw "The '$name' service could not be disabled for the next boot." }
        }
    }
    throw "The protection service is still running. Automatic starts were disabled; recovery will retry on the next boot."
}

& $fltmc unload $driverName *> $null
$filters = & $fltmc filters 2>&1
if ($LASTEXITCODE -ne 0) { throw "Could not query Filter Manager before rollback recovery." }
if ($filters -match "(?im)^\s*$([regex]::Escape($driverName))\s") {
    & $sc config $driverName start= disabled *> $null
    if ($LASTEXITCODE -ne 0) { throw "The loaded minifilter could not be disabled for the next boot." }
    if (Test-ServiceRegistration $serviceName) {
        & $sc config $serviceName start= disabled *> $null
        if ($LASTEXITCODE -ne 0) { throw "The protection service could not be disabled for the next boot." }
    }
    throw "The filter is still loaded. Automatic start was disabled; recovery will retry on the next boot."
}

Remove-ServiceRegistration $serviceName
Remove-ServiceRegistration $driverName
$driverImage = Join-Path $env:windir "System32\drivers\StaiProtection.sys"
if (Test-Path -LiteralPath $driverImage -PathType Leaf) {
    Remove-Item -LiteralPath $driverImage -Force
    if (Test-Path -LiteralPath $driverImage -PathType Leaf) { throw "The unloaded driver image could not be removed." }
}

Remove-Item -LiteralPath $markerPath -Force
Remove-RecoveryTask
