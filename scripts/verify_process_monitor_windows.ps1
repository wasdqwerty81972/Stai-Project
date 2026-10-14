param(
    [string]$ApiOrigin = "http://127.0.0.1:6764",
    [int]$TimeoutSeconds = 35
)

$ErrorActionPreference = "Stop"
$pythonCommand = Get-Command python -ErrorAction Stop
$pythonPath = $pythonCommand.Source
$probePath = Join-Path $PSScriptRoot "process_monitor_probe.py"
$process = $null
$appearedAt = $null
$maxCpu = $null
$maxMemory = $null
$maxConnections = $null
$connectionsVerified = $false

try {
    $health = Invoke-RestMethod -Uri "$ApiOrigin/api/antivirus/process-monitor/status" -TimeoutSec 3
    Write-Host "Monitor state: $($health.state); event source: $($health.event_source)"
    if ($health.event_source_error) {
        Write-Host "Event source detail: $($health.event_source_error)"
    }

    $startedAt = Get-Date
    $process = Start-Process -FilePath $pythonPath `
        -ArgumentList @("-u", "`"$probePath`"", "--duration", "30") `
        -PassThru -WindowStyle Hidden
    Write-Host "Started harmless probe PID $($process.Id)."

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
        $snapshot = Invoke-RestMethod -Uri "$ApiOrigin/api/antivirus/processes" -TimeoutSec 3
        $row = $snapshot.processes | Where-Object { $_.pid -eq $process.Id } | Select-Object -First 1
        if ($row) {
            if (-not $appearedAt) { $appearedAt = Get-Date }
            if ($null -ne $row.cpu_percent) { $maxCpu = [Math]::Max(($maxCpu ?? 0), [double]$row.cpu_percent) }
            if ($null -ne $row.memory_bytes) { $maxMemory = [Math]::Max(($maxMemory ?? 0), [double]$row.memory_bytes) }
            if ($null -ne $row.network_connection_count) { $maxConnections = [Math]::Max(($maxConnections ?? 0), [int]$row.network_connection_count) }
            if ($row.network_connection_count -gt 0 -and -not $connectionsVerified) {
                $detail = Invoke-RestMethod -Uri "$ApiOrigin/api/antivirus/processes/$([Uri]::EscapeDataString($row.instance_id))/connections" -TimeoutSec 3
                Write-Host "Observed $($detail.connections.Count) verified process-owned connection(s)."
                $connectionsVerified = $detail.connections.Count -gt 0
            }
            if ($row.cpu_percent -ne $null -and $row.memory_bytes -ge 20MB -and ((Get-Date) - $startedAt).TotalSeconds -ge 7) { break }
        }
        Start-Sleep -Milliseconds 350
    }

    if (-not $appearedAt) { throw "Probe process did not appear in the live process snapshot." }
    $latencyMs = [Math]::Round(($appearedAt - $startedAt).TotalMilliseconds)
    Write-Host "Appearance latency: ${latencyMs}ms; observed CPU: $maxCpu%; working set: $maxMemory bytes; owned connections: $maxConnections"
    if ($null -eq $maxMemory -or $maxMemory -lt 20MB) { throw "The probe's measured working set did not reach the expected bounded allocation." }

    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    $process.WaitForExit()
    $exitDeadline = (Get-Date).AddSeconds(10)
    $removed = $false
    while ((Get-Date) -lt $exitDeadline) {
        $snapshot = Invoke-RestMethod -Uri "$ApiOrigin/api/antivirus/processes" -TimeoutSec 3
        if (-not ($snapshot.processes | Where-Object { $_.pid -eq $process.Id })) { $removed = $true; break }
        Start-Sleep -Milliseconds 350
    }
    if (-not $removed) { throw "Exited probe remained in the running-process snapshot past the 10 second check." }
    Write-Host "Process disappearance verified."
    $viewerCount = (Get-Process).Count
    Write-Host "Process count comparison: SVS-Cyber snapshot $($snapshot.processes.Count); PowerShell Get-Process $viewerCount (sampled moments apart)."
} finally {
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
}
