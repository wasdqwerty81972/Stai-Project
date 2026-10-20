# SVS-Cyber launcher — starts the FastAPI server with the D:\ venv.
# Usage:  .\run.ps1            (from I:\STAI 2)
# Or:     powershell -ExecutionPolicy Bypass -File "I:\STAI 2\run.ps1"

$ErrorActionPreference = "Stop"

$VenvPython = "D:\STAI-venv\Scripts\python.exe"
$WorkDir    = $PSScriptRoot
$PreferredPort = 8000
$FallbackCount = 5

if (-not (Test-Path $VenvPython)) {
    Write-Error "Venv not found at $VenvPython"
    exit 1
}

$Port = $null
for ($Candidate = $PreferredPort; $Candidate -le [Math]::Min(65535, $PreferredPort + $FallbackCount); $Candidate++) {
    $Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Candidate)
    try {
        $Listener.Start()
        $Listener.Stop()
        $Port = $Candidate
        break
    } catch {
        try { $Listener.Stop() } catch {}
    }
}

if ($null -eq $Port) {
    Write-Error "No available SVS-Cyber API port from $PreferredPort through $([Math]::Min(65535, $PreferredPort + $FallbackCount))."
    exit 1
}

Write-Host "Starting SVS-Cyber API server on http://localhost:$Port"
Write-Host "  Workdir: $WorkDir"
Write-Host "  Python : $VenvPython"
Write-Host "  UI     : http://localhost:$Port/"
Write-Host ""
Write-Host "Open that URL in your browser. Ctrl+C to stop."
Write-Host ""

& $VenvPython -m uvicorn ui.api_server:app --host 127.0.0.1 --port $Port --reload
