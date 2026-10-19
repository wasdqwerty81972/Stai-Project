[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ParameterSetName = "Update")]
    [string] $StagedPackagePath,
    [Parameter(ParameterSetName = "Update")]
    [string] $InstallRoot = (Join-Path $env:ProgramFiles "STAI\Protection"),
    [Parameter(ParameterSetName = "Update")]
    [switch] $AllowTestPackage,
    [Parameter(Mandatory = $true, ParameterSetName = "Recover")]
    [switch] $Recover,
    [Parameter(ParameterSetName = "Recover")]
    [string] $RecoveryInstallRoot = (Join-Path $env:ProgramFiles "STAI\Protection")
)

$ErrorActionPreference = "Stop"
$serviceName = "STAIProtection"
$driverName = "StaiProtectionFilter"
$legacyDriverName = "StaiProtection"
$dataRoot = Join-Path $env:ProgramData "STAI\Protection"
$updateRoot = Join-Path $dataRoot "updates"
$journalPath = Join-Path $updateRoot "active-update.json"
$pipeName = "STAI.Protection.v1"
$maxFrameBytes = 1048576
$recoveryTaskName = "STAI Protection Update Recovery"

function Get-CertificateEkuOids([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate) {
    $ekuExtension = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
        Select-Object -First 1
    if (-not $ekuExtension) { return @() }
    return @($ekuExtension.EnhancedKeyUsages | ForEach-Object { $_.Value })
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The protection updater must run from an elevated administrator PowerShell session."
    }
}

function Quote-CommandLineArgument([string] $Value) {
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $backslashes + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * (2 * $backslashes)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Request-AdministratorElevation {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }

    $powershell = Join-Path $env:windir "System32\WindowsPowerShell\v1.0\powershell.exe"
    $childArguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', (Quote-CommandLineArgument ([IO.Path]::GetFullPath($PSCommandPath)))
    )
    if ($Recover) {
        $childArguments += @('-Recover', '-RecoveryInstallRoot', (Quote-CommandLineArgument ([IO.Path]::GetFullPath($RecoveryInstallRoot))))
    } else {
        $childArguments += @('-StagedPackagePath', (Quote-CommandLineArgument ([IO.Path]::GetFullPath($StagedPackagePath))))
        $childArguments += @('-InstallRoot', (Quote-CommandLineArgument ([IO.Path]::GetFullPath($InstallRoot))))
        if ($AllowTestPackage) { $childArguments += '-AllowTestPackage' }
    }

    try {
        $elevatedProcess = Start-Process -FilePath $powershell -Verb RunAs `
            -ArgumentList ($childArguments -join ' ') -Wait -PassThru
    } catch {
        throw "Administrator elevation was canceled or could not be started: $($_.Exception.Message)"
    }
    if (-not $elevatedProcess) {
        throw "Could not start the elevated protection updater."
    }
    exit $elevatedProcess.ExitCode
}

function Invoke-CheckedProcess([string] $FilePath, [string[]] $ArgumentList, [string] $WorkingDirectory, [int] $TimeoutSeconds = 90, [switch] $IgnoreExitCode) {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = ($ArgumentList -join " ")
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $process) { throw "Could not start $([IO.Path]::GetFileName($FilePath))." }
    try {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            throw "$([IO.Path]::GetFileName($FilePath)) exceeded its time limit."
        }
        if ($process.ExitCode -ne 0 -and -not $IgnoreExitCode) {
            throw "$([IO.Path]::GetFileName($FilePath)) returned exit code $($process.ExitCode)."
        }
        return $process.ExitCode
    } finally { $process.Dispose() }
}

function Invoke-InfInstall([string] $DriverDirectory) {
    $infPath = Join-Path $DriverDirectory "StaiProtection.inf"
    if (-not (Test-Path -LiteralPath $infPath -PathType Leaf)) { throw "The staged minifilter INF is missing." }
    # pnputil installs the package as a primitive driver (DiInstallDriver) and returns
    # a real exit code. The legacy "rundll32 setupapi.dll,InstallHinfSection
    # DefaultInstall 132" path is the mechanism Microsoft recommends replacing, and
    # rundll32 always exits 0, so INF install failures were silently ignored here.
    Invoke-CheckedProcess (Join-Path $env:windir "System32\pnputil.exe") @("/add-driver", ('"' + $infPath + '"'), "/install") $DriverDirectory | Out-Null
}

function Ensure-FilterLoaded {
    $fltmc = Join-Path $env:windir "System32\fltmc.exe"
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $fltmc
    $startInfo.Arguments = "filters"
    $startInfo.WorkingDirectory = $env:windir
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $process = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $process) { throw "Could not query the Windows minifilter state." }
    try {
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw "Minifilter state query timed out." }
        $filterList = $process.StandardOutput.ReadToEnd()
        if ($process.ExitCode -eq 0 -and $filterList -match "(?im)^\s*$([regex]::Escape($driverName))\s") { return }
    } finally { $process.Dispose() }
    Invoke-CheckedProcess $fltmc @("load", $driverName) $env:windir | Out-Null
}

function Ensure-FilterUnloaded {
    $fltmc = Join-Path $env:windir "System32\fltmc.exe"
    $filterNames = @($driverName, $legacyDriverName) | Select-Object -Unique
    foreach ($filterName in $filterNames) {
        Invoke-CheckedProcess $fltmc @("unload", $filterName) $env:windir -IgnoreExitCode | Out-Null
    }
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $fltmc
    $startInfo.Arguments = "filters"
    $startInfo.WorkingDirectory = $env:windir
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $process = [System.Diagnostics.Process]::Start($startInfo)
    if (-not $process) { throw "Could not verify minifilter unload state." }
    try {
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw "Minifilter unload verification timed out." }
        $filterList = $process.StandardOutput.ReadToEnd()
        foreach ($filterName in $filterNames) {
            if ($filterList -match "(?im)^\s*$([regex]::Escape($filterName))\s") {
                throw "The STAI minifilter '$filterName' is still loaded; update stopped before replacing driver files."
            }
        }
    } finally { $process.Dispose() }
}

function Wait-Service([string] $Name, [string] $DesiredStatus, [int] $Seconds = 30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status.ToString() -eq $DesiredStatus) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Windows service '$Name' did not reach $DesiredStatus state."
}

function Read-PipeExactly([System.IO.Stream] $Stream, [int] $Length) {
    $bytes = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($bytes, $offset, $Length - $offset)
        if ($read -le 0) { throw "The local protection service closed its pipe early." }
        $offset += $read
    }
    return ,$bytes
}

function Get-ProtectionStatus {
    $request = @{
        version = 1
        request_id = [Guid]::NewGuid().ToString("N")
        operation = "get_status"
        payload = @{}
    } | ConvertTo-Json -Compress -Depth 4
    $body = [Text.Encoding]::UTF8.GetBytes($request)
    if ($body.Length -eq 0 -or $body.Length -gt $maxFrameBytes) { throw "The local status request exceeded its frame limit." }

    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(".", $pipeName, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None)
    try {
        $pipe.Connect(1500)
        $pipe.ReadTimeout = 3000
        $pipe.WriteTimeout = 3000
        $header = [BitConverter]::GetBytes([UInt32]$body.Length)
        $pipe.Write($header, 0, $header.Length)
        $pipe.Write($body, 0, $body.Length)
        $pipe.Flush()
        $responseHeader = Read-PipeExactly $pipe 4
        $responseLength = [BitConverter]::ToUInt32($responseHeader, 0)
        if ($responseLength -eq 0 -or $responseLength -gt $maxFrameBytes) { throw "The service response exceeded its frame limit." }
        $responseBody = Read-PipeExactly $pipe ([int]$responseLength)
        return ([Text.Encoding]::UTF8.GetString($responseBody) | ConvertFrom-Json)
    } finally { $pipe.Dispose() }
}

function Wait-ProtectionHealthy([int] $Seconds = 45) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $response = Get-ProtectionStatus
            $status = $response.data
            if ($response.ok -and $status.state -eq "active" -and $status.service_state -eq "running" -and
                $status.driver_state -eq "running" -and $status.rules_version -and $status.rules_version -ne "unknown") {
                return
            }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    throw "STAI did not report active service, driver, and signed-rule health."
}

function Write-UpdateJournal([hashtable] $Journal) {
    $temporary = $journalPath + ".tmp"
    $json = $Journal | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($temporary, $json, [Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $journalPath) {
        [IO.File]::Replace($temporary, $journalPath, $null)
    } else {
        [IO.File]::Move($temporary, $journalPath)
    }
}

function Register-UpdateRecoveryTask([string] $ProtectionRoot) {
    $expectedUpdater = [IO.Path]::GetFullPath((Join-Path $ProtectionRoot "update.ps1"))
    $runningUpdater = [IO.Path]::GetFullPath($PSCommandPath)
    if (-not [string]::Equals($runningUpdater, $expectedUpdater, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Updates must run from the protected installed updater so boot recovery can use that same trusted copy."
    }

    $powershell = Join-Path $env:windir "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $expectedUpdater +
        '" -Recover -RecoveryInstallRoot "' + [IO.Path]::GetFullPath($ProtectionRoot) + '"'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $recoveryTaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
}

function Unregister-UpdateRecoveryTask {
    Unregister-ScheduledTask -TaskName $recoveryTaskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Copy-Payload([string] $SourceRoot, [string] $DestinationRoot) {
    New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null
    foreach ($relative in @("STAIProtectionService.exe", "package-metadata.json")) {
        $source = Join-Path $SourceRoot $relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Package file is missing: $relative" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $DestinationRoot $relative) -Force
    }
    foreach ($subdir in @("driver", "rules")) {
        $sourceDir = Join-Path $SourceRoot $subdir
        if (-not (Test-Path -LiteralPath $sourceDir -PathType Container)) { throw "Package directory is missing: $subdir" }
        $targetDir = Join-Path $DestinationRoot $subdir
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        Get-ChildItem -LiteralPath $sourceDir -File | Copy-Item -Destination $targetDir -Force
    }
}

function Invoke-ServiceCommand([string] $Verb) {
    $serviceExe = Join-Path $InstallRoot "STAIProtectionService.exe"
    if (-not (Test-Path -LiteralPath $serviceExe -PathType Leaf)) { throw "The installed service executable is missing." }
    Invoke-CheckedProcess $serviceExe @($Verb) $InstallRoot | Out-Null
}

function Stop-Protection {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -ErrorAction Stop
        Wait-Service $serviceName "Stopped"
    }
    Ensure-FilterUnloaded
}

function Start-Protection {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) { throw "The STAI Windows Protection service is not registered." }
    if ($service.Status -ne "Running") {
        Start-Service -Name $serviceName -ErrorAction Stop
        Wait-Service $serviceName "Running"
    }
    $fltmc = Join-Path $env:windir "System32\fltmc.exe"
    Ensure-FilterLoaded
    Wait-ProtectionHealthy
}

function Restore-Transaction([string] $ProtectionRoot, [string] $BackupRoot, [string] $RulesBackup) {
    Write-Warning "Restoring the last known-good STAI service, driver, and rules package."
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) { throw "The STAI protection service is not registered; rollback cannot safely replace files." }
    if ($service -and $service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -ErrorAction Stop
        Wait-Service $serviceName "Stopped" 30
    }
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -ne "Stopped") {
        throw "The STAI protection service is still running; rollback will retain its journal and recovery task without replacing files."
    }
    Ensure-FilterUnloaded

    foreach ($relative in @("STAIProtectionService.exe", "package-metadata.json")) {
        $backup = Join-Path $BackupRoot $relative
        if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw "Rollback payload is missing: $relative" }
        Copy-Item -LiteralPath $backup -Destination (Join-Path $ProtectionRoot $relative) -Force
    }
    foreach ($file in @("StaiProtection.inf", "StaiProtection.sys", "StaiProtection.cat")) {
        $backup = Join-Path $BackupRoot (Join-Path "driver" $file)
        if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw "Rollback driver file is missing: $file" }
        Copy-Item -LiteralPath $backup -Destination (Join-Path $ProtectionRoot (Join-Path "driver" $file)) -Force
    }

    if (Test-Path -LiteralPath $RulesBackup -PathType Container) {
        $currentRules = Join-Path $dataRoot "rules"
        if (Test-Path -LiteralPath $currentRules) { Remove-Item -LiteralPath $currentRules -Recurse -Force }
        New-Item -ItemType Directory -Path $currentRules -Force | Out-Null
        Get-ChildItem -LiteralPath $RulesBackup -Force | Copy-Item -Destination $currentRules -Recurse -Force
    } else {
        throw "Rollback rules backup is missing."
    }
    Invoke-InfInstall (Join-Path $ProtectionRoot "driver")
    Start-Protection
}

function Recover-InterruptedUpdate([string] $ProtectionRoot) {
    if (-not (Test-Path -LiteralPath $journalPath -PathType Leaf)) {
        Unregister-UpdateRecoveryTask
        Write-Host "No interrupted STAI update was found; recovery is not required."
        return
    }
    $journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
    $ProtectionRoot = [IO.Path]::GetFullPath($ProtectionRoot)
    if (-not [string]::Equals($ProtectionRoot, [IO.Path]::GetFullPath([string]$journal.protection_root), [StringComparison]::OrdinalIgnoreCase)) {
        throw "The requested recovery install root does not match the interrupted transaction."
    }
    if ([string]$journal.transaction_id -notmatch '^[a-fA-F0-9]{32}$') {
        throw "The update journal has an invalid transaction identifier."
    }
    $backupRoot = [IO.Path]::GetFullPath([string]$journal.backup_root)
    $transactionRoot = [IO.Path]::GetFullPath((Join-Path $updateRoot ([string]$journal.transaction_id)))
    $expectedBackup = [IO.Path]::GetFullPath((Join-Path $transactionRoot "backup"))
    $expectedRulesBackup = [IO.Path]::GetFullPath((Join-Path $transactionRoot "rules"))
    if (-not [string]::Equals($backupRoot, $expectedBackup, [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals([IO.Path]::GetFullPath([string]$journal.rules_backup), $expectedRulesBackup, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The update journal points outside its private transaction directory."
    }
    Restore-Transaction $ProtectionRoot $backupRoot ([string]$journal.rules_backup)
    Remove-Item -LiteralPath $journalPath -Force
    Remove-Item -LiteralPath $transactionRoot -Recurse -Force
    Unregister-UpdateRecoveryTask
    Write-Host "Interrupted update rolled back and the previous protection health was restored."
}

if ($Recover) {
    $InstallRoot = [IO.Path]::GetFullPath($RecoveryInstallRoot)
} else {
    $InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
}
$expectedRunningUpdater = [IO.Path]::GetFullPath((Join-Path $InstallRoot "update.ps1"))
if (-not [string]::Equals([IO.Path]::GetFullPath($PSCommandPath), $expectedRunningUpdater, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Run the updater from the installed protection directory: $expectedRunningUpdater"
}

Request-AdministratorElevation
Assert-Administrator
New-Item -ItemType Directory -Path $updateRoot -Force | Out-Null
$lockPath = Join-Path $updateRoot "update.lock"
$lock = $null
try {
    $lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    if ($Recover) {
        Recover-InterruptedUpdate $RecoveryInstallRoot
        return
    }
    if (Test-Path -LiteralPath $journalPath) {
        Recover-InterruptedUpdate $InstallRoot
    }

    $StagedPackagePath = [IO.Path]::GetFullPath($StagedPackagePath)
    $currentExe = Join-Path $InstallRoot "STAIProtectionService.exe"
    $packageMetadataPath = Join-Path $StagedPackagePath "package-metadata.json"
    if (-not (Test-Path -LiteralPath $currentExe -PathType Leaf)) { throw "STAI is not installed at '$InstallRoot'." }
    if (-not (Test-Path -LiteralPath $packageMetadataPath -PathType Leaf)) { throw "The staged package metadata is missing." }
    $metadata = Get-Content -LiteralPath $packageMetadataPath -Raw | ConvertFrom-Json
    if ($metadata.test_signature -eq $true -and -not $AllowTestPackage) {
        throw "Test-channel updates require the explicit -AllowTestPackage switch and a test-signing VM."
    }
    if ($metadata.production_ready -ne $true -and -not $AllowTestPackage) {
        throw "The staged package is not production-ready; refusing to apply it as a production update."
    }
    if ($metadata.production_ready -eq $true) {
        $currentSignature = Get-AuthenticodeSignature -LiteralPath $currentExe
        $serviceSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $StagedPackagePath "STAIProtectionService.exe")
        if ($currentSignature.Status -ne "Valid" -or -not $currentSignature.SignerCertificate -or
            $serviceSignature.Status -ne "Valid" -or -not $serviceSignature.SignerCertificate) {
            throw "Production update requires valid Authenticode signatures on both current and staged service executables."
        }
        $currentEkus = Get-CertificateEkuOids $currentSignature.SignerCertificate
        $serviceEkus = Get-CertificateEkuOids $serviceSignature.SignerCertificate
        $metadataThumbprint = ([string]$metadata.publisher_thumbprint -replace '\s', '').ToUpperInvariant()
        if ("1.3.6.1.5.5.7.3.3" -notin $currentEkus -or "1.3.6.1.5.5.7.3.3" -notin $serviceEkus -or
            -not [string]::Equals($currentSignature.SignerCertificate.Thumbprint, $metadataThumbprint, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($serviceSignature.SignerCertificate.Thumbprint, $metadataThumbprint, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Production update service signatures must use the installed, code-signing-enabled publisher certificate."
        }
        $catalogSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $StagedPackagePath "driver\StaiProtection.cat")
        if ($catalogSignature.Status -ne "Valid" -or -not $catalogSignature.SignerCertificate) {
            throw "A production update requires a valid Authenticode signature on the minifilter catalog."
        }
        $driverEkus = Get-CertificateEkuOids $catalogSignature.SignerCertificate
        if (@($driverEkus | Where-Object { $_ -in @("1.3.6.1.4.1.311.10.3.5", "1.3.6.1.4.1.311.10.3.5.1") }).Count -eq 0) {
            throw "A production update requires the Microsoft hardware-driver signing EKU on its catalog."
        }
        $currentMetadataPath = Join-Path $InstallRoot "package-metadata.json"
        $currentMetadata = Get-Content -LiteralPath $currentMetadataPath -Raw | ConvertFrom-Json
        $expectedDriverThumbprint = ([string]$currentMetadata.driver_signer_thumbprint -replace '\s', '').ToUpperInvariant()
        $stagedDriverThumbprint = ([string]$metadata.driver_signer_thumbprint -replace '\s', '').ToUpperInvariant()
        $actualDriverThumbprint = ($catalogSignature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
        if (-not $expectedDriverThumbprint -or
            $expectedDriverThumbprint -ne $stagedDriverThumbprint -or
            $expectedDriverThumbprint -ne $actualDriverThumbprint) {
            throw "Production updates must use the Microsoft hardware signer pinned by the currently installed package."
        }
        if ($metadata.test_signature -eq $true) { throw "Production metadata cannot mark the driver package as test-signed." }
    }

    foreach ($file in @("STAIProtectionService.exe", "driver\StaiProtection.inf", "driver\StaiProtection.sys", "driver\StaiProtection.cat", "rules\manifest.json", "rules\manifest.sig")) {
        if (-not (Test-Path -LiteralPath (Join-Path $StagedPackagePath $file) -PathType Leaf)) { throw "Staged update file is missing: $file" }
    }
    $rulesManifest = Join-Path $StagedPackagePath "rules\manifest.json"
    $rulesSignature = Join-Path $StagedPackagePath "rules\manifest.sig"
    $verify = & $currentExe --stai-verify-rules $rulesManifest $rulesSignature 2>&1
    if ($LASTEXITCODE -ne 0) { throw "The installed trust key rejected the staged signed rules package." }
    $verify = & (Join-Path $StagedPackagePath "STAIProtectionService.exe") --stai-verify-rules $rulesManifest $rulesSignature 2>&1
    if ($LASTEXITCODE -ne 0) { throw "The updated service trust key rejected the staged signed rules package." }

    $transactionId = [Guid]::NewGuid().ToString("N")
    $backupRoot = Join-Path $updateRoot (Join-Path $transactionId "backup")
    $backupDriver = Join-Path $backupRoot "driver"
    $rulesBackup = Join-Path $updateRoot (Join-Path $transactionId "rules")
    $stagedTransaction = Join-Path $updateRoot (Join-Path $transactionId "stage")
    New-Item -ItemType Directory -Path $backupDriver, $rulesBackup, $stagedTransaction -Force | Out-Null
    Copy-Item -LiteralPath $currentExe -Destination $backupRoot -Force
    Copy-Item -LiteralPath (Join-Path $InstallRoot "package-metadata.json") -Destination $backupRoot -Force
    foreach ($file in @("StaiProtection.inf", "StaiProtection.sys", "StaiProtection.cat")) {
        Copy-Item -LiteralPath (Join-Path $InstallRoot (Join-Path "driver" $file)) -Destination $backupDriver -Force
    }
    $currentRules = Join-Path $dataRoot "rules"
    if (-not (Test-Path -LiteralPath $currentRules -PathType Container)) { throw "The installed signed rules directory is missing." }
    Get-ChildItem -LiteralPath $currentRules -File | Copy-Item -Destination $rulesBackup -Force
    Copy-Payload $StagedPackagePath $stagedTransaction
    $journal = @{
        transaction_id = $transactionId
        phase = "prepared"
        protection_root = $InstallRoot
        backup_root = $backupRoot
        rules_backup = $rulesBackup
        created_utc = [DateTime]::UtcNow.ToString("o")
        version = [string]$metadata.version
    }
    Write-UpdateJournal $journal

    $stopAttempted = $false
    $replacementStarted = $false
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -ne "Running") { throw "The existing STAI service is not running; update requires a healthy baseline." }
        Wait-ProtectionHealthy 10
        Register-UpdateRecoveryTask $InstallRoot
        $stopAttempted = $true
        Stop-Protection
        $journal.phase = "service-and-filter-stopped"; Write-UpdateJournal $journal

        $replacementStarted = $true
        Copy-Item -LiteralPath (Join-Path $stagedTransaction "STAIProtectionService.exe") -Destination $InstallRoot -Force
        Copy-Item -LiteralPath (Join-Path $stagedTransaction "package-metadata.json") -Destination $InstallRoot -Force
        $currentDriver = Join-Path $InstallRoot "driver"
        foreach ($file in @("StaiProtection.inf", "StaiProtection.sys", "StaiProtection.cat")) {
            Copy-Item -LiteralPath (Join-Path $stagedTransaction (Join-Path "driver" $file)) -Destination $currentDriver -Force
        }
        $journal.phase = "binaries-staged"; Write-UpdateJournal $journal

        $currentRulesOld = Join-Path $updateRoot (Join-Path $transactionId "rules-old")
        Move-Item -LiteralPath $currentRules -Destination $currentRulesOld
        Move-Item -LiteralPath (Join-Path $stagedTransaction "rules") -Destination $currentRules
        $journal.rules_live_old = $currentRulesOld
        $journal.phase = "rules-swapped"; Write-UpdateJournal $journal

        Invoke-InfInstall $currentDriver
        $journal.phase = "driver-installed"; Write-UpdateJournal $journal
        Start-Service -Name $serviceName -ErrorAction Stop
        Wait-Service $serviceName "Running"
        Ensure-FilterLoaded
        Wait-ProtectionHealthy
        $journal.phase = "healthy"; Write-UpdateJournal $journal

        Remove-Item -LiteralPath $journalPath -Force
        Remove-Item -LiteralPath (Join-Path $updateRoot $transactionId) -Recurse -Force
        Unregister-UpdateRecoveryTask
        Write-Host "STAI Windows Protection updated to version $($metadata.version); health handshake passed."
    } catch {
        $failure = $_
        if (-not $replacementStarted) {
            if ($stopAttempted) {
                try {
                    Start-Protection
                } catch {
                    throw "Update failed before replacing files ($($failure.Exception.Message)); the previous service/filter could not be reactivated ($($_.Exception.Message)). The journal and startup recovery task were retained."
                }
            }
            Remove-Item -LiteralPath $journalPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $updateRoot $transactionId) -Recurse -Force -ErrorAction SilentlyContinue
            Unregister-UpdateRecoveryTask
        } else {
            Restore-Transaction $InstallRoot $backupRoot $rulesBackup
            Remove-Item -LiteralPath $journalPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $updateRoot $transactionId) -Recurse -Force -ErrorAction SilentlyContinue
            Unregister-UpdateRecoveryTask
        }
        throw $failure
    }
} finally {
    if ($lock) { $lock.Dispose() }
}
