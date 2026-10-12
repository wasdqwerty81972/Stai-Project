[CmdletBinding()]
param(
    [ValidateSet("Test", "Release")]
    [string] $Configuration = "Test",
    [string] $TrustedRulesPublicKeyPath,
    [string] $SigningCertificateThumbprint,
    [string] $TimestampServer = "https://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$buildRoot = Join-Path $PSScriptRoot (Join-Path "build" $Configuration)
$venvPath = Join-Path $buildRoot "venv"
$pythonPath = Join-Path $venvPath "Scripts\python.exe"
$distPath = Join-Path $buildRoot "dist"
$workPath = Join-Path $buildRoot "work"
$specPath = Join-Path $PSScriptRoot "pyinstaller.spec"
$requirementsPath = Join-Path $repoRoot "requirements-windows-protection.txt"
$buildPythonVersion = (& python -c "import platform, sys; print(f'{sys.version_info.major}.{sys.version_info.minor};{platform.architecture()[0]}')" 2>&1 | Out-String).Trim()
if ($buildPythonVersion -ne "3.11;64bit") {
    throw "The pinned Windows protection build requires 64-bit Python 3.11; found '$buildPythonVersion'."
}

if ($Configuration -eq "Release" -and -not $TrustedRulesPublicKeyPath) {
    throw "Release configuration requires -TrustedRulesPublicKeyPath with a trusted Ed25519 public-key PEM file."
}
if ($Configuration -eq "Release" -and -not $SigningCertificateThumbprint) {
    throw "Release configuration requires a code-signing certificate thumbprint from the Windows certificate store."
}

if ($TrustedRulesPublicKeyPath) {
    $keyPath = (Resolve-Path -LiteralPath $TrustedRulesPublicKeyPath).Path
    $env:STAI_TRUSTED_RULES_PUBLIC_KEY = $keyPath
} else {
    Remove-Item Env:STAI_TRUSTED_RULES_PUBLIC_KEY -ErrorAction SilentlyContinue
    Write-Warning "No trusted rules key supplied. The built service will report protection unavailable until installed with a trusted public key and signed rules."
}

New-Item -ItemType Directory -Path $buildRoot, $distPath, $workPath -Force | Out-Null
$env:STAI_BUILD_ROOT = $buildRoot
$rawPublicKeyPath = Join-Path $buildRoot "resources\trusted-rules.pub"
if (-not $TrustedRulesPublicKeyPath) {
    Remove-Item -LiteralPath $rawPublicKeyPath -Force -ErrorAction SilentlyContinue
}
if (-not (Test-Path -LiteralPath $pythonPath)) {
    & python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) { throw "Failed to create the isolated service build environment." }
}

& $pythonPath -m pip install --disable-pip-version-check --requirement $requirementsPath
if ($LASTEXITCODE -ne 0) { throw "Failed to install pinned Windows protection build dependencies." }

& $pythonPath -m PyInstaller --noconfirm --clean --distpath $distPath --workpath $workPath $specPath
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed to build STAIProtectionService.exe." }

$serviceExe = Join-Path $distPath "STAIProtectionService.exe"
if (-not (Test-Path -LiteralPath $serviceExe)) {
    throw "PyInstaller completed without producing STAIProtectionService.exe."
}
if ($Configuration -eq "Release") {
    if ($SigningCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
        throw "Signing certificate thumbprint must contain 40 hexadecimal SHA-1 characters."
    }
    $releasePolicy = Get-Content -LiteralPath (Join-Path $PSScriptRoot "release-policy.json") -Raw | ConvertFrom-Json
    $approvedThumbprints = @($releasePolicy.approved_service_publisher_thumbprints |
        ForEach-Object { ([string]$_ -replace '\s', '').ToUpperInvariant() })
    $normalizedThumbprint = ($SigningCertificateThumbprint -replace '\s', '').ToUpperInvariant()
    if ($releasePolicy.status -ne "approved" -or $approvedThumbprints.Count -eq 0 -or
        $normalizedThumbprint -notin $approvedThumbprints) {
        throw "Release is blocked until release-policy.json approves this service/MSI publisher thumbprint."
    }
    $signTool = Get-Command -Name signtool.exe -ErrorAction SilentlyContinue
    if (-not $signTool) { throw "Release signing requires signtool.exe from the Windows SDK." }
    & $signTool.Source sign /fd SHA256 /sha1 $SigningCertificateThumbprint /tr $TimestampServer /td SHA256 /d "STAI Windows Protection Service" $serviceExe
    if ($LASTEXITCODE -ne 0) { throw "SignTool failed to sign the protection service executable." }
    & $signTool.Source verify /pa /v $serviceExe
    if ($LASTEXITCODE -ne 0) { throw "SignTool could not verify the protection service signature." }
    $serviceSignature = Get-AuthenticodeSignature -LiteralPath $serviceExe
    if ($serviceSignature.Status -ne "Valid" -or -not $serviceSignature.SignerCertificate) {
        throw "Release service executable must have a valid Authenticode signature."
    }
    $ekuExtension = $serviceSignature.SignerCertificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
        Select-Object -First 1
    $serviceEkus = @()
    if ($ekuExtension) { $serviceEkus = @($ekuExtension.EnhancedKeyUsages | ForEach-Object { $_.Value }) }
    if (-not [string]::Equals($serviceSignature.SignerCertificate.Thumbprint, $normalizedThumbprint, [StringComparison]::OrdinalIgnoreCase) -or
        "1.3.6.1.5.5.7.3.3" -notin $serviceEkus) {
        throw "Release service executable must use the pinned approved publisher with the code-signing EKU."
    }
}
$smokeOutput = & $serviceExe --stai-smoke-check
if ($LASTEXITCODE -ne 0) {
    $smokeOutput | Write-Host
    throw "The frozen service executable failed its non-installing command-line smoke check."
}

$dependencyOutput = & $pythonPath -m pip list --format=json
if ($LASTEXITCODE -ne 0) { throw "Unable to produce the dependency manifest." }
$dependencyJson = $dependencyOutput -join [System.Environment]::NewLine
$parsedDependencies = ConvertFrom-Json -InputObject $dependencyJson
if ($parsedDependencies.PSObject.Properties["value"] -and $parsedDependencies.PSObject.Properties["Count"]) {
    $dependencyItems = @($parsedDependencies.value)
} else {
    $dependencyItems = @($parsedDependencies)
}
$publicKeyFormat = if ($TrustedRulesPublicKeyPath) {
    "Ed25519 public PEM, exported as raw public bytes"
} else {
    $null
}
$manifest = [ordered]@{
    product = "STAI Windows Protection Service"
    configuration = $Configuration
    python = (& $pythonPath --version 2>&1 | Out-String).Trim()
    executable = "STAIProtectionService.exe"
    trusted_rules_public_key_embedded = [bool]$TrustedRulesPublicKeyPath
    trusted_rules_public_key_format = $publicKeyFormat
    production_ready = $false
    release_gates = @(
        "Microsoft-signed minifilter driver and allocated altitude",
        "clean Windows 10/11 VM installer and rollback results",
        "release signing and end-to-end validation evidence"
    )
    dependencies = $dependencyItems
}
$manifestPath = Join-Path $distPath "dependency-manifest.json"
$manifestJson = $manifest | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText(
    $manifestPath,
    $manifestJson,
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "Built: $serviceExe"
Write-Host "Manifest: $manifestPath"
Write-Host "Production readiness: blocked pending signed driver and VM release gates."
