[CmdletBinding()]
param(
    [ValidateSet("Test", "Release")]
    [string] $Configuration = "Test",
    [Parameter(Mandatory = $true)]
    [string] $ServiceExePath,
    [Parameter(Mandatory = $true)]
    [string] $DriverPackagePath,
    [Parameter(Mandatory = $true)]
    [string] $SignedRulesPackagePath,
    [string] $ReleaseEvidencePath,
    [string] $SigningCertificateThumbprint,
    [string] $TimestampServer = "https://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$installerRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$stageRoot = Join-Path $installerRoot (Join-Path "build" (Join-Path $Configuration "stage"))
$serviceExe = (Resolve-Path -LiteralPath $ServiceExePath).Path
$driverRoot = (Resolve-Path -LiteralPath $DriverPackagePath).Path
$rulesRoot = (Resolve-Path -LiteralPath $SignedRulesPackagePath).Path

function Get-CertificateEkuOids([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate) {
    $ekuExtension = $Certificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
        Select-Object -First 1
    if (-not $ekuExtension) { return @() }
    return @($ekuExtension.EnhancedKeyUsages | ForEach-Object { $_.Value })
}

function ConvertTo-NormalizedAltitude([string] $Value, [string] $Name) {
    $parsed = [decimal]::Zero
    $style = [Globalization.NumberStyles]::AllowDecimalPoint
    $culture = [Globalization.CultureInfo]::InvariantCulture
    if (-not [decimal]::TryParse($Value, $style, $culture, [ref]$parsed) -or $parsed -le [decimal]::Zero) {
        throw "$Name must be a positive decimal minifilter altitude."
    }
    return $parsed
}

foreach ($fileName in @("StaiProtection.inf", "StaiProtection.sys", "StaiProtection.cat")) {
    if (-not (Test-Path -LiteralPath (Join-Path $driverRoot $fileName) -PathType Leaf)) {
        throw "The driver package is incomplete; required file missing: $fileName"
    }
}
foreach ($fileName in @("manifest.json", "manifest.sig")) {
    if (-not (Test-Path -LiteralPath (Join-Path $rulesRoot $fileName) -PathType Leaf)) {
        throw "The signed rule package is incomplete; required file missing: $fileName"
    }
}

if ($Configuration -eq "Release") {
    if (-not $ReleaseEvidencePath) {
        throw "Release packaging requires -ReleaseEvidencePath with verified production release evidence."
    }
    if (-not $SigningCertificateThumbprint -or $SigningCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
        throw "Release packaging requires a 40 character SHA-1 code-signing certificate thumbprint for SignTool."
    }
    $releasePolicyPath = Join-Path $installerRoot "release-policy.json"
    if (-not (Test-Path -LiteralPath $releasePolicyPath -PathType Leaf)) {
        throw "Release packaging requires the reviewed release-policy.json publisher allowlist."
    }
    $releasePolicy = Get-Content -LiteralPath $releasePolicyPath -Raw | ConvertFrom-Json
    $approvedPublisherThumbprints = @($releasePolicy.approved_service_publisher_thumbprints |
        ForEach-Object { ([string]$_ -replace '\s', '').ToUpperInvariant() })
    $approvedDriverThumbprints = @($releasePolicy.approved_microsoft_driver_signer_thumbprints |
        ForEach-Object { ([string]$_ -replace '\s', '').ToUpperInvariant() })
    $normalizedPublisherThumbprint = ($SigningCertificateThumbprint -replace '\s', '').ToUpperInvariant()
    if ($releasePolicy.status -ne "approved" -or $approvedPublisherThumbprints.Count -eq 0 -or $approvedDriverThumbprints.Count -eq 0 -or
        $normalizedPublisherThumbprint -notin $approvedPublisherThumbprints) {
        throw "Release is blocked until release-policy.json pins the approved service/MSI publisher and Microsoft driver signer thumbprints."
    }
    $releaseEvidenceFile = (Resolve-Path -LiteralPath $ReleaseEvidencePath).Path
    $releaseEvidence = Get-Content -LiteralPath $releaseEvidenceFile -Raw | ConvertFrom-Json
    if ($releaseEvidence.production_ready -ne $true -or $releaseEvidence.status -ne "passed") {
        throw "Release evidence must explicitly mark the full package readiness review as passed."
    }
    $requiredGates = @(
        "microsoft_signed_driver",
        "allocated_altitude",
        "clean_windows_vm_validation"
    )
    foreach ($gateName in $requiredGates) {
        $gate = $releaseEvidence.gates.$gateName
        if (-not $gate -or $gate.passed -ne $true -or -not $gate.evidence) {
            throw "Release gate '$gateName' is not backed by passing evidence."
        }
        if (-not (Test-Path -LiteralPath $gate.evidence -PathType Leaf)) {
            throw "Release gate '$gateName' references missing evidence: $($gate.evidence)"
        }
    }
    $evidenceAltitude = ConvertTo-NormalizedAltitude ([string]$releaseEvidence.gates.allocated_altitude.value) "Release altitude"
    if ($evidenceAltitude -eq [decimal]329999) {
        throw "The VM-only debug altitude 329999 cannot be used in a production package."
    }
    $altitudeRecordPath = (Resolve-Path -LiteralPath $releaseEvidence.gates.allocated_altitude.evidence).Path
    $altitudeRecord = Get-Content -LiteralPath $altitudeRecordPath -Raw | ConvertFrom-Json
    $recordAltitude = ConvertTo-NormalizedAltitude ([string]$altitudeRecord.altitude) "Microsoft allocation record altitude"
    $sourceUri = $null
    $sourceIsMicrosoft = [uri]::TryCreate([string]$altitudeRecord.source_url, [UriKind]::Absolute, [ref]$sourceUri) -and
        $sourceUri.Scheme -eq "https" -and ($sourceUri.Host -eq "microsoft.com" -or $sourceUri.Host.EndsWith(".microsoft.com", [StringComparison]::OrdinalIgnoreCase))
    $allocationDocumentPath = $null
    $allocationDocumentHashMatches = $false
    if ($altitudeRecord.official_record_file -and $altitudeRecord.official_record_sha256 -match '^[A-Fa-f0-9]{64}$') {
        $allocationDocumentPath = (Resolve-Path -LiteralPath $altitudeRecord.official_record_file).Path
        $allocationDocumentHash = (Get-FileHash -LiteralPath $allocationDocumentPath -Algorithm SHA256).Hash
        $allocationDocumentHashMatches = [string]::Equals($allocationDocumentHash, [string]$altitudeRecord.official_record_sha256, [StringComparison]::OrdinalIgnoreCase)
    }
    if ($altitudeRecord.issuer -ne "Microsoft Hardware Dev Center" -or
        $altitudeRecord.filter_name -ne "StaiProtection" -or $recordAltitude -ne $evidenceAltitude -or
        -not $altitudeRecord.reference_id -or -not $sourceIsMicrosoft -or
        -not $altitudeRecord.reviewed_by -or -not $altitudeRecord.reviewed_utc -or
        -not $allocationDocumentPath -or -not $allocationDocumentHashMatches) {
        throw "Altitude evidence must include a reviewed Microsoft Hardware Dev Center record for STAI, an official HTTPS source, and the SHA-256-verified allocation document."
    }
    $infText = Get-Content -LiteralPath (Join-Path $driverRoot "StaiProtection.inf") -Raw
    $infAltitude = [regex]::Match($infText, 'STAI_ALTITUDE\s*=\s*"([^"]+)"')
    if (-not $infAltitude.Success -or (ConvertTo-NormalizedAltitude $infAltitude.Groups[1].Value "Driver INF altitude") -ne $evidenceAltitude) {
        throw "The driver INF altitude does not match the allocation evidence."
    }
    $vmEvidencePath = (Resolve-Path -LiteralPath $releaseEvidence.gates.clean_windows_vm_validation.evidence).Path
    $vmEvidence = Get-Content -LiteralPath $vmEvidencePath -Raw | ConvertFrom-Json
    if ($vmEvidence.status -ne "passed" -or -not $vmEvidence.results -or
        @($vmEvidence.results | Where-Object { $_.status -ne "passed" }).Count -gt 0) {
        throw "Windows VM evidence does not show every required installer and enforcement assertion passing."
    }
    if ($vmEvidence.test_signing_enabled -ne $false) {
        throw "Production VM evidence must explicitly confirm Windows test-signing mode was disabled."
    }
    if ([string]$vmEvidence.windows -notmatch 'Windows 10|Windows 11' -or [string]$vmEvidence.architecture -ne "x64") {
        throw "VM evidence must cover a supported Windows 10/11 x64 system."
    }
    $requiredAssertions = @(
        "test_install_requires_elevation",
        "test_install_registers_service_and_filter",
        "test_failed_driver_start_rolls_back_service",
        "test_uninstall_preserves_quarantine",
        "test_test_signed_build_is_marked_nonproduction",
        "test_signed_block",
        "test_benign_allow",
        "test_observe_allow",
        "test_service_unavailable_fail_open",
        "test_service_process_recursion_prevention",
        "test_unload_during_outstanding_io",
        "test_interrupted_update_keeps_prior_version",
        "test_invalid_rule_signature_rolls_back_package",
        "test_new_driver_health_failure_restores_previous_driver",
        "test_release_gate_rejects_test_signature"
    )
    $reportedAssertions = @($vmEvidence.results | ForEach-Object { [string]$_.name })
    $missingAssertions = @($requiredAssertions | Where-Object { $_ -notin $reportedAssertions })
    if ($missingAssertions.Count -gt 0) {
        throw "VM evidence is missing required passing assertions: $($missingAssertions -join ', ')"
    }
    $signTool = Get-Command -Name signtool.exe -ErrorAction SilentlyContinue
    if (-not $signTool) { throw "Release driver verification requires signtool.exe from the Windows SDK/WDK." }
    $bcdedit = Join-Path $env:windir "System32\bcdedit.exe"
    $bootConfiguration = & $bcdedit /enum "{current}" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Release build host boot configuration could not be verified." }
    if (($bootConfiguration -join "`n") -match '(?im)^\s*(testsigning|nointegritychecks|flightsigning)\s+Yes\s*$') {
        throw "Release signing is blocked while Windows test-signing or integrity-check bypass is enabled on the build host."
    }
    $catalogPath = Join-Path $driverRoot "StaiProtection.cat"
    $driverInfPath = Join-Path $driverRoot "StaiProtection.inf"
    $driverSysPath = Join-Path $driverRoot "StaiProtection.sys"
    & $signTool.Source verify /kp /v $catalogPath
    if ($LASTEXITCODE -ne 0) { throw "SignTool kernel-policy verification rejected the driver catalog." }
    foreach ($driverFile in @($driverInfPath, $driverSysPath)) {
        & $signTool.Source verify /kp /v /c $catalogPath $driverFile
        if ($LASTEXITCODE -ne 0) { throw "SignTool kernel-policy verification rejected catalog membership for $([IO.Path]::GetFileName($driverFile))." }
    }
    $catalogSignature = Get-AuthenticodeSignature -LiteralPath $catalogPath
    if ($catalogSignature.Status -ne "Valid" -or -not $catalogSignature.SignerCertificate) {
        throw "Release packaging requires a valid Authenticode signature on the driver catalog."
    }
    $driverSigningEkus = Get-CertificateEkuOids $catalogSignature.SignerCertificate
    $hardwareDriverEkus = @("1.3.6.1.4.1.311.10.3.5", "1.3.6.1.4.1.311.10.3.5.1")
    if (@($driverSigningEkus | Where-Object { $_ -in $hardwareDriverEkus }).Count -eq 0) {
        throw "Release packaging requires a valid Microsoft hardware driver signature verified by SignTool and the hardware-driver EKU."
    }
    $driverSignerThumbprint = ($catalogSignature.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant()
    if ($driverSignerThumbprint -notin $approvedDriverThumbprints) {
        throw "The driver catalog signer is not the Microsoft hardware publisher pinned in release-policy.json."
    }
    $serviceSignature = Get-AuthenticodeSignature -LiteralPath $serviceExe
    if ($serviceSignature.Status -ne "Valid" -or -not $serviceSignature.SignerCertificate) {
        throw "Release packaging requires a valid Authenticode signature on the service executable."
    }
    $serviceSigningEkus = Get-CertificateEkuOids $serviceSignature.SignerCertificate
    if (-not [string]::Equals($serviceSignature.SignerCertificate.Thumbprint, $normalizedPublisherThumbprint, [StringComparison]::OrdinalIgnoreCase) -or
        "1.3.6.1.5.5.7.3.3" -notin $serviceSigningEkus) {
        throw "Release packaging requires the pinned approved publisher's valid code-signing signature on the service executable."
    }
}

New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
$stageDriver = Join-Path $stageRoot "driver"
$stageRules = Join-Path $stageRoot "rules"
New-Item -ItemType Directory -Path $stageDriver, $stageRules -Force | Out-Null
Copy-Item -LiteralPath $serviceExe -Destination (Join-Path $stageRoot "STAIProtectionService.exe") -Force
Copy-Item -LiteralPath (Join-Path $installerRoot "update.ps1") -Destination $stageRoot -Force
Copy-Item -LiteralPath (Join-Path $installerRoot "InstallRollbackRecovery.ps1") -Destination $stageRoot -Force
Copy-Item -LiteralPath (Join-Path $driverRoot "StaiProtection.inf") -Destination $stageDriver -Force
Copy-Item -LiteralPath (Join-Path $driverRoot "StaiProtection.sys") -Destination $stageDriver -Force
Copy-Item -LiteralPath (Join-Path $driverRoot "StaiProtection.cat") -Destination $stageDriver -Force
Copy-Item -LiteralPath (Join-Path $rulesRoot "manifest.json") -Destination $stageRules -Force
Copy-Item -LiteralPath (Join-Path $rulesRoot "manifest.sig") -Destination $stageRules -Force

$stagedService = Join-Path $stageRoot "STAIProtectionService.exe"
$verifyOutput = & $stagedService --stai-verify-rules (Join-Path $stageRules "manifest.json") (Join-Path $stageRules "manifest.sig") 2>&1
if ($LASTEXITCODE -ne 0) {
    $verifyOutput | Write-Host
    throw "The embedded public key rejected the staged signed rule package."
}

$packageMetadata = [ordered]@{
    product = "STAI Windows Protection"
    version = "1.0.0.0"
    build_flavor = $Configuration
    built_utc = [DateTime]::UtcNow.ToString("o")
    test_signature = ($Configuration -eq "Test")
    rules_signature_verified = $true
    production_ready = $false
    release_evidence = $null
    publisher_thumbprint = $null
    driver_signer_thumbprint = $null
    release_gates = @(
        "Microsoft-signed minifilter and allocated altitude",
        "clean Windows 10/11 VM install, enforcement, rollback, and uninstall results",
        "signed release artifacts and independent validation evidence"
    )
}
if ($Configuration -eq "Release") {
    $packageMetadata.production_ready = $true
    $packageMetadata.release_evidence = (Split-Path -Leaf $releaseEvidenceFile)
    $packageMetadata.publisher_thumbprint = $serviceSignature.SignerCertificate.Thumbprint
    $packageMetadata.driver_signer_thumbprint = $driverSignerThumbprint
}
$metadataPath = Join-Path $stageRoot "package-metadata.json"
[System.IO.File]::WriteAllText(
    $metadataPath,
    ($packageMetadata | ConvertTo-Json -Depth 8),
    [System.Text.UTF8Encoding]::new($false)
)

$project = Join-Path $installerRoot "StaiProtection.wixproj"
& dotnet build $project -c $Configuration -p:StageDir=$stageRoot -p:BuildFlavor=$Configuration
if ($LASTEXITCODE -ne 0) {
    throw "WiX failed to build the STAI Windows Protection installer."
}
$outputRoot = Join-Path $installerRoot (Join-Path "bin" $Configuration)
$msi = Get-ChildItem -LiteralPath $outputRoot -Filter "*.msi" -Recurse -File |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if (-not $msi) {
    throw "WiX build completed without producing an MSI."
}
if ($Configuration -eq "Release") {
    $signTool = Get-Command -Name signtool.exe -ErrorAction SilentlyContinue
    if (-not $signTool) { throw "Release signing requires signtool.exe from the Windows SDK." }
    try {
        & $signTool.Source sign /fd SHA256 /sha1 $SigningCertificateThumbprint /tr $TimestampServer /td SHA256 /d "STAI Windows Protection" $msi.FullName
        if ($LASTEXITCODE -ne 0) { throw "SignTool failed to sign the installer MSI." }
        & $signTool.Source verify /pa /v $msi.FullName
        if ($LASTEXITCODE -ne 0) { throw "SignTool could not verify the installer MSI signature." }
        $msiSignature = Get-AuthenticodeSignature -LiteralPath $msi.FullName
        $msiSigningEkus = Get-CertificateEkuOids $msiSignature.SignerCertificate
        if ($msiSignature.Status -ne "Valid" -or
            -not [string]::Equals($msiSignature.SignerCertificate.Thumbprint, $normalizedPublisherThumbprint, [StringComparison]::OrdinalIgnoreCase) -or
            "1.3.6.1.5.5.7.3.3" -notin $msiSigningEkus) {
            throw "Release MSI must have a valid non-test Authenticode signature."
        }
    } catch {
        $packageMetadata.production_ready = $false
        $packageMetadata.release_evidence = $null
        [System.IO.File]::WriteAllText(
            $metadataPath,
            ($packageMetadata | ConvertTo-Json -Depth 8),
            [System.Text.UTF8Encoding]::new($false)
        )
        $outputRootFull = [IO.Path]::GetFullPath($outputRoot) + [IO.Path]::DirectorySeparatorChar
        $msiPathFull = [IO.Path]::GetFullPath($msi.FullName)
        if ($msiPathFull.StartsWith($outputRootFull, [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($msiPathFull) -eq "StaiProtection.msi") {
            Remove-Item -LiteralPath $msiPathFull -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    $readyReport = [ordered]@{
        schema_version = 1
        status = "passed"
        production_ready = $true
        built_installer = $msi.FullName
        installer_signer = $msiSignature.SignerCertificate.Subject
        gates = @{
            microsoft_signed_driver = $true
            allocated_altitude = [string]$releaseEvidence.gates.allocated_altitude.value
            clean_windows_vm_validation = "passed"
            approved_service_publisher = $normalizedPublisherThumbprint
            signed_release_artifacts = "verified by SignTool and Authenticode"
        }
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $installerRoot (Join-Path "build\Release" "release-readiness.json")),
        ($readyReport | ConvertTo-Json -Depth 8),
        [System.Text.UTF8Encoding]::new($false)
    )
}
Write-Host "Built installer: $($msi.FullName)"
Write-Host "Build flavor: $Configuration"
Write-Host "Production readiness: $($packageMetadata.production_ready)"
