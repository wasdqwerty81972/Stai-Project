[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path $env:TEMP 'svs-wfp-event-bridge-build'),
    [string] $VsInstallPath = $env:STAI_VS_INSTALL,
    [string] $WindowsSdkVersion
)

$ErrorActionPreference = 'Stop'
$nativeDirectory = $PSScriptRoot
$repositoryRoot = (Resolve-Path (Join-Path $nativeDirectory '..\..\..')).Path

if (-not $VsInstallPath) {
    $vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswherePath) {
        $VsInstallPath = (& $vswherePath -latest -products '*' -property installationPath | Select-Object -First 1)
    }
}
if (-not $VsInstallPath -and (Test-Path -LiteralPath 'F:\STAI-BuildTools\BuildTools')) {
    $VsInstallPath = 'F:\STAI-BuildTools\BuildTools'
}
if (-not $VsInstallPath) {
    throw 'Visual Studio Build Tools were not found. Set -VsInstallPath or STAI_VS_INSTALL.'
}

$vcvars = Join-Path $VsInstallPath 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path -LiteralPath $vcvars)) {
    throw "MSVC x64 environment script was not found: $vcvars"
}

$sdkIncludeRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Include'
if (-not $WindowsSdkVersion) {
    $WindowsSdkVersion = Get-ChildItem -LiteralPath $sdkIncludeRoot -Directory |
        Where-Object { $_.Name -match '^10\.0\d+\.\d+\.\d+$' } |
        Sort-Object { [version] $_.Name } -Descending |
        Select-Object -First 1 -ExpandProperty Name
}
if (-not $WindowsSdkVersion) {
    throw "Windows 10 SDK headers were not found beneath $sdkIncludeRoot"
}

$includeRoot = Join-Path $sdkIncludeRoot $WindowsSdkVersion
$sdkLibRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Lib\$WindowsSdkVersion"
$sdkUmLib = Join-Path $sdkLibRoot 'um\x64'
$sdkUcrtLib = Join-Path $sdkLibRoot 'ucrt\x64'
foreach ($requiredPath in @(
    (Join-Path $includeRoot 'um\fwpmu.h'),
    (Join-Path $sdkUmLib 'Fwpuclnt.lib'),
    (Join-Path $sdkUmLib 'Advapi32.lib')
)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Required Windows SDK file is missing: $requiredPath"
    }
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

# Import the environment produced by vcvarsall without running any WFP API.
$environmentLines = & $env:ComSpec /d /s /c "call `"$vcvars`" >nul && set"
if ($LASTEXITCODE -ne 0) {
    throw "vcvars64.bat failed with exit code $LASTEXITCODE"
}
foreach ($line in $environmentLines) {
    $separator = $line.IndexOf('=')
    if ($separator -gt 0) {
        $name = $line.Substring(0, $separator)
        $value = $line.Substring($separator + 1)
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')
    }
}

$env:INCLUDE = @(
    (Join-Path $includeRoot 'um'),
    (Join-Path $includeRoot 'shared'),
    (Join-Path $includeRoot 'ucrt'),
    $env:INCLUDE
) -join ';'
$env:LIB = @($sdkUmLib, $sdkUcrtLib, $env:LIB) -join ';'

$bridgeSource = Join-Path $nativeDirectory 'wfp_event_bridge.cpp'
$testsSource = Join-Path $nativeDirectory 'wfp_event_bridge_tests.cpp'
$dllPath = Join-Path $OutputDirectory 'svs_wfp_event_bridge.dll'
$testPath = Join-Path $OutputDirectory 'svs_wfp_event_bridge_tests.exe'
$commonFlags = @(
    '/nologo', '/std:c++17', '/EHsc', '/W4', '/MD',
    '/D_WIN32_WINNT=0x0A00', '/DNTDDI_VERSION=0x0A000005',
    "/I$(Join-Path $includeRoot 'um')",
    "/I$(Join-Path $includeRoot 'shared')",
    "/I$(Join-Path $includeRoot 'ucrt')"
)

Write-Host "Building user-mode WFP event bridge with Windows SDK $WindowsSdkVersion..."
& cl.exe @commonFlags /LD $bridgeSource "/link" "/OUT:$dllPath" 'Fwpuclnt.lib' 'Advapi32.lib'
if ($LASTEXITCODE -ne 0) {
    throw "WFP event bridge DLL build failed with exit code $LASTEXITCODE"
}

Write-Host 'Building synthetic tests (they do not subscribe to live WFP events)...'
& cl.exe @commonFlags '/DSVS_WFP_TESTING' $bridgeSource $testsSource "/Fe:$testPath" "/link" 'Fwpuclnt.lib' 'Advapi32.lib'
if ($LASTEXITCODE -ne 0) {
    throw "WFP event bridge synthetic test build failed with exit code $LASTEXITCODE"
}

Write-Host 'Running synthetic tests; no live WFP subscription is started.'
& $testPath
if ($LASTEXITCODE -ne 0) {
    throw "WFP event bridge synthetic tests failed with exit code $LASTEXITCODE"
}

Write-Host "Built: $dllPath"
Write-Host "Tests: $testPath"
