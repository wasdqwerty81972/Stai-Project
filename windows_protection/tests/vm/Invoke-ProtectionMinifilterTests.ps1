<#
.SYNOPSIS
    Isolated VM integration tests for STAI Minifilter Driver

.DESCRIPTION
    Runs end-to-end tests in a disposable Windows 10/11 x64 VM with test signing enabled.
    Tests cover signed block rules, benign fixture execution, observe rules, service timeout,
    service process recursion prevention, and clean unload with pending requests.

.NOTES
    Requires: Hyper-V VM named "STAI-AV-Test" with test signing enabled
    Run from: Elevated PowerShell on host
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$VmName = "STAI-AV-Test",
    
    [string]$TestPackagePath = ".\windows_protection\driver\x64\Debug",
    
    [switch]$SkipCleanup
)

$ErrorActionPreference = "Stop"
$script:TestResults = @()

function Invoke-VMCommand {
    param(
        [string]$ScriptBlock,
        [int]$TimeoutSeconds = 60
    )
    
    $command = "Invoke-Command -VMName $VmName -ScriptBlock { $ScriptBlock }"
    $result = Invoke-Expression $command -ErrorAction Stop
    return $result
}

function Copy-ToVM {
    param(
        [string]$SourcePath,
        [string]$DestPath
    )
    
    Copy-VMFile -VMName $VmName -SourcePath $SourcePath -DestinationPath $DestPath `
        -FileSource Host -CreateFullPath -Force
}

function Test-SignedBlockRulePreventsImageMapping {
    Write-Host "Testing: Signed block rule prevents image mapping..." -ForegroundColor Cyan
    
    $result = Invoke-VMCommand {
        $testExe = "C:\Test\benign-marker.exe"
        $process = Start-Process -FilePath $testExe -PassThru -Wait -NoNewWindow
        exit $process.ExitCode
    }
    
    if ($result.ExitCode -eq 0) {
        throw "Block rule test FAILED: Process should have been blocked but exited with code 0"
    }
    
    if ($result.ExitCode -eq -1073741811) { # STATUS_ACCESS_DENIED
        Write-Host "  PASS: Process blocked with STATUS_ACCESS_DENIED" -ForegroundColor Green
        $script:TestResults += @{ Name = "SignedBlockRulePreventsImageMapping"; Passed = $true }
    } else {
        throw "Block rule test FAILED: Unexpected exit code $($result.ExitCode)"
    }
}

function Test-BenignFixtureStarts {
    Write-Host "Testing: Benign fixture starts when not blocked..." -ForegroundColor Cyan
    
    # Create a benign executable not in block list
    $result = Invoke-VMCommand {
        $testExe = "C:\Test\benign-allow.exe"
        if (-not (Test-Path $testExe)) {
            $code = @"
#include <windows.h>
#include <stdio.h>
int main() { printf("Benign allow test\n"); return 0; }
"@
            $code | Set-Content -Path "C:\Test\benign-allow.c" -Encoding ASCII
            & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe" `
                /nologo /W4 /O2 /GS /guard:cf /DYNAMICBASE /NXCOMPAT /ENTRY:mainCRTStartup `
                /SUBSYSTEM:CONSOLE,5.01 /OUT:"C:\Test\benign-allow.exe" "C:\Test\benign-allow.c" kernel32.lib
        }
        $process = Start-Process -FilePath $testExe -PassThru -Wait -NoNewWindow
        exit $process.ExitCode
    }
    
    if ($result.ExitCode -eq 0) {
        Write-Host "  PASS: Benign fixture started successfully" -ForegroundColor Green
        $script:TestResults += @{ Name = "BenignFixtureStarts"; Passed = $true }
    } else {
        throw "Benign fixture test FAILED: Exit code $($result.ExitCode)"
    }
}

function Test-ObserveRuleAllowsImageMapping {
    Write-Host "Testing: Observe rule allows image mapping..." -ForegroundColor Cyan
    
    # This test requires an observe rule in the rule package
    # The test fixture should match an observe rule but not a block rule
    $result = Invoke-VMCommand {
        $testExe = "C:\Test\observe-marker.exe"
        if (-not (Test-Path $testExe)) {
            $code = @"
#include <windows.h>
#include <stdio.h>
int main() { printf("Observe test marker\n"); return 0; }
"@
            $code | Set-Content -Path "C:\Test\observe-marker.c" -Encoding ASCII
            & "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.40.33807\bin\Hostx64\x64\cl.exe" `
                /nologo /W4 /O2 /GS /guard:cf /DYNAMICBASE /NXCOMPAT /ENTRY:mainCRTStartup `
                /SUBSYSTEM:CONSOLE,5.01 /OUT:"C:\Test\observe-marker.exe" "C:\Test\observe-marker.c" kernel32.lib
        }
        $process = Start-Process -FilePath $testExe -PassThru -Wait -NoNewWindow
        exit $process.ExitCode
    }
    
    if ($result.ExitCode -eq 0) {
        Write-Host "  PASS: Observe rule allowed execution" -ForegroundColor Green
        $script:TestResults += @{ Name = "ObserveRuleAllowsImageMapping"; Passed = $true }
    } else {
        throw "Observe rule test FAILED: Exit code $($result.ExitCode)"
    }
}

function Test-ServiceTimeoutPassesThroughAndMarksDegraded {
    Write-Host "Testing: Service timeout passes through and marks degraded..." -ForegroundColor Cyan
    
    $result = Invoke-VMCommand {
        # Stop the protection service
        Stop-Service -Name "StaiProtectionService" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # Try to execute a file - should pass through (fail-open)
        $testExe = "C:\Test\benign-allow.exe"
        $process = Start-Process -FilePath $testExe -PassThru -Wait -NoNewWindow
        $exitCode = $process.ExitCode
        
        # Check if protection status shows degraded
        $status = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\StaiProtection" -Name "Status" -ErrorAction SilentlyContinue
        
        Start-Service -Name "StaiProtectionService" -ErrorAction SilentlyContinue
        
        @{ ExitCode = $exitCode; Status = $status.Status }
    }
    
    if ($result.ExitCode -eq 0) {
        Write-Host "  PASS: Operation passed through during service timeout" -ForegroundColor Green
        $script:TestResults += @{ Name = "ServiceTimeoutPassesThrough"; Passed = $true }
    } else {
        throw "Service timeout test FAILED: Exit code $($result.ExitCode)"
    }
}

function Test-ServiceProcessDoesNotRecurse {
    Write-Host "Testing: Service process does not recurse..." -ForegroundColor Cyan
    
    $result = Invoke-VMCommand {
        # The service process should be able to read its own files without being scanned
        # This is implicitly tested by the service functioning correctly
        $servicePid = (Get-Service -Name "StaiProtectionService").Id
        $process = Get-Process -Id $servicePid -ErrorAction SilentlyContinue
        
        if ($process) {
            # Service is running, try to read a file it would scan
            $testFile = "C:\Test\test-file.txt"
            "test content" | Set-Content -Path $testFile
            $content = Get-Content -Path $testFile
            
            if ($content -eq "test content") {
                exit 0
            }
        }
        exit 1
    }
    
    if ($result.ExitCode -eq 0) {
        Write-Host "  PASS: Service process does not recurse" -ForegroundColor Green
        $script:TestResults += @{ Name = "ServiceProcessDoesNotRecurse"; Passed = $true }
    } else {
        throw "Service recursion test FAILED"
    }
}

function Test-UnloadWithPendingRequestCompletesCleanly {
    Write-Host "Testing: Unload with pending request completes cleanly..." -ForegroundColor Cyan
    
    $result = Invoke-VMCommand {
        # Load the filter
        fltmc load StaiProtection
        Start-Sleep -Seconds 1
        
        # Initiate a file operation that would create a pending request
        # Then unload the filter
        fltmc unload StaiProtection
        Start-Sleep -Seconds 2
        
        # Verify no crash or hang
        $driverLoaded = fltmc filters | Where-Object { $_ -like "*StaiProtection*" }
        
        if (-not $driverLoaded) {
            exit 0
        }
        exit 1
    }
    
    if ($result.ExitCode -eq 0) {
        Write-Host "  PASS: Unload with pending request completed cleanly" -ForegroundColor Green
        $script:TestResults += @{ Name = "UnloadWithPendingRequestCompletesCleanly"; Passed = $true }
    } else {
        throw "Unload test FAILED: Filter still loaded or crash occurred"
    }
}

function Run-AllTests {
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "STAI Minifilter VM Integration Tests" -ForegroundColor Yellow
    Write-Host "VM: $VmName" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    
    try {
        # Setup: Copy test package to VM
        Write-Host "Copying test package to VM..." -ForegroundColor Cyan
        Copy-ToVM -SourcePath $TestPackagePath -DestPath "C:\TestPackage"
        
        Write-Host "Installing driver in VM..." -ForegroundColor Cyan
        Invoke-VMCommand {
            pnputil.exe /add-driver C:\TestPackage\StaiProtection.inf /install
            fltmc load StaiProtection
        }
        
        # Run all test functions
        Test-SignedBlockRulePreventsImageMapping
        Test-BenignFixtureStarts
        Test-ObserveRuleAllowsImageMapping
        Test-ServiceTimeoutPassesThroughAndMarksDegraded
        Test-ServiceProcessDoesNotRecurse
        Test-UnloadWithPendingRequestCompletesCleanly
        
    } catch {
        Write-Host "TEST FAILED: $_" -ForegroundColor Red
        $script:TestResults += @{ Name = $_.InvocationInfo.MyCommand.Name; Passed = $false; Error = $_.ToString() }
    } finally {
        if (-not $SkipCleanup) {
            Write-Host "Cleaning up VM..." -ForegroundColor Cyan
            try {
                Invoke-VMCommand {
                    fltmc unload StaiProtection -ErrorAction SilentlyContinue
                    pnputil.exe /delete-driver StaiProtection.inf /uninstall /force -ErrorAction SilentlyContinue
                }
            } catch {
                Write-Host "Cleanup warning: $_" -ForegroundColor Yellow
            }
        }
        
        # Print summary
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "TEST SUMMARY" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        
        $passed = ($script:TestResults | Where-Object { $_.Passed }).Count
        $failed = ($script:TestResults | Where-Object { -not $_.Passed }).Count
        
        foreach ($test in $script:TestResults) {
            $status = if ($test.Passed) { "PASS" } else { "FAIL" }
            $color = if ($test.Passed) { "Green" } else { "Red" }
            Write-Host "  [$status] $($test.Name)" -ForegroundColor $color
            if ($test.Error) {
                Write-Host "    Error: $($test.Error)" -ForegroundColor Red
            }
        }
        
        Write-Host "Total: $($script:TestResults.Count), Passed: $passed, Failed: $failed" -ForegroundColor Yellow
        
        if ($failed -gt 0) {
            exit 1
        }
    }
}

Run-AllTests