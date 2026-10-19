@echo off
echo [CyberOS] Cleaning up firewall rules...
netsh advfirewall firewall delete rule name="CyberOS_Block_*" >nul 2>&1
echo [CyberOS] Cleaning up quarantine...
if exist "C:\AEGIS_Quarantine" (
    rmdir /S /Q "C:\AEGIS_Quarantine" >nul 2>&1
    mkdir "C:\AEGIS_Quarantine" >nul 2>&1
)
echo [CyberOS] Restoring test files...
if exist "C:\AEGIS_Test_Backup" (
    xcopy /E /Y "C:\AEGIS_Test_Backup\*" "C:\AEGIS_Test\" >nul 2>&1
)
echo [CyberOS] Re-enabling local accounts...
net user Guest /active:yes >nul 2>&1
echo [CyberOS] Cleanup complete.
pause
