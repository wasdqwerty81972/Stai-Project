@echo off
REM Build script for benign-marker.exe test fixture
REM Run from x64 Native Tools Command Prompt for VS 2022

cl /nologo /W4 /O2 /GS /guard:cf /DYNAMICBASE /NXCOMPAT /ENTRY:mainCRTStartup ^
   /SUBSYSTEM:CONSOLE,5.01 ^
   /OUT:benign-marker.exe benign-marker.c kernel32.lib

if %ERRORLEVEL% NEQ 0 (
    echo Build failed
    exit /b 1
)

echo Build successful: benign-marker.exe