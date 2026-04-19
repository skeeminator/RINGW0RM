@echo off
REM ============================================================
REM Safe DLL Obfuscation Script
REM Uses conservative settings to prevent breakage
REM ============================================================

setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "REACTOR=%PROJECT_DIR%Obfuscator\dotNET_Reactor.Console.exe"
set "OUTPUT=%PROJECT_DIR%plugins"

echo [OBFUSCATE] Starting...

REM Check if Reactor exists
if not exist "%REACTOR%" (
    echo [OBFUSCATE] WARNING: dotNET_Reactor not found at %REACTOR%
    echo [OBFUSCATE] Skipping obfuscation - DLLs will be unprotected
    exit /b 0
)

REM Check for skip flag
if "%SKIP_OBFUSCATION%"=="1" (
    echo [OBFUSCATE] Skipping obfuscation (SKIP_OBFUSCATION=1)
    exit /b 0
)

echo ============================================================
echo  DLL Obfuscation (Conservative Mode)
echo ============================================================

REM Create backup of unobfuscated DLLs
set "BACKUP_DIR=%PROJECT_DIR%plugins_unobfuscated"
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\Release\net48\Pulsar.Plugin.Ring0.Client.dll" "%BACKUP_DIR%\" >nul 2>&1
copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Common\bin\Release\net48\Pulsar.Plugin.Ring0.Common.dll" "%BACKUP_DIR%\" >nul 2>&1
copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Server\bin\Release\net9.0-windows\Pulsar.Plugin.Ring0.Server.dll" "%BACKUP_DIR%\" >nul 2>&1
echo    Unobfuscated backups saved to: %BACKUP_DIR%

REM ============================================================
REM Obfuscate Client DLL (Maximum protection - runs on victim)
REM ============================================================
echo.
echo [1/3] Obfuscating Client DLL...
"%REACTOR%" -file "%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\Release\net48\Pulsar.Plugin.Ring0.Client.dll" -targetfile "%OUTPUT%\Pulsar.Plugin.Ring0.Client.dll" -obfuscation 1 -stringencryption 1 -control_flow 0 -necrobit 0 -antitamp 0 -resourceencryption 0 -q -nodialog

if errorlevel 1 (
    echo    ERROR: Client obfuscation failed!
    echo    Falling back to unobfuscated version...
    copy /Y "%BACKUP_DIR%\Pulsar.Plugin.Ring0.Client.dll" "%OUTPUT%\" >nul
) else (
    echo    Client.dll obfuscated successfully
)

REM ============================================================
REM Obfuscate Common DLL (Light protection - shared types)
REM ============================================================
echo.
echo [2/3] Obfuscating Common DLL (symbols only)...
"%REACTOR%" -file "%PROJECT_DIR%Pulsar.Plugin.Ring0.Common\bin\Release\net48\Pulsar.Plugin.Ring0.Common.dll" -targetfile "%OUTPUT%\Pulsar.Plugin.Ring0.Common.dll" -obfuscation 1 -stringencryption 0 -control_flow 0 -necrobit 0 -antitamp 0 -q -nodialog

if errorlevel 1 (
    echo    ERROR: Common obfuscation failed!
    echo    Falling back to unobfuscated version...
    copy /Y "%BACKUP_DIR%\Pulsar.Plugin.Ring0.Common.dll" "%OUTPUT%\" >nul
) else (
    echo    Common.dll obfuscated successfully
)

REM ============================================================
REM Obfuscate Server DLL (Medium protection - operator side)
REM ============================================================
echo.
echo [3/3] Obfuscating Server DLL...
"%REACTOR%" -file "%PROJECT_DIR%Pulsar.Plugin.Ring0.Server\bin\Release\net9.0-windows\Pulsar.Plugin.Ring0.Server.dll" -targetfile "%OUTPUT%\Pulsar.Plugin.Ring0.Server.dll" -obfuscation 1 -stringencryption 1 -control_flow 0 -necrobit 0 -antitamp 0 -q -nodialog

if errorlevel 1 (
    echo    ERROR: Server obfuscation failed!
    echo    Falling back to unobfuscated version...
    copy /Y "%BACKUP_DIR%\Pulsar.Plugin.Ring0.Server.dll" "%OUTPUT%\" >nul
) else (
    echo    Server.dll obfuscated successfully
)

echo.
echo ============================================================
echo  Obfuscation Complete
echo ============================================================
echo  Protected DLLs in: %OUTPUT%
echo  Backups in: %BACKUP_DIR%
echo ============================================================

endlocal
exit /b 0
