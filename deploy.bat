@echo off
REM ============================================================
REM RINGW0RM Deploy Script
REM Copies built plugins to Pulsar installation
REM ============================================================

setlocal

set "PROJECT_DIR=%~dp0"
set "PLUGINS_DIR=%PROJECT_DIR%plugins"
set "PULSAR_DIR=C:\Users\skeem\Documents\pulsar-net-win64-2.4.5\Plugins"

echo ============================================================
echo  RINGW0RM Deploy
echo ============================================================

REM Check source exists
if not exist "%PLUGINS_DIR%" (
    echo ERROR: Plugins folder not found: %PLUGINS_DIR%
    echo Run build_debug.bat or build_release.bat first!
    exit /b 1
)

REM Check destination exists
if not exist "%PULSAR_DIR%" (
    echo ERROR: Pulsar directory not found: %PULSAR_DIR%
    echo Please edit deploy.bat to set PULSAR_DIR path
    exit /b 1
)

echo Source:      %PLUGINS_DIR%
echo Destination: %PULSAR_DIR%
echo.

echo Copying files...
copy /Y "%PLUGINS_DIR%\Pulsar.Plugin.Ring0.Client.dll" "%PULSAR_DIR%\" >nul
copy /Y "%PLUGINS_DIR%\Pulsar.Plugin.Ring0.Common.dll" "%PULSAR_DIR%\" >nul
copy /Y "%PLUGINS_DIR%\Pulsar.Plugin.Ring0.Server.dll" "%PULSAR_DIR%\" >nul
copy /Y "%PLUGINS_DIR%\ringw0rm.sys" "%PULSAR_DIR%\" >nul

REM Copy EFI if exists
if exist "%PLUGINS_DIR%\ringw0rm.efi" (
    copy /Y "%PLUGINS_DIR%\ringw0rm.efi" "%PULSAR_DIR%\" >nul
)

echo.
echo ============================================================
echo  DEPLOY COMPLETE
echo ============================================================
echo  Copied to: %PULSAR_DIR%
echo  Ready to restart Pulsar Server!
echo ============================================================

endlocal
exit /b 0
