@echo off

if "%~1"=="" (
    echo Usage: %~nx0 DriverName
    echo Example: %~nx0 driver.sys
    pause
    exit /b 1
)

set DRIVER_NAME=%~1
set DRIVER_FILE=%~dp0%DRIVER_NAME%.sys

REM Copy driver to System32\drivers if not already there
echo Copying %DRIVER_FILE% to %SystemRoot%\System32\drivers\
copy /Y "%DRIVER_FILE%" "%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys"

REM Delete old service if exists
sc delete %DRIVER_NAME% >nul 2>&1

REM Create boot-start driver service
sc create %DRIVER_NAME% type= kernel start= boot binPath= "System32\drivers\%DRIVER_NAME%.sys"

REM Confirm settings
sc qc %DRIVER_NAME%

pause

