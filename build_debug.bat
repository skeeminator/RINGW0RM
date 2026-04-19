@echo off
REM ============================================================
REM Ring0 DEBUG Build Script v2.0
REM Full debug logging, symbols, no obfuscation
REM For development and testing only
REM ============================================================

setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "PLUGINS_DIR=%PROJECT_DIR%plugins"
set "DRIVER_DIR=%PROJECT_DIR%Chaos-Rootkit-Driver"
set "ILREPACK=%USERPROFILE%\.nuget\packages\ilrepack\2.0.34\tools\ILRepack.exe"

echo ============================================================
echo  Ring0 DEBUG Build v2.0
echo ============================================================
echo  - Full verbose logging enabled (DEBUG define)
echo  - Debug symbols included
echo  - No obfuscation
echo  - Driver with DbgPrint statements
echo  - Common.dll merged into Client.dll
echo ============================================================
echo.

if not exist "%PLUGINS_DIR%" mkdir "%PLUGINS_DIR%"

REM ============================================================
REM Step 1: Build Kernel Driver (Debug) FIRST
REM ============================================================
echo [1/4] Building Kernel Driver (Debug)...
call "%PROJECT_DIR%build_driver_debug.bat"
if errorlevel 1 goto BUILD_FAILED
echo       Driver built with debug symbols.
echo.

REM ============================================================
REM Step 2: Build C# Solution (Debug)
REM ============================================================
echo [2/4] Building C# Solution (Debug)...
dotnet build "%PROJECT_DIR%Pulsar.Plugin.Ring0.sln" -c Debug --nologo -v minimal
if errorlevel 1 goto BUILD_FAILED
echo       C# projects built successfully.
echo.

REM ============================================================
REM Step 3: Merge Common.dll into Client.dll
REM ============================================================
echo [3/4] Merging Common.dll into Client.dll...

set "CLIENT_SRC=%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\Debug\net48\Pulsar.Plugin.Ring0.Client.dll"
set "COMMON_SRC=%PROJECT_DIR%Pulsar.Plugin.Ring0.Common\bin\Debug\net48\Pulsar.Plugin.Ring0.Common.dll"
set "CLIENT_MERGED=%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\Debug\net48\Pulsar.Plugin.Ring0.Client.merged.dll"

REM Check for ILRepack
if not exist "%ILREPACK%" (
    echo       ILRepack not found, trying to restore...
    dotnet restore "%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\Pulsar.Plugin.Ring0.Client.csproj" --nologo >nul 2>&1
)

REM Merge Common.dll into Client.dll
if exist "%ILREPACK%" (
    "%ILREPACK%" /out:"%CLIENT_MERGED%" /lib:"%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\Debug\net48" "%CLIENT_SRC%" "%COMMON_SRC%"
    if exist "%CLIENT_MERGED%" (
        move /Y "%CLIENT_MERGED%" "%CLIENT_SRC%" >nul
        echo       Merge successful - Common.dll embedded into Client.dll
    ) else (
        echo       WARNING: Merge failed, copying both DLLs separately
    )
) else (
    echo       WARNING: ILRepack not available, copying both DLLs separately
)
echo.

REM ============================================================
REM Step 4: Copy to plugins folder (NO obfuscation for debug)
REM ============================================================
echo [4/4] Copying to plugins folder...
copy /Y "%CLIENT_SRC%" "%PLUGINS_DIR%\" >nul
copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Common\bin\Debug\net48\Pulsar.Plugin.Ring0.Common.dll" "%PLUGINS_DIR%\" >nul
copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Server\bin\Debug\net9.0-windows\Pulsar.Plugin.Ring0.Server.dll" "%PLUGINS_DIR%\" >nul
copy /Y "%DRIVER_DIR%\x64\Release\ring0.sys" "%PLUGINS_DIR%\" >nul
echo       Files copied to plugins folder.
echo.

echo ============================================================
echo  DEBUG BUILD COMPLETE
echo ============================================================
echo  Output: %PLUGINS_DIR%
echo  
echo  Features enabled:
echo    [x] Verbose logging (LogVerbose calls active)
echo    [x] Debug symbols included
echo    [x] Driver DbgPrint statements enabled
echo    [x] Common.dll merged into Client.dll
echo    [ ] Obfuscation (disabled for debug)
echo ============================================================

endlocal
exit /b 0

:BUILD_FAILED
echo.
echo ERROR: Build failed!
endlocal
exit /b 1
