@echo off
echo ============================================================
echo  RINGW0RM Licensing Manager Build
echo ============================================================
echo.

set PROJECT_DIR=%~dp0Licensing-System
set OUTPUT_DIR=%~dp0Licensing-System\bin\Release\net8.0-windows

echo Building Licensing Manager...
echo.

dotnet build "%PROJECT_DIR%\Licensing-System.csproj" -c Release

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed!
    exit /b 1
)

echo.
echo ============================================================
echo  BUILD COMPLETE
echo ============================================================
echo  Output: %OUTPUT_DIR%
echo.
echo  To run: dotnet run --project "%PROJECT_DIR%" -c Release
echo  Or run: "%OUTPUT_DIR%\Licensing-System.exe"
echo ============================================================
echo.

pause
