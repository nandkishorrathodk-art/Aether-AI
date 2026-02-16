@echo off
setlocal enabledelayedexpansion

:: Aether AI Uninstaller Script for Windows
:: Version: 1.0.0

title Aether AI Uninstaller

echo ============================================
echo    Aether AI Uninstaller
echo    Version 0.1.0 MVP
echo ============================================
echo.
echo This will remove Aether AI from your system.
echo.
echo WARNING: The following will be deleted:
echo   - Virtual environment (venv/)
echo   - Node modules (ui/node_modules/)
echo   - Build files (ui/build/)
echo   - Desktop shortcut
echo.
echo Your data and configuration will be preserved:
echo   - .env file (API keys and settings)
echo   - data/ folder (user data, conversations, memory)
echo   - logs/ folder (application logs)
echo.

choice /C YN /M "Do you want to proceed with uninstallation"
if errorlevel 2 (
    echo.
    echo Uninstallation cancelled.
    pause
    exit /b 0
)

echo.
echo Starting uninstallation...
echo.

:: Stop any running processes
echo [1/5] Stopping Aether AI processes...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq Aether*" >nul 2>&1
taskkill /F /IM node.exe /FI "WINDOWTITLE eq Aether*" >nul 2>&1
taskkill /F /IM electron.exe >nul 2>&1
echo Processes stopped
echo.

:: Remove virtual environment
echo [2/5] Removing Python virtual environment...
if exist "venv" (
    rmdir /S /Q "venv"
    echo Virtual environment removed
) else (
    echo Virtual environment not found
)
echo.

:: Remove node_modules
echo [3/5] Removing Node.js dependencies...
if exist "ui\node_modules" (
    rmdir /S /Q "ui\node_modules"
    echo Node modules removed
) else (
    echo Node modules not found
)
echo.

:: Remove build files
echo [4/5] Removing build files...
if exist "ui\build" (
    rmdir /S /Q "ui\build"
    echo Build files removed
) else (
    echo Build files not found
)

if exist "ui\dist" (
    rmdir /S /Q "ui\dist"
    echo Distribution files removed
) else (
    echo Distribution files not found
)
echo.

:: Remove desktop shortcut
echo [5/5] Removing desktop shortcut...
set SHORTCUT_PATH=%USERPROFILE%\Desktop\Aether AI.lnk
if exist "%SHORTCUT_PATH%" (
    del /F /Q "%SHORTCUT_PATH%"
    echo Desktop shortcut removed
) else (
    echo Desktop shortcut not found
)
echo.

:: Ask about configuration and data
echo ============================================
echo    Uninstallation Complete
echo ============================================
echo.
echo Aether AI has been uninstalled from your system.
echo.
echo Do you want to remove your data and configuration?
echo   - .env file (API keys and settings)
echo   - data/ folder (conversations, memory, user profiles)
echo   - logs/ folder (application logs)
echo.

choice /C YN /M "Remove all data and configuration"
if errorlevel 2 (
    echo.
    echo Data and configuration preserved.
    echo You can reinstall Aether AI later without losing your settings.
) else (
    echo.
    echo Removing data and configuration...
    
    if exist ".env" (
        del /F /Q ".env"
        echo .env file removed
    )
    
    if exist "data" (
        rmdir /S /Q "data"
        echo data/ folder removed
    )
    
    if exist "logs" (
        rmdir /S /Q "logs"
        echo logs/ folder removed
    )
    
    if exist "models" (
        rmdir /S /Q "models"
        echo models/ folder removed
    )
    
    echo.
    echo All data and configuration removed.
)

echo.
echo ============================================
echo Thank you for using Aether AI!
echo.
echo To reinstall, run: install.bat
echo ============================================
echo.
pause
