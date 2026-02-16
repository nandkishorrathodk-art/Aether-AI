@echo off
title Aether AI - Control Center
color 0A
cls

:MENU
cls
echo.
echo  =====================================================
echo    █████╗ ███████╗████████╗██╗  ██╗███████╗██████╗ 
echo   ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗
echo   ███████║█████╗     ██║   ███████║█████╗  ██████╔╝
echo   ██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗
echo   ██║  ██║███████╗   ██║   ██║  ██║███████╗██║  ██║
echo   ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
echo  =====================================================
echo           Advanced AI Assistant v0.1.0
echo           All-in-One Control Center
echo  =====================================================
echo.
echo   [LAUNCH]
echo   1. Start Aether AI Server
echo   2. Start Full App (Server + UI)
echo   3. Start API Only
echo.
echo   [INSTALL]
echo   4. Install Aether AI
echo   5. Install OpenClaw
echo   6. Update Dependencies
echo.
echo   [TESTING]
echo   7. Run Integration Tests
echo   8. Test OpenClaw
echo   9. Test Voice Pipeline
echo   10. Verify Installation
echo.
echo   [TOOLS]
echo   11. Open API Docs
echo   12. View Logs
echo   13. Check Status
echo   14. Clean Cache
echo.
echo   [ADVANCED]
echo   15. Build Installer
echo   16. Uninstall
echo.
echo   0. Exit
echo.
echo  =====================================================
echo.

set /p choice="  Enter your choice (0-16): "

if "%choice%"=="0" goto EXIT
if "%choice%"=="1" goto START_SERVER
if "%choice%"=="2" goto START_FULL
if "%choice%"=="3" goto START_API
if "%choice%"=="4" goto INSTALL
if "%choice%"=="5" goto INSTALL_OPENCLAW
if "%choice%"=="6" goto UPDATE_DEPS
if "%choice%"=="7" goto TEST_INTEGRATION
if "%choice%"=="8" goto TEST_OPENCLAW
if "%choice%"=="9" goto TEST_VOICE
if "%choice%"=="10" goto VERIFY
if "%choice%"=="11" goto OPEN_DOCS
if "%choice%"=="12" goto VIEW_LOGS
if "%choice%"=="13" goto CHECK_STATUS
if "%choice%"=="14" goto CLEAN_CACHE
if "%choice%"=="15" goto BUILD_INSTALLER
if "%choice%"=="16" goto UNINSTALL

echo.
echo  Invalid choice! Press any key to try again...
pause >nul
goto MENU

:START_SERVER
cls
echo.
echo  =====================================================
echo   Starting Aether AI Server...
echo  =====================================================
echo.
cd /d "%~dp0"
call venv\Scripts\activate.bat
echo   Server: http://127.0.0.1:8000
echo   Docs:   http://127.0.0.1:8000/docs
echo   OpenClaw: http://127.0.0.1:8000/api/v1/openclaw/status
echo.
echo   Press Ctrl+C to stop
echo.
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
pause
goto MENU

:START_FULL
cls
echo.
echo  =====================================================
echo   Starting Aether AI (Server + UI)...
echo  =====================================================
echo.
call start-aether.bat
pause
goto MENU

:START_API
cls
echo.
echo  =====================================================
echo   Starting API Only...
echo  =====================================================
echo.
call start-api-only.bat
pause
goto MENU

:INSTALL
cls
echo.
echo  =====================================================
echo   Installing Aether AI...
echo  =====================================================
echo.
call install.bat
echo.
echo  Installation complete!
pause
goto MENU

:INSTALL_OPENCLAW
cls
echo.
echo  =====================================================
echo   Installing OpenClaw...
echo  =====================================================
echo.
call install-openclaw.bat
echo.
echo  OpenClaw installation complete!
pause
goto MENU

:UPDATE_DEPS
cls
echo.
echo  =====================================================
echo   Updating Dependencies...
echo  =====================================================
echo.
cd /d "%~dp0"
call venv\Scripts\activate.bat
echo   Upgrading pip...
python -m pip install --upgrade pip
echo.
echo   Installing/Updating all dependencies...
pip install -r requirements.txt --upgrade
echo.
echo   Dependencies updated!
pause
goto MENU

:TEST_INTEGRATION
cls
echo.
echo  =====================================================
echo   Running Integration Tests...
echo  =====================================================
echo.
cd /d "%~dp0"
call venv\Scripts\activate.bat
python -m pytest tests\integration\test_api.py -v
echo.
echo  Tests complete!
pause
goto MENU

:TEST_OPENCLAW
cls
echo.
echo  =====================================================
echo   Testing OpenClaw...
echo  =====================================================
echo.
cd /d "%~dp0"
call venv\Scripts\activate.bat
python scripts\test_openclaw.py
echo.
pause
goto MENU

:TEST_VOICE
cls
echo.
echo  =====================================================
echo   Testing Voice Pipeline...
echo  =====================================================
echo.
call test-voice-pipeline.bat
pause
goto MENU

:VERIFY
cls
echo.
echo  =====================================================
echo   Verifying Installation...
echo  =====================================================
echo.
cd /d "%~dp0"
call venv\Scripts\activate.bat
python scripts\verify_installation.py
echo.
pause
goto MENU

:OPEN_DOCS
cls
echo.
echo  =====================================================
echo   Opening API Documentation...
echo  =====================================================
echo.
echo   Please start the server first (Option 1)
echo   Then visit: http://127.0.0.1:8000/docs
echo.
start http://127.0.0.1:8000/docs
pause
goto MENU

:VIEW_LOGS
cls
echo.
echo  =====================================================
echo   Viewing Logs...
echo  =====================================================
echo.
cd /d "%~dp0"
if exist logs\aether.log (
    type logs\aether.log
) else (
    echo   No log file found at logs\aether.log
)
echo.
pause
goto MENU

:CHECK_STATUS
cls
echo.
echo  =====================================================
echo   System Status
echo  =====================================================
echo.
cd /d "%~dp0"

echo   [Environment]
if exist venv\Scripts\activate.bat (
    echo   ✓ Virtual environment: Found
) else (
    echo   ✗ Virtual environment: NOT FOUND
)

if exist .env (
    echo   ✓ Configuration file: Found
) else (
    echo   ✗ Configuration file: NOT FOUND
)

echo.
echo   [Components]
if exist src\action\automation\openclaw.py (
    echo   ✓ OpenClaw: Installed
) else (
    echo   ✗ OpenClaw: Not installed
)

if exist ui\package.json (
    echo   ✓ Desktop UI: Found
) else (
    echo   ✗ Desktop UI: Not found
)

echo.
echo   [API Server]
curl -s http://127.0.0.1:8000/health >nul 2>&1
if %errorlevel%==0 (
    echo   ✓ API Server: Running at http://127.0.0.1:8000
) else (
    echo   ✗ API Server: Not running
)

echo.
echo   [Files]
echo   - Logs: logs\aether.log
echo   - Config: .env
echo   - Data: data\
echo.
pause
goto MENU

:CLEAN_CACHE
cls
echo.
echo  =====================================================
echo   Cleaning Cache...
echo  =====================================================
echo.
cd /d "%~dp0"

echo   Cleaning Python cache...
if exist __pycache__ rmdir /s /q __pycache__
if exist src\__pycache__ rmdir /s /q src\__pycache__
if exist tests\__pycache__ rmdir /s /q tests\__pycache__

echo   Cleaning pytest cache...
if exist .pytest_cache rmdir /s /q .pytest_cache

echo   Cleaning coverage files...
if exist .coverage del /q .coverage
if exist htmlcov rmdir /s /q htmlcov

echo   Cleaning log files...
if exist logs\backend.log del /q logs\backend.log

echo.
echo   ✓ Cache cleaned!
pause
goto MENU

:BUILD_INSTALLER
cls
echo.
echo  =====================================================
echo   Building Installer...
echo  =====================================================
echo.
call build-installer.bat
pause
goto MENU

:UNINSTALL
cls
echo.
echo  =====================================================
echo   Uninstalling Aether AI...
echo  =====================================================
echo.
set /p confirm="  Are you sure? (Y/N): "
if /i "%confirm%"=="Y" (
    call uninstall.bat
) else (
    echo   Uninstall cancelled.
)
pause
goto MENU

:EXIT
cls
echo.
echo  =====================================================
echo   Thank you for using Aether AI!
echo  =====================================================
echo.
timeout /t 2 /nobreak >nul
exit
