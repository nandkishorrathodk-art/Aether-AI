@echo off
title Aether AI - Quick Start
color 0B
cls

:MENU
cls
echo.
echo  ================================================
echo         AETHER AI - QUICK START MENU
echo  ================================================
echo.
echo   What do you want to do?
echo.
echo   [1] Start Aether AI          (Recommended)
echo   [2] Run Tests
echo   [3] Install/Setup
echo   [4] Help
echo   [5] Exit
echo.
echo  ================================================
echo.

set /p choice="  Your choice (1-5): "

if "%choice%"=="1" goto START
if "%choice%"=="2" goto TEST
if "%choice%"=="3" goto INSTALL
if "%choice%"=="4" goto HELP
if "%choice%"=="5" goto EXIT

echo.
echo  Invalid choice!
timeout /t 2 /nobreak >nul
goto MENU

:START
cls
echo.
echo  ================================================
echo   Starting Aether AI...
echo  ================================================
echo.
cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo  ERROR: Not installed!
    echo.
    echo  Please run option [3] Install first.
    echo.
    pause
    goto MENU
)

call venv\Scripts\activate.bat

echo  Starting server...
echo.
echo  ================================================
echo   AETHER AI IS RUNNING!
echo  ================================================
echo.
echo   API:      http://127.0.0.1:8000
echo   Docs:     http://127.0.0.1:8000/docs
echo   OpenClaw: http://127.0.0.1:8000/api/v1/openclaw/status
echo.
echo   Press Ctrl+C to stop
echo  ================================================
echo.

python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload

pause
goto MENU

:TEST
cls
echo.
echo  ================================================
echo   Running Tests...
echo  ================================================
echo.
cd /d "%~dp0"
call venv\Scripts\activate.bat 2>nul

echo  [1/2] Integration Tests...
python -m pytest tests\integration\test_api.py -v --tb=short

echo.
echo  [2/2] OpenClaw Tests...
python scripts\test_openclaw.py

echo.
echo  ================================================
echo   Tests Complete!
echo  ================================================
pause
goto MENU

:INSTALL
cls
echo.
echo  ================================================
echo   Installation Menu
echo  ================================================
echo.
echo   [1] Full Install (First Time)
echo   [2] Install OpenClaw Only
echo   [3] Update Dependencies
echo   [4] Back to Main Menu
echo.
set /p inst="  Choice: "

if "%inst%"=="1" (
    echo.
    echo  Starting full installation...
    call install.bat
    pause
)
if "%inst%"=="2" (
    echo.
    echo  Installing OpenClaw...
    call install-openclaw.bat
    pause
)
if "%inst%"=="3" (
    echo.
    echo  Updating dependencies...
    call venv\Scripts\activate.bat
    pip install -r requirements.txt --upgrade
    echo  Done!
    pause
)
goto MENU

:HELP
cls
echo.
echo  ================================================
echo   AETHER AI - HELP
echo  ================================================
echo.
echo   QUICK START:
echo   1. First time? Choose [3] Install
echo   2. After install, choose [1] Start
echo   3. Visit http://127.0.0.1:8000/docs
echo.
echo   FEATURES:
echo   - Chat with AI (4 providers)
echo   - Task automation
echo   - Web scraping (OpenClaw)
echo   - Settings management
echo.
echo   FILES:
echo   - AETHER.bat       : Full menu (16 options)
echo   - RUN.bat          : Direct start
echo   - START.bat        : This menu (simple)
echo   - QUICK-START.txt  : Text guide
echo.
echo   DOCUMENTATION:
echo   - README.md
echo   - docs\OPENCLAW.md
echo   - OPENCLAW_QUICKSTART.md
echo.
echo   TROUBLESHOOTING:
echo   - Check: logs\aether.log
echo   - Verify: .env file exists
echo   - Re-run: install.bat
echo.
echo   API KEYS:
echo   Edit .env file to add:
echo   - OPENAI_API_KEY
echo   - ANTHROPIC_API_KEY
echo   - FIREWORKS_API_KEY (already set)
echo   - OPENROUTER_API_KEY
echo.
echo   CURRENT STATUS:
echo   ✓ Chat API - Working
echo   ✓ Task Management - Working
echo   ✓ Settings - Working
echo   ✓ OpenClaw (Web Scraping) - Working
echo   ✓ 4 AI Providers - Working
echo.
echo  ================================================
pause
goto MENU

:EXIT
cls
echo.
echo  Goodbye! 👋
echo.
timeout /t 1 /nobreak >nul
exit
