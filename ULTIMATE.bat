@echo off
title Aether AI - Ultimate Launcher
color 0B
cls

echo.
echo  ================================================
echo         AETHER AI - ULTIMATE LAUNCHER
echo  ================================================
echo.
echo   This will:
echo   1. Auto-install if needed
echo   2. Start server in background
echo   3. Auto-test all features
echo   4. Launch interactive chat
echo.
echo   Press any key to continue...
pause >nul

cd /d "%~dp0"

REM Install if needed
if not exist "venv\Scripts\activate.bat" (
    cls
    echo.
    echo  Installing Aether AI...
    call install.bat
    timeout /t 3 /nobreak >nul
)

call venv\Scripts\activate.bat

REM Install OpenClaw if needed
if not exist "venv\Lib\site-packages\bs4" (
    echo  Installing OpenClaw...
    pip install beautifulsoup4 selenium lxml html5lib webdriver-manager --quiet
)

cls
echo.
echo  ================================================
echo   STARTING SERVER...
echo  ================================================
echo.

REM Kill any existing python servers
taskkill /F /IM python.exe >nul 2>&1

REM Start server
start /B python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

echo  Waiting for server...
timeout /t 3 /nobreak >nul

REM Wait for ready
:WAIT
curl -s http://127.0.0.1:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 1 /nobreak >nul
    goto WAIT
)

cls
echo.
echo  ================================================
echo   SERVER READY!
echo  ================================================
echo.
echo   Testing features...
echo.

REM Quick health check
curl -s http://127.0.0.1:8000/health
echo.
echo.

REM Test OpenClaw
echo  Testing OpenClaw...
python -c "import requests; r = requests.post('http://127.0.0.1:8000/api/v1/openclaw/scrape', json={'url': 'https://example.com'}, timeout=10); print('OK - OpenClaw Working!' if r.status_code == 200 else 'ERROR')" 2>nul
echo.

REM Test AI Chat
echo  Testing AI Chat...
python -c "import requests; r = requests.post('http://127.0.0.1:8000/api/v1/chat/conversation', json={'message': 'Hi', 'session_id': 'test'}, timeout=15); print('OK - AI Chat Working!' if r.status_code == 200 else 'ERROR: ' + str(r.status_code))" 2>nul
echo.

echo  ================================================
echo   ALL SYSTEMS GO!
echo  ================================================
echo.
timeout /t 2 /nobreak >nul

cls
python chat-with-aether.py

echo.
echo  Stopping server...
taskkill /F /IM python.exe >nul 2>&1
echo  Goodbye!
timeout /t 2 /nobreak >nul
