@echo off
title Aether AI - All in One
color 0A
cls

echo.
echo  ========================================
echo   AETHER AI - ALL IN ONE LAUNCHER
echo  ========================================
echo.

cd /d "%~dp0"

REM Check installation
if not exist "venv\Scripts\activate.bat" (
    echo  [!] Not installed. Installing now...
    echo.
    call install.bat
    echo.
    echo  ========================================
    echo   Installation Complete!
    echo  ========================================
    echo.
    timeout /t 3 /nobreak >nul
)

REM Activate environment
call venv\Scripts\activate.bat

REM Check OpenClaw
if not exist "venv\Lib\site-packages\bs4" (
    echo  [*] Installing OpenClaw...
    pip install beautifulsoup4 selenium lxml html5lib webdriver-manager --quiet >nul 2>&1
)

echo  ========================================
echo   STARTING AETHER AI SERVER...
echo  ========================================
echo.
echo  [*] Starting server in background...
echo.

REM Start server in background
start /B python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 >nul 2>&1

echo  [*] Waiting for server to start...
timeout /t 5 /nobreak >nul

REM Wait for server to be ready
:CHECK_SERVER
curl -s http://127.0.0.1:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 2 /nobreak >nul
    goto CHECK_SERVER
)

cls
echo.
echo  ========================================
echo   AETHER AI IS RUNNING!
echo  ========================================
echo.
echo   Server: http://127.0.0.1:8000
echo   Docs:   http://127.0.0.1:8000/docs
echo.
echo  ========================================
echo   TESTING FEATURES...
echo  ========================================
echo.

REM Test OpenClaw
echo  [1/2] Testing OpenClaw (Web Scraping)...
python quick-openclaw-test.py 2>nul
echo.

REM Test AI Chat
echo  [2/2] Testing AI Chat (Groq)...
python test-groq-chat.py 2>nul
echo.

echo  ========================================
echo   ALL TESTS COMPLETE!
echo  ========================================
echo.
echo  Server is running in background.
echo.
echo  What do you want to do?
echo.
echo   [1] Chat with Aether AI
echo   [2] Open API Docs in Browser
echo   [3] Show Server Status
echo   [4] Stop Server and Exit
echo.

set /p choice="  Your choice (1-4): "

if "%choice%"=="1" goto CHAT
if "%choice%"=="2" goto DOCS
if "%choice%"=="3" goto STATUS
if "%choice%"=="4" goto STOP

:CHAT
cls
echo.
echo  ========================================
echo   CHAT WITH AETHER AI
echo  ========================================
echo.
python chat-with-aether.py
goto MENU2

:DOCS
start http://127.0.0.1:8000/docs
echo.
echo  Browser opened!
timeout /t 2 /nobreak >nul
goto MENU2

:STATUS
cls
echo.
echo  ========================================
echo   SERVER STATUS
echo  ========================================
echo.
curl -s http://127.0.0.1:8000/health
echo.
echo.
curl -s http://127.0.0.1:8000/api/v1/chat/providers
echo.
echo.
pause
goto MENU2

:MENU2
cls
echo.
echo  ========================================
echo   AETHER AI - RUNNING
echo  ========================================
echo.
echo   [1] Chat Again
echo   [2] Open API Docs
echo   [3] Check Status
echo   [4] Stop Server and Exit
echo.
set /p choice2="  Your choice (1-4): "

if "%choice2%"=="1" goto CHAT
if "%choice2%"=="2" goto DOCS
if "%choice2%"=="3" goto STATUS
if "%choice2%"=="4" goto STOP
goto MENU2

:STOP
echo.
echo  Stopping server...
taskkill /F /IM python.exe >nul 2>&1
echo  Server stopped.
echo.
timeout /t 2 /nobreak >nul
exit
