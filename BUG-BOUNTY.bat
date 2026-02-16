@echo off
title Aether AI - Bug Bounty Hunter Mode
color 0C
cls

echo.
echo  ================================================
echo   AETHER AI - BUG BOUNTY HUNTER MODE
echo  ================================================
echo.
echo   Advanced Automated Penetration Testing
echo   BurpSuite + AI = Ultimate Bug Hunting
echo.
echo  ================================================
echo.

cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo  [!] Not installed. Installing now...
    call install.bat
)

call venv\Scripts\activate.bat

echo  [*] Checking BurpSuite...
echo.

REM Stop any running servers
taskkill /F /IM python.exe >nul 2>&1

echo  [*] Starting Aether AI Security Server...
echo.

start /B python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

echo  [*] Waiting for server...
timeout /t 8 /nobreak >nul

:WAIT_SERVER
curl -s http://127.0.0.1:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 2 /nobreak >nul
    goto WAIT_SERVER
)

cls
echo.
echo  ================================================
echo   AETHER AI SECURITY SERVER RUNNING!
echo  ================================================
echo.
echo   API Server:     http://127.0.0.1:8000
echo   API Docs:       http://127.0.0.1:8000/docs
echo   Security API:   http://127.0.0.1:8000/api/v1/security
echo.
echo  ================================================
echo   AVAILABLE FEATURES
echo  ================================================
echo.
echo   1. BurpSuite Integration
echo      - Automated Scanning
echo      - Intruder Attacks
echo      - Proxy History Analysis
echo.
echo   2. AI-Powered Analysis
echo      - Vulnerability Analysis
echo      - Exploit Chain Discovery
echo      - Smart Prioritization
echo.
echo   3. Bug Bounty Automation
echo      - Full Recon Pipeline
echo      - Automated Scanning
echo      - Report Generation
echo.
echo  ================================================
echo   QUICK START
echo  ================================================
echo.
echo   Option 1: Use API Docs
echo      Open: http://127.0.0.1:8000/docs
echo.
echo   Option 2: Run Test Script
echo      python test-bugbounty.py
echo.
echo   Option 3: Use CLI Tool
echo      python bugbounty-cli.py
echo.
echo  ================================================
echo.

set /p choice="Press 1 for API Docs, 2 for Test, 3 for CLI, Q to quit: "

if /i "%choice%"=="1" (
    start http://127.0.0.1:8000/docs
    echo.
    echo  [*] Opened API docs in browser
    echo.
    pause
)

if /i "%choice%"=="2" (
    if exist "test-bugbounty.py" (
        echo.
        echo  [*] Running bug bounty test...
        echo.
        python test-bugbounty.py
    ) else (
        echo.
        echo  [!] test-bugbounty.py not found
        echo.
    )
    pause
)

if /i "%choice%"=="3" (
    if exist "bugbounty-cli.py" (
        python bugbounty-cli.py
    ) else (
        echo.
        echo  [!] bugbounty-cli.py not found
        echo.
        pause
    )
)

echo.
echo  [*] Cleaning up...
taskkill /F /IM python.exe >nul 2>&1
echo.
echo  Security session ended.
