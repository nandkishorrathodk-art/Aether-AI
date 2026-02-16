@echo off
title Aether AI - Super Powered Virtual Assistant
color 0A

echo.
echo ================================================================
echo          AETHER AI - WORLD'S MOST POWERFUL AI ASSISTANT
echo ================================================================
echo.
echo [*] Starting Aether with ALL new features...
echo.
echo New Features Active:
echo   [+] Workflow Recorder
echo   [+] 22 Workflow Templates
echo   [+] Smart Browser Automation (10x more powerful than Vy!)
echo   [+] Puppeteer Controller
echo   [+] 183+ API Endpoints
echo   [+] Voice Control
echo   [+] Memory System
echo   [+] 8 AI Providers
echo   [+] Bug Bounty Automation
echo.
echo ================================================================
echo.

REM Kill any existing backend on port 8000
echo [*] Stopping any existing Aether instances...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8000') do taskkill /F /PID %%a >nul 2>&1
timeout /t 2 /nobreak >nul

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Start backend
echo [*] Starting FastAPI Backend...
start "Aether Backend" /MIN python -m src.api.main

REM Wait for backend to start (takes ~15 seconds to load all components)
echo [*] Waiting for backend to initialize (15 seconds)...
timeout /t 15 /nobreak >nul

REM Test backend
echo [*] Testing backend...
curl -s http://localhost:8000/health >nul
if %errorlevel% equ 0 (
    echo [OK] Backend is running!
) else (
    echo [ERROR] Backend failed to start
    pause
    exit /b 1
)

REM Show status
echo.
echo ================================================================
echo                    AETHER IS NOW RUNNING!
echo ================================================================
echo.
echo Backend:     http://localhost:8000
echo API Docs:    http://localhost:8000/docs
echo Health:      http://localhost:8000/health
echo.
echo Workflow API:
echo   - Templates:  http://localhost:8000/api/v1/workflows/templates
echo   - Stats:      http://localhost:8000/api/v1/workflows/stats
echo.
echo Press Ctrl+C to stop
echo.
echo ================================================================
echo.

REM Keep window open
pause
