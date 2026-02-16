@echo off
title Aether AI - Quick Start
cls

echo.
echo  ================================================
echo   AETHER AI - QUICK START (FIXED)
echo  ================================================
echo.
echo   This script will:
echo   1. Stop any running servers
echo   2. Start Aether AI with GROQ
echo   3. Test the chat functionality
echo.

cd /d "%~dp0"

REM Activate venv
call venv\Scripts\activate.bat

echo  [*] Stopping old servers...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *uvicorn*" >nul 2>&1

echo  [*] Starting Aether AI server...
echo.

REM Start server in background
start /B python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload

echo  [*] Waiting for server to initialize...
timeout /t 8 /nobreak >nul

REM Wait for health check
:WAIT_LOOP
curl -s http://127.0.0.1:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 2 /nobreak >nul
    goto WAIT_LOOP
)

cls
echo.
echo  ================================================
echo   AETHER AI IS RUNNING!
echo  ================================================
echo.
echo   API Server:  http://127.0.0.1:8000
echo   API Docs:    http://127.0.0.1:8000/docs
echo   OpenClaw:    http://127.0.0.1:8000/api/v1/openclaw/status
echo.
echo  ================================================
echo   TESTING AI CHAT WITH GROQ...
echo  ================================================
echo.

python test-groq-chat.py

echo.
echo  ================================================
echo   READY TO CHAT!
echo  ================================================
echo.
echo   You can now:
echo   - Run: python chat-with-aether.py
echo   - Open: http://127.0.0.1:8000/docs
echo.
echo  Press any key to launch chat interface...
pause >nul

python chat-with-aether.py

echo.
echo  [*] Cleaning up...
taskkill /F /IM python.exe >nul 2>&1
echo.
echo  Goodbye!
