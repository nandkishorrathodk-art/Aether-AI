@echo off
title Aether AI - Starting...
color 0A

echo.
echo ================================================================
echo                   STARTING AETHER AI
echo ================================================================
echo.

REM Activate venv
call venv\Scripts\activate.bat

REM Kill old instances
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *Aether Backend*" >nul 2>&1

REM Start backend
echo [*] Launching Aether Backend...
echo.
echo     This will take 15-20 seconds to load:
echo       - 8 AI Providers (OpenAI, Claude, Groq, etc.)
echo       - Conversation Engine
echo       - Bug Bounty Tools
echo       - Memory System
echo       - 183 API Endpoints
echo.
echo     Please wait...
echo.

python -m src.api.main

pause
