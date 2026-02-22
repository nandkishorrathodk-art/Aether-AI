@echo off
echo ===================================================
echo    AETHER AI VOICE FIX - RESTART SERVER
echo ===================================================
echo.

echo Stopping any existing Python processes...
taskkill /F /IM python.exe 2>nul
timeout /t 2 >nul

echo.
echo Starting Aether AI Server with Voice Fix...
cd /d "C:\Users\nandk\.zenflow\worktrees\aether-00f9\aether-ai-repo"

echo.
echo Server starting... Voice echo should be FIXED now!
echo ===================================================
venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

pause
