@echo off
echo Restarting Aether AI Server with Voice Fix...
echo.

echo Stopping current server...
taskkill /F /IM python.exe 2>nul

echo.
echo Starting server...
cd /d "C:\Users\nandk\.zenflow\worktrees\aether-00f9\aether-ai-repo"
venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

pause
