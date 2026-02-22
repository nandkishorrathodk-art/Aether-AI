@echo off
title Aether AI

cd /d "%~dp0"

echo ============================================
echo    Starting Aether AI v0.1.0
echo ============================================
echo.

if not exist venv\Scripts\activate.bat (
    echo ERROR: Virtual environment not found. Please run install.bat first.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat

echo [1/2] Starting backend server...
start /B venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

timeout /t 5 /nobreak > nul

echo [2/2] Starting UI...
cd ui
start npm start

echo.
echo Aether AI is running!
echo Backend: http://127.0.0.1:8000/docs
echo Frontend: http://localhost:3000
echo.
echo Close this window to stop the server (Ctrl+C).
pause
