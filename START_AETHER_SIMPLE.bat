@echo off
chcp 65001 >nul
title Aether AI v3.0 - Simple Launcher
color 0B

echo ════════════════════════════════════════
echo  AETHER AI v3.0 - Simple Start
echo ════════════════════════════════════════
echo.

REM Check virtual environment
if not exist "venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found!
    echo Please run install.bat first
    pause
    exit /b 1
)

echo [1/2] Starting Backend...
call venv\Scripts\activate.bat
start "Aether Backend" /MIN cmd /k "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"
echo       Backend starting on http://localhost:8000
timeout /t 10 /nobreak >nul

echo [2/2] Starting Frontend...
cd ui
start "Aether Frontend" /MIN cmd /k "npm run dev"
cd ..
echo       Frontend starting on http://localhost:3000
timeout /t 5 /nobreak >nul

echo.
echo ════════════════════════════════════════
echo  Aether AI v3.0 Started!
echo ════════════════════════════════════════
echo.
echo  Backend:  http://localhost:8000
echo  Docs:     http://localhost:8000/docs
echo  Frontend: http://localhost:3000
echo.
echo  Press any key to check status...
pause >nul

curl -s http://localhost:8000/api/v1/v3/status
echo.
pause
