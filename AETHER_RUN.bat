@echo off
title Aether AI v3.0 Launcher
color 0B

echo.
echo ================================================================
echo          AETHER AI v3.0 - FLOATING ORB
echo ================================================================
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check venv
if not exist "venv\Scripts\python.exe" (
    echo [X] Virtual environment missing!
    echo.
    echo Please run: install.bat first
    echo.
    pause
    exit /b 1
)

echo [1/2] Starting Backend Server...
start "Aether Backend" cmd /k "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"
echo       [OK] Backend starting...
echo.

echo [2/2] Starting Floating Orb...
echo       Waiting 90 seconds for backend...
echo       (Loading 43 AI components takes time)
ping 127.0.0.1 -n 91 >nul
cd ui
start "Aether Orb" cmd /k "npm run dev"
cd ..
echo       [OK] Frontend starting...
echo.

echo.
echo ================================================================
echo   [OK] AETHER STARTED!
echo.
echo   Backend API: http://localhost:8000/docs
echo   Frontend: http://localhost:3000
echo   Floating Orb: Will appear after backend is ready
echo.
echo   To stop: Close both CMD windows or run STOP_AETHER.bat
echo ================================================================
echo.
pause
