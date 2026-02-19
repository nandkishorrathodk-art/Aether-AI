@echo off
title Aether AI Launcher
color 0B

echo.
echo ================================================================
echo          AETHER AI v3.0 - FLOATING ORB
echo ================================================================
echo.
echo   Starting Backend and Frontend...
echo.
echo ================================================================
echo.

REM Check venv
if not exist "venv\Scripts\python.exe" (
    echo [X] Virtual environment missing! Run: install.bat
    pause
    exit /b 1
)

echo [1/2] Starting FastAPI Backend...
start "Aether Backend" cmd /k "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"
echo       [OK] Backend starting in new window
echo.

echo [2/2] Starting Floating Orb UI...
echo       Waiting 90 seconds for backend initialization...
echo       (Loading 43 AI components + models takes time)
ping 127.0.0.1 -n 91 >nul
cd ui
start "Aether Floating Orb" cmd /k "npm run dev"
cd ..
echo       [OK] Frontend starting in new window
echo.

echo.
echo ================================================================
echo   AETHER STATUS:
echo   Backend: http://localhost:8000/docs (Takes 60-90 sec to start)
echo   Frontend: http://localhost:3000
echo   Floating Orb: Will appear after backend is ready
echo.
echo   Please wait 1-2 minutes for full initialization
echo ================================================================
echo.
echo Press any key to close this launcher (processes will continue)...
pause >nul
