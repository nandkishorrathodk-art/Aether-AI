@echo off
title Aether AI

:: Change to script directory
cd /d "%~dp0"

echo ============================================
echo    Starting Aether AI v0.1.0
echo ============================================
echo.

:: Check if virtual environment exists
if not exist "venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found
    echo.
    echo Please run install.bat first to set up Aether AI
    echo.
    pause
    exit /b 1
)

:: Check if .env file exists
if not exist ".env" (
    echo ERROR: Configuration file (.env) not found
    echo.
    echo Please run install.bat or create .env from .env.example
    echo.
    pause
    exit /b 1
)

:: Activate virtual environment
call venv\Scripts\activate.bat

:: Start FastAPI backend in background
echo [1/2] Starting backend server...
start /B cmd /c "uvicorn src.api.main:app --host 127.0.0.1 --port 8000 > logs\backend.log 2>&1"

:: Wait for backend to start
timeout /t 3 /nobreak > nul

:: Check if backend started successfully
curl -s http://localhost:8000/docs > nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Backend may not have started correctly
    echo Check logs\backend.log for details
    echo.
)

:: Start Electron frontend
echo [2/2] Starting Aether AI desktop app...
cd ui
npm start

:: Cleanup on exit
echo.
echo Shutting down Aether AI...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *uvicorn*" >nul 2>&1

cd ..
echo Aether AI stopped
pause
