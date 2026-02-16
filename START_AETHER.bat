@echo off
chcp 65001 >nul
title Aether AI - One-Click Launcher
color 0A

echo.
echo ════════════════════════════════════════════════════════════════
echo               🚀 AETHER AI - ONE-CLICK LAUNCHER 🚀
echo ════════════════════════════════════════════════════════════════
echo.

REM Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo ❌ Virtual environment not found!
    echo    Please run install.bat first
    pause
    exit /b 1
)

echo [1/3] 🔧 Activating virtual environment...
call venv\Scripts\activate.bat

echo [2/3] 🌐 Starting FastAPI Backend Server...
echo       └─ Running on: http://localhost:8000
start "Aether Backend" /MIN cmd /k "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"

REM Wait for backend to start
echo       └─ Waiting for server to initialize...
timeout /t 5 /nobreak >nul

echo [3/3] 🎨 Starting Electron Frontend...
echo       └─ Launching floating dashboard...
cd ui
start "Aether Frontend" cmd /k "npm run dev"
cd ..

echo.
echo ════════════════════════════════════════════════════════════════
echo ✅ AETHER AI STARTED SUCCESSFULLY!
echo ════════════════════════════════════════════════════════════════
echo.
echo 📊 Backend API: http://localhost:8000
echo 💻 Frontend UI: http://localhost:3000
echo 📚 API Docs: http://localhost:8000/docs
echo.
echo 🎤 Voice Command: Press Ctrl+Space
echo 🌐 System Tray: Look for Aether icon
echo.
echo Press any key to open browser to API docs...
pause >nul
start http://localhost:8000/docs

echo.
echo ════════════════════════════════════════════════════════════════
echo ✨ Aether AI is now running!
echo ════════════════════════════════════════════════════════════════
echo.
echo To stop Aether:
echo   - Close this window
echo   - Or close from system tray
echo   - Or press Ctrl+C in backend/frontend windows
echo.
echo Keeping this window open for monitoring...
echo.

REM Keep window open
:loop
timeout /t 60 >nul
goto loop
