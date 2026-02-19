@echo off
chcp 65001 >nul
title Aether AI v3.0 - GOD-TIER LAUNCHER
color 0B

echo.
echo ════════════════════════════════════════════════════════════════
echo          🚀 AETHER AI v3.0 - GOD-TIER AUTONOMY 🚀
echo ════════════════════════════════════════════════════════════════
echo.
echo   DO ANYTHING MODE - FULL AUTONOMOUS SYSTEM
echo.
echo ════════════════════════════════════════════════════════════════
echo.

REM Check if virtual environment exists
if not exist "venv\Scripts\python.exe" (
    echo ❌ Virtual environment not found!
    echo    Please run install.bat first
    echo.
    pause
    exit /b 1
)

echo [1/4] 🔧 Activating Python virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
)
echo       ✅ Virtual environment activated
echo.

echo [2/4] 🌐 Starting FastAPI Backend (v3.0)...
echo       ├─ OmniTask Handler: Ready for ANYTHING
echo       ├─ Predictive Agent: Forecasting needs
echo       ├─ Empathy Engine: Human-like care
echo       ├─ Autonomous Brain: FULL GOD MODE
echo       ├─ Self-Coder: Auto improvement
echo       ├─ Bug Bounty Engine: Auto hunting
echo       ├─ Running on: http://localhost:8000
echo       └─ Starting in background...
start "Aether v3.0 Backend" /MIN cmd /k "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"

REM Wait for backend to initialize
echo       └─ Waiting for backend initialization...
timeout /t 8 /nobreak >nul

REM Check if backend is running
curl -s http://localhost:8000/api/v1/v3/status >nul 2>&1
if errorlevel 1 (
    echo       ⚠️  Backend starting... (may take a few more seconds)
) else (
    echo       ✅ Backend ready!
)
echo.

echo [3/4] 🎨 Starting React Frontend + Electron...
echo       ├─ Jarvis-style dashboard
echo       ├─ v3.0 Control Panel
echo       ├─ Live monitoring
echo       ├─ Running on: http://localhost:3000
echo       └─ Launching...
cd ui
if not exist "node_modules" (
    echo       ⚠️  Frontend dependencies missing!
    echo       ⚠️  Running 'npm install'...
    cmd /c "npm install"
)
echo       └─ Starting React + Electron (Dev Mode)...
start "Aether v3.0 Frontend" cmd /k "npm run dev"
cd ..
timeout /t 8 /nobreak >nul
echo       ✅ Frontend launched!
echo.

echo [4/4] 📋 System Status Check...
timeout /t 3 /nobreak >nul

REM Check backend again
curl -s http://localhost:8000/api/v1/v3/status >nul 2>&1
if errorlevel 1 (
    echo       ⚠️  Backend: Starting...
) else (
    echo       ✅ Backend: ONLINE
)

REM Check if React dev server is starting
netstat -an | findstr ":3000" >nul 2>&1
if errorlevel 1 (
    echo       ⚠️  Frontend: Starting...
) else (
    echo       ✅ Frontend: ONLINE
)
echo.

echo ════════════════════════════════════════════════════════════════
echo ✨ AETHER AI v3.0 STARTED SUCCESSFULLY! ✨
echo ════════════════════════════════════════════════════════════════
echo.
echo 🌐 ENDPOINTS:
echo    └─ Backend API:  http://localhost:8000
echo    └─ API Docs:     http://localhost:8000/docs
echo    └─ v3.0 Status:  http://localhost:8000/api/v1/v3/status
echo    └─ Frontend UI:  http://localhost:3000
echo.
echo 🔥 v3.0 GOD-TIER FEATURES:
echo    ├─ 🎯 OmniTask: Handles ANYTHING (even with no input)
echo    ├─ 🧠 Predictive Agent: ML-powered need forecasting
echo    ├─ ❤️  Empathy Engine: Human-like emotional intelligence
echo    ├─ 🤖 Autonomous Brain: Full god-mode autonomy
echo    ├─ 👁️  Vision System: Screen understanding
echo    ├─ 💻 Self-Coder: Auto code improvement
echo    ├─ 🛡️  Bug Bounty: Auto vulnerability hunting
echo    ├─ ⚡ NPU Ready: Hardware acceleration support
echo    └─ 🔄 Always-On: Windows Service mode
echo.
echo 🎮 QUICK TESTS:
echo    └─ Test v3.0: curl http://localhost:8000/api/v1/v3/status
echo    └─ OmniTask:  curl http://localhost:8000/api/v1/v3/omni
echo    └─ Predict:   curl http://localhost:8000/api/v1/v3/predict
echo.
echo 🛑 TO STOP AETHER:
echo    └─ Close this window
echo    └─ Or close backend/frontend windows
echo    └─ Or press Ctrl+C in terminal windows
echo.
echo ════════════════════════════════════════════════════════════════
echo.

choice /C YN /N /M "Open API documentation in browser? (Y/N): "
if errorlevel 2 goto skip_browser
if errorlevel 1 (
    echo Opening browser...
    start http://localhost:8000/docs
    timeout /t 2 /nobreak >nul
)

:skip_browser
echo.
echo ════════════════════════════════════════════════════════════════
echo ✨ Aether AI v3.0 is now fully operational!
echo ════════════════════════════════════════════════════════════════
echo.
echo 💡 TIP: Check v3.0 status at http://localhost:8000/api/v1/v3/status
echo.
echo Keeping this window open for monitoring...
echo Type "status" to check system, or "help" for commands
echo.

REM Keep window open with basic command loop
:loop
set /p cmd="Aether v3.0> "

if /i "%cmd%"=="status" (
    echo.
    echo Checking v3.0 system status...
    curl -s http://localhost:8000/api/v1/v3/status
    echo.
    echo Frontend: http://localhost:3000
    netstat -an | findstr ":3000"
    echo.
    goto loop
)

if /i "%cmd%"=="help" (
    echo.
    echo Available commands:
    echo   status  - Check v3.0 system status
    echo   api     - Open API docs
    echo   ui      - Open frontend
    echo   test    - Test v3.0 features
    echo   exit    - Exit monitor
    echo   help    - Show this help
    echo.
    goto loop
)

if /i "%cmd%"=="api" (
    start http://localhost:8000/docs
    goto loop
)

if /i "%cmd%"=="ui" (
    start http://localhost:3000
    goto loop
)

if /i "%cmd%"=="test" (
    echo.
    echo Testing v3.0 features...
    echo.
    echo === v3.0 Status ===
    curl -s http://localhost:8000/api/v1/v3/status
    echo.
    goto loop
)

if /i "%cmd%"=="exit" (
    echo Goodbye!
    exit /b 0
)

if not "%cmd%"=="" (
    echo Unknown command: %cmd%
    echo Type "help" for available commands
)

goto loop
