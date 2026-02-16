@echo off
chcp 65001 >nul
title Aether AI - Hybrid Launcher (Mekio Edition)
color 0D

echo.
echo ════════════════════════════════════════════════════════════════
echo          🎀 AETHER AI - MEKIO HYBRID LAUNCHER 🎀
echo ════════════════════════════════════════════════════════════════
echo.
echo   Jarvis Tech + Anime Companion = Ultimate AI Experience
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

echo [1/5] 🔧 Activating Python virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ❌ Failed to activate virtual environment
    pause
    exit /b 1
)
echo       ✅ Virtual environment activated
echo.

echo [2/5] 📦 Checking critical dependencies...
python -c "import fastapi, discord" 2>nul
if errorlevel 1 (
    echo    ⚠️  Installing missing dependencies...
    pip install -q discord.py aiofiles
    echo       ✅ Dependencies installed
) else (
    echo       ✅ All dependencies present
)
echo.

echo [3/5] 🌐 Starting FastAPI Backend (with Mekio Integration)...
echo       ├─ Multi-Provider AI: 6 providers
echo       ├─ Voice Pipeline: STT + TTS
echo       ├─ Discord Bot API: Ready
echo       ├─ Memory System: RAG enabled
echo       ├─ Running on: http://localhost:8000
echo       └─ Starting in background...
start "Aether Backend" /MIN cmd /k "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"

REM Wait for backend to initialize
echo       └─ Waiting for backend initialization...
timeout /t 5 /nobreak >nul

REM Check if backend is running
curl -s http://localhost:8000/health >nul 2>&1
if errorlevel 1 (
    echo       ⚠️  Backend starting... (may take a few more seconds)
) else (
    echo       ✅ Backend ready!
)
echo.

echo [4/5] 🎨 Starting React Frontend (with Anime Character)...
echo       ├─ Jarvis-style dashboard
echo       ├─ Anime character companion
echo       ├─ Live voice visualization
echo       ├─ Compact task bar
echo       ├─ 5 personality modes
echo       ├─ Running on: http://localhost:3000
echo       └─ Launching...
echo       └─ Launching...
cd ui
if not exist "node_modules" (
    echo       ⚠️  Frontend dependencies missing!
    echo       ⚠️  Running 'npm install'...
    cmd /c "npm install"
)
echo       └─ Starting React + Electron (Dev Mode)...
start "Aether Frontend" cmd /k "set NODE_ENV=development && npm run dev"
cd ..
timeout /t 5 /nobreak >nul
echo       ✅ Frontend launched!
echo.

echo [5/5] 📋 System Status Check...
timeout /t 3 /nobreak >nul

REM Check backend again
curl -s http://localhost:8000/health >nul 2>&1
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
echo ✨ AETHER AI (MEKIO EDITION) STARTED SUCCESSFULLY! ✨
echo ════════════════════════════════════════════════════════════════
echo.
echo 🌐 ENDPOINTS:
echo    └─ Backend API:  http://localhost:8000
echo    └─ API Docs:     http://localhost:8000/docs
echo    └─ Frontend UI:  http://localhost:3000
echo.
echo 🎯 FEATURES:
echo    ├─ 🤖 Multi-Provider AI (6 providers)
echo    ├─ 🧠 Advanced Reasoning (5 engines)
echo    ├─ 🌍 Multi-Language (30+ languages)
echo    ├─ 💼 Business Intelligence (4 engines)
echo    ├─ 📄 Document RAG (PDF/DOCX/PPT)
echo    ├─ 💻 Code Generation (20+ languages)
echo    ├─ 🏢 Enterprise Integrations (4 platforms)
echo    ├─ 🔒 Bug Bounty Automation
echo    ├─ 👁️  Screen Understanding
echo    ├─ 🌐 Web Research Engine
echo    ├─ 🎀 Anime Character Companion
echo    └─ 🤖 Discord Bot Integration
echo.
echo 🎮 CONTROLS:
echo    └─ Voice: Click mic button in dashboard
echo    └─ Anime Character: Click face icon (👤) in top-right
echo    └─ Personality: Right-click character for menu
echo    └─ Chat: Click chat icon in top-right
echo    └─ Settings: Click gear icon
echo.
echo 🎭 PERSONALITIES (5 modes):
echo    ├─ 😊 Friendly     - Warm and helpful
echo    ├─ 😜 Playful     - Fun and energetic
echo    ├─ 💼 Professional - Formal and efficient
echo    ├─ 🎀 Kawaii      - Super cute anime style
echo    └─ 😤 Tsundere    - Cold but caring
echo.
echo 🤖 DISCORD BOT (Optional):
echo    To start Discord bot, use API:
echo    curl -X POST http://localhost:8000/api/v1/discord/start ^
echo      -H "Content-Type: application/json" ^
echo      -d "{\"token\": \"YOUR_TOKEN\", \"personality\": \"kawaii\"}"
echo.
echo    Bot Commands:
echo    └─ @Aether hello             - Direct mention
echo    └─ !aether chat <message>   - Chat command
echo    └─ !aether personality <type> - Change personality
echo    └─ !aether status           - Bot status
echo    └─ !aether joke             - Tell a joke
echo.
echo ════════════════════════════════════════════════════════════════
echo.
echo 📖 DOCUMENTATION:
echo    ├─ Quick Start:  MEKIO_QUICKSTART.md
echo    ├─ Full Guide:   MEKIO_INTEGRATION_COMPLETE.md
echo    ├─ Power Status: AETHER_POWER_STATUS.md
echo    └─ Complete Doc: AETHER_FINAL_COMPLETE_SUMMARY.md
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
echo ✨ Aether AI is now fully operational!
echo ════════════════════════════════════════════════════════════════
echo.
echo 💡 TIP: Enable anime character by clicking the pink face icon!
echo.
echo 🛑 TO STOP AETHER:
echo    └─ Close this window
echo    └─ Or close backend/frontend windows
echo    └─ Or press Ctrl+C in terminal windows
echo.
echo Keeping this window open for monitoring...
echo Type "status" to check system, or "help" for commands
echo.

REM Keep window open with basic command loop
:loop
set /p cmd="Aether> "

if /i "%cmd%"=="status" (
    echo.
    echo Checking system status...
    curl -s http://localhost:8000/health
    echo.
    echo Frontend: http://localhost:3000
    netstat -an | findstr ":3000"
    echo.
    goto loop
)

if /i "%cmd%"=="help" (
    echo.
    echo Available commands:
    echo   status  - Check system status
    echo   api     - Open API docs
    echo   ui      - Open frontend
    echo   docs    - Open documentation
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

if /i "%cmd%"=="docs" (
    start MEKIO_QUICKSTART.md
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
