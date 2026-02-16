@echo off
echo ========================================
echo  AETHER v1.5 - ULTIMATE AI ASSISTANT
echo  With OpenClaw Integration
echo ========================================
echo.

REM Check if virtual environment exists
if not exist "venv\" (
    echo [ERROR] Virtual environment not found!
    echo Run install.bat first
    pause
    exit /b 1
)

REM Activate virtual environment
echo [1/4] Activating Python virtual environment...
call venv\Scripts\activate.bat

REM Check if Node.js is installed (for OpenClaw)
echo [2/4] Checking Node.js installation...
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] Node.js not found! OpenClaw features will be limited.
    echo Download from: https://nodejs.org/
) else (
    node --version
)

REM Install OpenClaw dependencies if needed
if exist "openclaw_source\" (
    echo [3/4] Setting up OpenClaw...
    cd openclaw_source
    if not exist "node_modules\" (
        echo Installing OpenClaw dependencies (first time only)...
        call pnpm install 2>nul || call npm install
        call pnpm build 2>nul || call npm run build
    )
    cd ..
) else (
    echo [WARNING] OpenClaw source not found at openclaw_source/
    echo OpenClaw features will not be available.
)

REM Start FastAPI backend
echo [4/4] Starting Aether AI backend...
echo.
echo ========================================
echo  AETHER v1.5 IS NOW RUNNING!
echo ========================================
echo.
echo  FastAPI Server: http://localhost:8000
echo  API Docs: http://localhost:8000/docs
echo.
echo  Features Available:
echo  - 20 Revolutionary AI Features
echo  - 50+ OpenClaw Skills
echo  - 15+ Messaging Platforms
echo  - Production Browser Automation
echo.
echo  Press Ctrl+C to stop
echo ========================================
echo.

python src\main.py

pause
