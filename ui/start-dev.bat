@echo off
echo ================================================
echo    Aether AI - Desktop Application
echo    Development Mode
echo ================================================
echo.

echo Checking Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo Node.js: OK
echo.

echo Checking dependencies...
if not exist node_modules (
    echo Installing dependencies...
    call npm install
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies!
        pause
        exit /b 1
    )
)

echo Dependencies: OK
echo.

echo Creating .env file if not exists...
if not exist .env (
    copy .env.example .env
    echo .env file created from template
)

echo.
echo ================================================
echo Starting Development Server...
echo ================================================
echo.
echo React Dev Server will start on http://localhost:3000
echo Electron app will launch automatically
echo.
echo Press Ctrl+C to stop
echo.

call npm run dev
