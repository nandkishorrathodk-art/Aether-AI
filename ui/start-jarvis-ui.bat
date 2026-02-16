@echo off
echo ============================================
echo   AETHER AI - JARVIS DASHBOARD
echo   Starting Jarvis-Style Interface...
echo ============================================
echo.

cd /d "%~dp0"

echo [1/2] Checking dependencies...
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies
        pause
        exit /b 1
    )
)

echo.
echo [2/2] Starting Jarvis Dashboard...
echo.
echo ============================================
echo   Dashboard will open at http://localhost:3000
echo   Features:
echo   - Live voice detection visualization
echo   - Animated Jarvis core
echo   - Real-time system stats
echo   - Compact task bar
echo ============================================
echo.

start http://localhost:3000

call npm start

pause
