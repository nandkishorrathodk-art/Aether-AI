@echo off
echo ========================================
echo Starting Aether AI UI
echo ========================================
echo.

cd /d "%~dp0"

REM Check if build exists
if not exist "build\index.html" (
    echo [!] Build folder not found. Building React app...
    echo [1/2] Installing dependencies...
    call npm install
    
    echo [2/2] Building production build...
    call npm run build
    
    if errorlevel 1 (
        echo.
        echo [ERROR] Build failed. Check errors above.
        pause
        exit /b 1
    )
)

echo.
echo [SUCCESS] Starting Electron app...
echo.

npm start

pause
