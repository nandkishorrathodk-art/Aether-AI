@echo off
chcp 65001 >nul
title Aether Frontend Only
color 0B

echo.
echo ════════════════════════════════════════════════════════════════
echo            🎨 Starting Aether Frontend Only 🎨
echo ════════════════════════════════════════════════════════════════
echo.

echo Checking backend...
curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel%==0 (
    echo ✅ Backend is running!
) else (
    echo ❌ Backend not running! Start it first with:
    echo    venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
    echo.
    pause
    exit /b 1
)

echo.
echo Starting Electron Frontend...
cd ui
npm run dev

pause
