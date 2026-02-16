@echo off
chcp 65001 >nul
title 🛑 Stop Aether AI
color 0C

echo.
echo ════════════════════════════════════════════════════════════════
echo              🛑 STOPPING AETHER AI SERVICES 🛑
echo ════════════════════════════════════════════════════════════════
echo.

echo [1/3] 🔍 Finding Aether processes...

REM Kill Python backend processes
echo [2/3] 🔴 Stopping Backend (Python/Uvicorn)...
taskkill /F /FI "WINDOWTITLE eq Aether Backend*" >nul 2>&1
taskkill /F /FI "IMAGENAME eq python.exe" /FI "WINDOWTITLE eq *uvicorn*" >nul 2>&1

REM Find and kill process using port 8000
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING') do (
    echo    └─ Killing process on port 8000 (PID: %%a)
    taskkill /F /PID %%a >nul 2>&1
)

REM Kill Electron frontend processes
echo [3/3] 🔴 Stopping Frontend (Electron/Node)...
taskkill /F /FI "WINDOWTITLE eq Aether Frontend*" >nul 2>&1
taskkill /F /IM electron.exe >nul 2>&1

echo.
echo ════════════════════════════════════════════════════════════════
echo ✅ AETHER AI STOPPED
echo ════════════════════════════════════════════════════════════════
echo.
echo All Aether processes terminated.
echo You can now start Aether again with QUICK_START.bat
echo.
pause
