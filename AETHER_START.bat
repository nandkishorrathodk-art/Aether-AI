@echo off
title Aether AI Launcher
color 0A

cls
echo.
echo  ╔════════════════════════════════════════╗
echo  ║     🚀 AETHER AI LAUNCHER 🚀          ║
echo  ╚════════════════════════════════════════╝
echo.

REM Kill any existing processes on port 8000
echo [1] Cleaning up old processes...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *uvicorn*" >nul 2>&1
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000"') do taskkill /F /PID %%a >nul 2>&1
timeout /t 2 /nobreak >nul

REM Start backend
echo [2] Starting Backend...
start /MIN "Aether-Backend" cmd /c "cd /d %~dp0 && venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"
timeout /t 8 /nobreak >nul

REM Start frontend  
echo [3] Starting Frontend...
start "Aether-Frontend" cmd /c "cd /d %~dp0\ui && npm run dev"

echo.
echo ✅ Aether AI Started!
echo.
echo Backend: http://localhost:8000
echo Frontend: Will open automatically
echo.
echo This window will close in 3 seconds...
timeout /t 3 >nul
exit
