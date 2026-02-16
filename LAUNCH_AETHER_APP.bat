@echo off
title Aether AI Launcher
color 0B

cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║          AETHER AI - VOICE ASSISTANT                 ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

REM Kill any existing processes
echo [1/4] Cleaning up...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq Aether-Backend*" 2>nul
taskkill /F /IM node.exe /FI "WINDOWTITLE eq Aether-Frontend*" 2>nul
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000" 2^>nul') do taskkill /F /PID %%a 2>nul
timeout /t 2 /nobreak >nul
echo       Done

REM Start backend
echo.
echo [2/4] Starting Backend...
cd /d "%~dp0"
start /MIN "Aether-Backend" cmd /c "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"
timeout /t 5 /nobreak >nul
echo       Done

REM Start frontend
echo.
echo [3/4] Starting Voice UI...
cd ui
start "Aether-Frontend" cmd /c "npm start"
cd ..
timeout /t 2 /nobreak >nul
echo       Done

echo.
echo [4/4] Ready!
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║              AETHER AI IS RUNNING!                   ║
echo  ║                                                      ║
echo  ║  Backend:  http://localhost:8000                    ║
echo  ║  Frontend: Opening...                               ║
echo  ║                                                      ║
echo  ║  Say "Hello" to activate voice!                     ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
timeout /t 3
exit
