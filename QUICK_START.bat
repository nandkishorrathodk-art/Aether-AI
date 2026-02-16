@echo off
chcp 65001 >nul
title 🚀 Aether AI - Quick Launcher
color 0B

cls
echo.
echo  ╔══════════════════════════════════════════════════════════╗
echo  ║          🤖 AETHER AI - QUICK START LAUNCHER 🤖          ║
echo  ╚══════════════════════════════════════════════════════════╝
echo.
echo  ⚡ Starting both Backend and Frontend in one click...
echo.

REM Backend
echo  [1/2] Starting Backend API Server...
start "Aether Backend" /MIN cmd /k "cd /d %~dp0 && venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"

REM Wait a bit
timeout /t 3 /nobreak >nul

REM Frontend
echo  [2/2] Starting Electron Frontend...
start "Aether Frontend" cmd /k "cd /d %~dp0\ui && npm run dev"

echo.
echo  ✅ Aether AI is starting up!
echo.
echo  📊 Backend: http://localhost:8000
echo  💻 Frontend: Floating window will appear
echo  🎤 Voice: Press Ctrl+Space anywhere
echo.
echo  This window will close in 3 seconds...
timeout /t 3 >nul
exit
