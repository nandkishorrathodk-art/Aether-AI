@echo off
chcp 65001 >nul
title Test Voice Greeting
color 0B

echo.
echo ════════════════════════════════════════════════════════════════
echo         🎤 Testing Aether Voice Greeting 🎤
echo ════════════════════════════════════════════════════════════════
echo.

echo [1] Checking if backend is running...
curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel%==0 (
    echo ✅ Backend is running!
) else (
    echo ❌ Backend not running. Starting...
    start /MIN "Aether-Backend" cmd /c "cd /d %~dp0 && venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"
    echo    Waiting 10 seconds for backend to start...
    timeout /t 10 /nobreak >nul
)

echo.
echo [2] Testing TTS directly...
curl -X POST http://localhost:8000/api/v1/voice/speak ^
  -H "Content-Type: application/json" ^
  -d "{\"text\":\"Hello sir, at your service!\",\"voice\":\"male\",\"play\":true}"

echo.
echo.
echo [3] Testing complete!
echo.
echo If you heard "Hello sir, at your service!" then TTS is working!
echo.
echo Now starting full app with auto-greeting...
timeout /t 3 /nobreak >nul

call AETHER_START.bat
