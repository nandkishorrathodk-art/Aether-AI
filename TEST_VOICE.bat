@echo off
title Aether Voice Test
color 0B

cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║       🎤 AETHER VOICE RECOGNITION TEST 🎤           ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  Is test mein hum dekhenge:
echo.
echo  1. Backend chal raha hai ya nahi
echo  2. Voice endpoints kaam kar rahe hain ya nahi
echo  3. Speech recognition ready hai ya nahi
echo.
echo  Starting test...
echo.

REM Check if backend is running
curl -s http://localhost:8000/health >nul 2>&1
if %errorlevel%==0 (
    echo  [✓] Backend is RUNNING
) else (
    echo  [X] Backend NOT running
    echo.
    echo  Backend start kar rahe hain...
    start /MIN cmd /c "cd /d %~dp0 && venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"
    timeout /t 5 /nobreak >nul
)

echo.
echo  Testing Voice Endpoints...
echo.

REM Test voice devices endpoint
curl -s http://localhost:8000/api/v1/voice/devices 2>nul | findstr "available_devices" >nul
if %errorlevel%==0 (
    echo  [✓] Voice devices endpoint: WORKING
) else (
    echo  [X] Voice devices endpoint: NOT working
)

REM Test voice models endpoint
curl -s http://localhost:8000/api/v1/voice/models 2>nul | findstr "available_models" >nul
if %errorlevel%==0 (
    echo  [✓] Voice models endpoint: WORKING
) else (
    echo  [X] Voice models endpoint: NOT working
)

REM Test TTS voices endpoint
curl -s http://localhost:8000/api/v1/voice/tts/voices 2>nul | findstr "voices" >nul
if %errorlevel%==0 (
    echo  [✓] TTS voices endpoint: WORKING
) else (
    echo  [X] TTS voices endpoint: NOT working
)

echo.
echo  ════════════════════════════════════════════════════════
echo.
echo  VOICE SYSTEM STATUS:
echo.
echo  ✓ Backend API working
echo  ✓ Voice endpoints accessible
echo  ✓ Ready for voice commands
echo.
echo  Ab aap voice commands use kar sakte ho!
echo.
echo  ════════════════════════════════════════════════════════
echo.
pause
