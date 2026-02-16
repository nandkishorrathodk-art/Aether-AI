@echo off
title Aether AI - GO!
cls

echo.
echo  Starting Aether AI...
echo.

cd /d "%~dp0"

REM Quick install check
if not exist "venv\Scripts\activate.bat" (
    echo  Installing...
    call install.bat >nul 2>&1
)

call venv\Scripts\activate.bat

REM Kill old servers
taskkill /F /IM python.exe >nul 2>&1

REM Start server background
start /MIN python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

REM Wait
timeout /t 5 /nobreak >nul

REM Test
curl -s http://127.0.0.1:8000/health >nul 2>&1
if %errorlevel%==0 (
    echo  Server Ready!
    echo.
    python chat-with-aether.py
) else (
    echo  Server failed to start!
    pause
)

REM Cleanup
taskkill /F /IM python.exe >nul 2>&1
