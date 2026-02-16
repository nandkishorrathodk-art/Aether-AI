@echo off
title Aether AI - Simple Start
cls

echo.
echo  =============================================
echo         AETHER AI - SIMPLE START
echo  =============================================
echo.

cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo  ERROR: Not installed!
    echo.
    echo  Please run install.bat first
    echo.
    pause
    exit /b 1
)

echo  Starting Aether AI...
echo.

call venv\Scripts\activate.bat

echo  =============================================
echo   AETHER AI RUNNING
echo  =============================================
echo.
echo   API:  http://127.0.0.1:8000
echo   Docs: http://127.0.0.1:8000/docs
echo.
echo   Press Ctrl+C to stop
echo  =============================================
echo.

python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload

pause
