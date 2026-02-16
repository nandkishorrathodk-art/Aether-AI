@echo off
title Aether AI - Click and Go!
color 0B
cls

echo.
echo  ================================================
echo         AETHER AI - AUTOMATIC SETUP
echo  ================================================
echo.
echo   This will automatically:
echo   1. Check if installed
echo   2. Install if needed
echo   3. Start Aether AI
echo.
echo   Just sit back and relax!
echo  ================================================
echo.

cd /d "%~dp0"

REM Check if installed
if not exist "venv\Scripts\activate.bat" (
    echo  [*] First time? Installing Aether AI...
    echo.
    call install.bat
    echo.
    echo  ================================================
    echo   Installation Complete!
    echo  ================================================
    echo.
    timeout /t 3 /nobreak >nul
)

REM Check if OpenClaw is installed
if not exist "venv\Lib\site-packages\bs4" (
    echo  [*] Installing OpenClaw web scraping...
    echo.
    call venv\Scripts\activate.bat
    pip install beautifulsoup4 selenium lxml html5lib webdriver-manager --quiet
    echo  ✓ OpenClaw installed!
    echo.
)

REM Start the server
cls
echo.
echo  ================================================
echo         STARTING AETHER AI...
echo  ================================================
echo.

call venv\Scripts\activate.bat

echo  ✓ Environment activated
echo  ✓ Starting server...
echo.
echo  ================================================
echo   AETHER AI IS RUNNING!
echo  ================================================
echo.
echo   API:      http://127.0.0.1:8000
echo   Docs:     http://127.0.0.1:8000/docs
echo   OpenClaw: http://127.0.0.1:8000/api/v1/openclaw/status
echo.
echo   Press Ctrl+C to stop
echo  ================================================
echo.

REM Open browser in background
start http://127.0.0.1:8000/docs

python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload

echo.
echo  Server stopped.
pause
