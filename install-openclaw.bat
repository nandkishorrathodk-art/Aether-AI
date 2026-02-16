@echo off
title OpenClaw Setup
cls

echo.
echo ========================================
echo    OPENCLAW INSTALLATION
echo ========================================
echo.

cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found!
    echo Please run install.bat first
    pause
    exit /b 1
)

echo [*] Activating environment...
call venv\Scripts\activate.bat

echo.
echo [*] Installing OpenClaw dependencies...
pip install beautifulsoup4==4.12.3 selenium==4.16.0 lxml==5.1.0 html5lib==1.1

echo.
echo [*] Installing Chrome WebDriver...
pip install webdriver-manager

echo.
echo ========================================
echo    OPENCLAW INSTALLED SUCCESSFULLY
echo ========================================
echo.
echo Chrome WebDriver will be auto-downloaded on first use
echo.
echo Test OpenClaw:
echo   python scripts\test_openclaw.py
echo.
echo API Endpoints:
echo   http://127.0.0.1:8000/api/v1/openclaw/status
echo   http://127.0.0.1:8000/api/v1/openclaw/scrape
echo.

pause
