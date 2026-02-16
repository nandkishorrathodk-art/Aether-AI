@echo off
title Aether AI - Quick Test
cls

echo.
echo ========================================
echo    AETHER AI - QUICK TEST
echo ========================================
echo.

cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found!
    echo.
    pause
    exit /b 1
)

echo [*] Activating environment...
call venv\Scripts\activate.bat

echo [*] Running integration tests...
echo.

python -m pytest tests\integration\test_api.py -v --tb=short

echo.
echo ========================================
echo    TEST RUN COMPLETE
echo ========================================
echo.

pause
