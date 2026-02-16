@echo off
title Aether AI - Start and Test All Features
color 0A
cls

echo.
echo  ================================================
echo   AETHER AI - AUTOMATED START  TEST
echo  ================================================
echo.
echo   Starting server and running full test suite...
echo.
echo  ================================================
echo.

cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo  [!] Virtual environment not found!
    echo  [!] Installing...
    call install.bat
)

echo  [1/5] Stopping old servers...
taskkill /F /IM python.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo  [2/5] Activating environment...
call venv\Scripts\activate.bat

echo  [3/5] Starting Aether AI server...
start /B python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --log-level warning

echo  [4/5] Waiting for server startup...
timeout /t 15 /nobreak >nul

:WAIT_LOOP
curl -s http://127.0.0.1:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    echo       Still waiting...
    timeout /t 3 /nobreak >nul
    goto WAIT_LOOP
)

cls
echo.
echo  ================================================
echo   SERVER STARTED - RUNNING TESTS
echo  ================================================
echo.

echo  [5/5] Running comprehensive test suite...
echo.

python test-all-features.py

echo.
echo  ================================================
echo   TEST COMPLETE
echo  ================================================
echo.
echo   Server is still running at:
echo   - API: http://127.0.0.1:8000
echo   - Docs: http://127.0.0.1:8000/docs
echo   - Security: http://127.0.0.1:8000/api/v1/security
echo.
echo   Test results saved to: test-results.json
echo.
echo  ================================================
echo.

pause
