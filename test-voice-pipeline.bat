@echo off
REM Test Voice Pipeline Integration
REM Runs comprehensive integration tests

echo ============================================================
echo   VOICE PIPELINE INTEGRATION TESTS
echo ============================================================
echo.

REM Activate virtual environment
if exist "venv\Scripts\activate.bat" (
    echo [1/2] Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo ERROR: Virtual environment not found!
    pause
    exit /b 1
)

echo [2/2] Running integration tests...
echo.

python scripts\test_voice_pipeline_integration.py

echo.
echo ============================================================
pause
