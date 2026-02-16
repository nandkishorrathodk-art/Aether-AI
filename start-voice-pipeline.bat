@echo off
REM Start Aether AI Voice Pipeline
REM End-to-End Voice Interaction: Wake Word → STT → LLM → TTS

echo ============================================================
echo   AETHER AI - Voice Pipeline
echo ============================================================
echo.

REM Activate virtual environment
if exist "venv\Scripts\activate.bat" (
    echo [1/2] Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo ERROR: Virtual environment not found!
    echo Please run setup.bat first to create the environment.
    pause
    exit /b 1
)

echo [2/2] Starting voice pipeline...
echo.
echo ============================================================
echo   Voice Pipeline is starting...
echo   Say 'hey aether' to activate!
echo   Press Ctrl+C to stop
echo ============================================================
echo.

python src\main.py

pause
