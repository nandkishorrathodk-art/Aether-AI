@echo off
echo ========================================
echo Starting Aether AI Backend
echo ========================================
echo.

cd /d "%~dp0"

echo [1/3] Activating virtual environment...
call venv\Scripts\activate.bat

echo [2/3] Checking dependencies...
python -c "import webrtcvad" 2>nul
if errorlevel 1 (
    echo Installing missing dependencies...
    pip install webrtcvad pyaudio openai-whisper pvporcupine tiktoken --quiet
)

echo [3/3] Starting FastAPI server...
echo.
echo Backend will be available at: http://127.0.0.1:8000
echo Press Ctrl+C to stop
echo.

python src/main.py

pause
