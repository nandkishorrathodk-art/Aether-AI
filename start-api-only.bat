@echo off
echo ========================================
echo Starting Aether AI - API Server Only
echo ========================================
echo.

cd /d "%~dp0"

echo [1/2] Activating virtual environment...
call venv\Scripts\activate.bat

echo [2/2] Starting FastAPI server (API only, no voice pipeline)...
echo.
echo API Server: http://127.0.0.1:8000
echo API Docs: http://127.0.0.1:8000/docs
echo Press Ctrl+C to stop
echo.

python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload

pause
