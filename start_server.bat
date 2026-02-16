@echo off
echo ====================================
echo Aether AI - Starting API Server
echo ====================================
echo.

REM Activate virtual environment
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
    echo Virtual environment activated
) else (
    echo Warning: Virtual environment not found
    echo Run: python -m venv venv
    pause
    exit /b 1
)

echo.
echo Starting FastAPI server...
echo API: http://localhost:8000
echo Docs: http://localhost:8000/docs
echo.

uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000

pause
