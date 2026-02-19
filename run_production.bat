@echo off
echo ============================================
echo  AETHER AI v3.0 - PRODUCTION MODE
echo ============================================
echo.
echo Starting Aether AI in production mode...
echo Server will run on http://localhost:8000
echo Using 4 worker processes
echo Press Ctrl+C to stop
echo.

cd /d "%~dp0"

uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 4

pause
