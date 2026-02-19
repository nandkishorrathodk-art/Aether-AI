@echo off
echo ============================================
echo  AETHER AI v3.0 - DEVELOPMENT MODE
echo ============================================
echo.
echo Starting Aether AI with auto-reload...
echo Server will run on http://localhost:8000
echo Code changes will auto-reload
echo Press Ctrl+C to stop
echo.

cd /d "%~dp0"

uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

pause
