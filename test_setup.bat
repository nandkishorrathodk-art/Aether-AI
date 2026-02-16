@echo off
echo ====================================
echo Aether AI - Setup Verification
echo ====================================
echo.

REM Activate virtual environment
if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
) else (
    echo Virtual environment not found
    echo Run: python -m venv venv
    pause
    exit /b 1
)

python scripts/setup.py

echo.
pause
