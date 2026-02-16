@echo off
:: Test Bug Bounty Automation Features

title Aether AI - Bug Bounty Test Suite

echo ============================================
echo    Aether AI Bug Bounty Test Suite
echo ============================================
echo.

:: Activate virtual environment
echo Activating Python environment...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo ERROR: Failed to activate virtual environment
    echo Run install.bat first
    pause
    exit /b 1
)

:: Run test suite
echo.
echo Running bug bounty automation tests...
echo.
python scripts\test_bugbounty.py

echo.
echo ============================================
echo Test suite completed!
echo ============================================
echo.
echo For full documentation:
echo   docs\BUGBOUNTY_AUTOMATION.md
echo.

pause
