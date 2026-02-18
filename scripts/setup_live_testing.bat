@echo off
echo ========================================
echo  Aether AI - Live Testing Setup
echo  Installing Playwright and dependencies
echo ========================================
echo.

echo [1/3] Installing Python dependencies...
pip install playwright==1.41.0 aiohttp==3.9.3
if errorlevel 1 (
    echo ERROR: Failed to install Python packages
    pause
    exit /b 1
)

echo.
echo [2/3] Installing Playwright browsers...
playwright install chromium
if errorlevel 1 (
    echo ERROR: Failed to install Playwright browsers
    pause
    exit /b 1
)

echo.
echo [3/3] Installing UI dependencies...
cd ui
call npm install
if errorlevel 1 (
    echo ERROR: Failed to install UI dependencies
    cd ..
    pause
    exit /b 1
)
cd ..

echo.
echo ========================================
echo  Installation Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Start backend: python -m src.api.main
echo 2. Start frontend: cd ui ^&^& npm start
echo 3. Open v0.9.0 panel ^> Live Testing tab
echo.
echo IMPORTANT:
echo - Only test authorized targets
echo - Review SECURITY.md for ethical guidelines
echo - Respect rate limits and program scopes
echo.
pause
