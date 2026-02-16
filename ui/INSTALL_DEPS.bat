@echo off
echo ========================================
echo  Installing UI Dependencies
echo ========================================
echo.
echo This will install all required packages
echo including Electron, React, and Mekio components
echo.
echo Estimated time: 2-5 minutes
echo.
pause

echo [1/3] Cleaning old installations...
if exist node_modules\electron (
    echo     Electron already installed, skipping clean
) else (
    echo     No previous installation found
)

echo [2/3] Installing dependencies...
echo     This may take a few minutes...
call npm install

if errorlevel 1 (
    echo.
    echo ========================================
    echo  ERROR: Installation failed!
    echo ========================================
    echo.
    echo Try these fixes:
    echo   1. Run: npm cache clean --force
    echo   2. Delete node_modules folder
    echo   3. Run this script again
    echo.
    pause
    exit /b 1
)

echo [3/3] Verifying installation...
if exist node_modules\electron (
    echo     ✅ Electron: Installed
) else (
    echo     ❌ Electron: MISSING
)

if exist node_modules\react (
    echo     ✅ React: Installed
) else (
    echo     ❌ React: MISSING
)

echo.
echo ========================================
echo  Installation Complete!
echo ========================================
echo.
echo You can now start Aether UI with:
echo   npm start
echo.
echo Or start full system with:
echo   ..\START-HYBRID.bat
echo.
pause
