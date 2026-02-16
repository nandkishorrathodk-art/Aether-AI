@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title 📦 Building Aether AI Desktop App
color 0D

cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                                                      ║
echo  ║         📦 AETHER AI APP BUILDER 📦                 ║
echo  ║                                                      ║
echo  ║    This will create a distributable Windows app     ║
echo  ║                                                      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo.

REM Check if in correct directory
if not exist "ui\package.json" (
    echo ❌ ERROR: Must run from project root
    echo    Current: %CD%
    pause
    exit /b 1
)

REM Check Node.js
echo [1/5] 🔍 Checking Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ ERROR: Node.js not installed
    echo    Download: https://nodejs.org/
    pause
    exit /b 1
)
for /f "delims=" %%i in ('node --version') do set NODE_VER=%%i
echo       ✅ Node.js %NODE_VER%

REM Check npm dependencies
echo.
echo [2/5] 📦 Checking dependencies...
cd ui
if not exist "node_modules" (
    echo       Installing dependencies... (this may take 5-10 minutes)
    call npm install
    if %errorlevel% neq 0 (
        echo ❌ ERROR: npm install failed
        cd ..
        pause
        exit /b 1
    )
)
echo       ✅ Dependencies ready

REM Build React app
echo.
echo [3/5] ⚛️  Building React production bundle...
echo       This may take 2-3 minutes...
call npm run build
if %errorlevel% neq 0 (
    echo ❌ ERROR: React build failed
    cd ..
    pause
    exit /b 1
)
echo       ✅ React bundle created

REM Create icon if missing
echo.
echo [4/5] 🎨 Checking app icon...
if not exist "assets\icon.ico" (
    echo       ⚠️  No icon found - creating placeholder
    if not exist "assets" mkdir assets
    echo       Using default Electron icon
)
echo       ✅ Icon ready

REM Build Electron app
echo.
echo [5/5] 🔨 Building Electron app...
echo       This may take 5-10 minutes...
echo       Creating Windows installer and portable executable...
echo.

call npm run build:win
set BUILD_RESULT=%errorlevel%

cd ..

if %BUILD_RESULT% neq 0 (
    echo.
    echo ❌ BUILD FAILED
    echo    Check errors above
    pause
    exit /b 1
)

REM Success message
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                                                      ║
echo  ║            ✅ BUILD SUCCESSFUL! ✅                   ║
echo  ║                                                      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  📁 Build artifacts:
echo.

REM List build files
if exist "ui\dist" (
    dir /b "ui\dist\*.exe" 2>nul
    echo.
    
    REM Show file sizes
    for %%F in ("ui\dist\*.exe") do (
        set "SIZE=%%~zF"
        set /a "SIZE_MB=!SIZE! / 1048576"
        echo     └─ %%~nxF - !SIZE_MB! MB
    )
)

echo.
echo  📂 Location: ui\dist\
echo.
echo  🎯 Ready to distribute:
echo     • Aether AI Setup.exe - Full installer
echo     • Portable executable - No install required
echo.
echo  🚀 Next steps:
echo     1. Test the installer on a clean machine
echo     2. Share with users
echo.

REM Open dist folder
choice /C YN /M "Open dist folder now"
if not errorlevel 2 (
    explorer "ui\dist"
)

echo.
pause
