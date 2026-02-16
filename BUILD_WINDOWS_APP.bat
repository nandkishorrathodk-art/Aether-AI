@echo off
title Building Aether AI Windows App
color 0D

cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                                                      ║
echo  ║      💻 AETHER AI - WINDOWS APP BUILDER 💻          ║
echo  ║                                                      ║
echo  ║    PC ke liye installer banaya jayega               ║
echo  ║                                                      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

REM Check directory
if not exist "ui\package.json" (
    echo ❌ Galat directory! Project root se chalao
    pause
    exit /b 1
)

REM Check Node.js
echo [1/5] Node.js check kar rahe hain...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js nahi mila!
    echo    Install karein: https://nodejs.org/
    pause
    exit /b 1
)
echo       ✅ Node.js ready

REM Install electron-builder if not present
echo.
echo [2/5] Dependencies check kar rahe hain...
cd ui
if not exist "node_modules\electron-builder" (
    echo       electron-builder install kar rahe hain...
    call npm install electron-builder --save-dev
    if %errorlevel% neq 0 (
        echo ❌ Install fail!
        cd ..
        pause
        exit /b 1
    )
)
echo       ✅ Dependencies ready

REM Build React app
echo.
echo [3/5] React app build kar rahe hain...
echo       Thoda time lagega (2-3 minutes)...
call npm run build
if %errorlevel% neq 0 (
    echo ❌ React build fail!
    cd ..
    pause
    exit /b 1
)
echo       ✅ React build done

REM Check icon
echo.
echo [4/5] Icon check kar rahe hain...
if not exist "assets\icon.ico" (
    echo       Icon nahi mila, default use karenge
    if not exist "assets" mkdir assets
)
echo       ✅ Assets ready

REM Build Windows app
echo.
echo [5/5] Windows installer bana rahe hain...
echo       Ye 5-10 minute le sakta hai...
echo       Dhairya rakhein!
echo.

call npm run build:win
set BUILD_RESULT=%errorlevel%

cd ..

if %BUILD_RESULT% neq 0 (
    echo.
    echo ❌ BUILD FAIL HO GAYA!
    echo    Error dekhein upar
    pause
    exit /b 1
)

REM Success
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                                                      ║
echo  ║            ✅ APP BAN GAYA! ✅                       ║
echo  ║                                                      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  🎉 Aapka Windows installer ready hai!
echo.
echo  📂 Location: ui\dist\
echo.

REM Show files
if exist "ui\dist" (
    echo  📦 Files banaye gaye:
    echo.
    dir /b "ui\dist\*.exe" 2>nul
    echo.
)

echo  ✅ Aap ye kar sakte hain:
echo     1. ui\dist\ folder kholen
echo     2. "Aether AI Setup.exe" chalao
echo     3. Install karo
echo     4. Enjoy!
echo.

REM Open folder
choice /C YN /M "Folder kholein abhi"
if not errorlevel 2 (
    explorer "ui\dist"
)

echo.
echo  🎊 Badhai ho! Aapka app ready hai! 🎊
echo.
pause
