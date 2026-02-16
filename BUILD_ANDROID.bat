@echo off
title Building Aether AI for Android
color 0D

cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                                                      ║
echo  ║         📱 AETHER AI - ANDROID BUILDER 📱           ║
echo  ║                                                      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo.

REM Check Node.js
echo [1/6] Checking Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js not found
    echo    Install: https://nodejs.org/
    pause
    exit /b 1
)
echo       ✅ Node.js installed

REM Check Java
echo.
echo [2/6] Checking Java JDK...
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Java JDK not found
    echo    Install JDK 17: https://adoptium.net/
    pause
    exit /b 1
)
echo       ✅ Java JDK installed

REM Check Android SDK
echo.
echo [3/6] Checking Android SDK...
if not defined ANDROID_HOME (
    echo ⚠️  ANDROID_HOME not set
    echo    Set in Environment Variables to Android SDK path
    echo    Example: C:\Users\%USERNAME%\AppData\Local\Android\Sdk
    pause
    exit /b 1
)
echo       ✅ Android SDK: %ANDROID_HOME%

REM Install npm dependencies
echo.
echo [4/6] Installing dependencies...
if not exist "node_modules" (
    call npm install
    if %errorlevel% neq 0 (
        echo ❌ npm install failed
        pause
        exit /b 1
    )
)
echo       ✅ Dependencies ready

REM Clean previous build
echo.
echo [5/6] Cleaning previous builds...
cd android
call gradlew clean
cd ..
echo       ✅ Clean complete

REM Build APK
echo.
echo [6/6] Building APK...
echo       This may take 5-10 minutes...
echo.

cd android
call gradlew assembleRelease
set BUILD_RESULT=%errorlevel%
cd ..

if %BUILD_RESULT% neq 0 (
    echo.
    echo ❌ BUILD FAILED
    pause
    exit /b 1
)

REM Success
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                                                      ║
echo  ║            ✅ APK BUILD SUCCESSFUL! ✅              ║
echo  ║                                                      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  📱 APK Location:
echo     android\app\build\outputs\apk\release\app-release.apk
echo.

REM Show file size
for %%A in ("android\app\build\outputs\apk\release\app-release.apk") do (
    set SIZE=%%~zA
    set /a SIZE_MB=!SIZE! / 1048576
    echo  📦 Size: !SIZE_MB! MB
)

echo.
echo  🚀 Next steps:
echo     1. Install APK on Android device
echo     2. Enable "Install from Unknown Sources"
echo     3. Transfer APK and install
echo     4. Grant microphone permissions
echo.

REM Open folder
choice /C YN /M "Open APK folder now"
if not errorlevel 2 (
    explorer "android\app\build\outputs\apk\release"
)

echo.
pause
