@echo off
setlocal enabledelayedexpansion

:: Aether AI Installer Build Script
:: Creates Windows installer and portable executable

title Building Aether AI Installer

echo ============================================
echo    Aether AI Installer Build Script
echo    Version 0.1.0
echo ============================================
echo.

:: Check if running from project root
if not exist "ui\package.json" (
    echo ERROR: Must run from project root directory
    echo Current directory: %CD%
    pause
    exit /b 1
)

:: Check Node.js
echo [1/6] Checking Node.js installation...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js not found
    echo Install from: https://nodejs.org/
    pause
    exit /b 1
)
echo Node.js found!
echo.

:: Install dependencies if needed
echo [2/6] Checking npm dependencies...
if not exist "ui\node_modules\electron-builder" (
    echo Installing electron-builder...
    cd ui
    call npm install electron-builder --save-dev
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install electron-builder
        cd ..
        pause
        exit /b 1
    )
    cd ..
)
echo Dependencies ready!
echo.

:: Build React app
echo [3/6] Building React application...
cd ui
call npm run build
if %errorlevel% neq 0 (
    echo ERROR: Failed to build React app
    cd ..
    pause
    exit /b 1
)
cd ..
echo React build complete!
echo.

:: Check for icon file
echo [4/6] Checking assets...
if not exist "ui\assets\icon.ico" (
    echo WARNING: Icon file not found at ui\assets\icon.ico
    echo Creating placeholder icon directory...
    mkdir "ui\assets" 2>nul
    echo.
    echo Please add icon.ico to ui\assets\ and run this script again
    echo Or continue without icon (installer will use default)
    echo.
    choice /C YN /M "Continue without icon"
    if errorlevel 2 (
        echo Build cancelled
        pause
        exit /b 1
    )
)
echo Assets ready!
echo.

:: Clean previous builds
echo [5/6] Cleaning previous builds...
if exist "ui\dist" (
    rmdir /S /Q "ui\dist"
    echo Previous builds removed
)
echo.

:: Build installer
echo [6/6] Building Windows installer...
echo This may take 5-10 minutes...
echo.

cd ui
call npm run package
set BUILD_RESULT=%errorlevel%
cd ..

if %BUILD_RESULT% neq 0 (
    echo.
    echo ============================================
    echo    BUILD FAILED
    echo ============================================
    echo.
    echo Check the error messages above for details.
    echo.
    echo Common issues:
    echo   - Missing icon file: Add icon.ico to ui\assets\
    echo   - Node memory limit: Increase with NODE_OPTIONS=--max-old-space-size=4096
    echo   - Antivirus blocking: Temporarily disable or add exception
    echo.
    pause
    exit /b 1
)

:: Verify build output
echo.
echo ============================================
echo    BUILD COMPLETE
echo ============================================
echo.

if exist "ui\dist\Aether AI Setup 0.1.0.exe" (
    echo ✓ NSIS Installer created:
    echo   ui\dist\Aether AI Setup 0.1.0.exe
    
    for %%A in ("ui\dist\Aether AI Setup 0.1.0.exe") do (
        set SIZE=%%~zA
        set /a SIZE_MB=!SIZE! / 1048576
        echo   Size: !SIZE_MB! MB
    )
    echo.
) else (
    echo WARNING: NSIS installer not found
)

if exist "ui\dist\AetherAI-0.1.0-portable.exe" (
    echo ✓ Portable executable created:
    echo   ui\dist\AetherAI-0.1.0-portable.exe
    
    for %%A in ("ui\dist\AetherAI-0.1.0-portable.exe") do (
        set SIZE=%%~zA
        set /a SIZE_MB=!SIZE! / 1048576
        echo   Size: !SIZE_MB! MB
    )
    echo.
) else (
    echo WARNING: Portable executable not found
)

:: List all build artifacts
echo Build artifacts:
dir /B "ui\dist\*.exe" 2>nul
dir /B "ui\dist\*.yml" 2>nul
echo.

:: Create release folder
echo Creating release folder...
set RELEASE_FOLDER=Aether-AI-v0.1.0-Release
if exist "%RELEASE_FOLDER%" (
    rmdir /S /Q "%RELEASE_FOLDER%"
)
mkdir "%RELEASE_FOLDER%"

:: Copy installers
if exist "ui\dist\Aether AI Setup 0.1.0.exe" (
    copy "ui\dist\Aether AI Setup 0.1.0.exe" "%RELEASE_FOLDER%\"
)

if exist "ui\dist\AetherAI-0.1.0-portable.exe" (
    copy "ui\dist\AetherAI-0.1.0-portable.exe" "%RELEASE_FOLDER%\"
)

:: Copy documentation
copy "README.md" "%RELEASE_FOLDER%\"
copy "QUICKSTART.md" "%RELEASE_FOLDER%\"
copy "CHANGELOG.md" "%RELEASE_FOLDER%\"
copy "LICENSE" "%RELEASE_FOLDER%\"

:: Create installation instructions
(
    echo # Aether AI v0.1.0 Installation
    echo.
    echo ## Installation Options
    echo.
    echo ### Option 1: NSIS Installer ^(Recommended^)
    echo 1. Run "Aether AI Setup 0.1.0.exe"
    echo 2. Follow installation wizard
    echo 3. Launch from desktop shortcut
    echo.
    echo ### Option 2: Portable Version
    echo 1. Run "AetherAI-0.1.0-portable.exe"
    echo 2. No installation required
    echo 3. All data stored in program directory
    echo.
    echo ## Requirements
    echo - Windows 10/11 ^(64-bit^)
    echo - 8-16GB RAM
    echo - 256GB SSD
    echo - Internet connection
    echo.
    echo ## First Time Setup
    echo 1. Add API keys to .env file
    echo 2. See QUICKSTART.md for detailed instructions
    echo.
    echo ## Documentation
    echo - README.md - Overview and features
    echo - QUICKSTART.md - Getting started guide
    echo - CHANGELOG.md - Version history
    echo.
    echo ## Support
    echo - GitHub Issues: https://github.com/aether-ai/aether-ai/issues
    echo - Documentation: See included files
) > "%RELEASE_FOLDER%\INSTALLATION.md"

echo Release folder created: %RELEASE_FOLDER%\
echo.

:: Summary
echo ============================================
echo    Next Steps
echo ============================================
echo.
echo 1. Test installers on clean Windows machine
echo    - Try both NSIS and portable versions
echo    - Verify all features work
echo.
echo 2. Create GitHub release
echo    - Tag: v0.1.0
echo    - Upload files from %RELEASE_FOLDER%\
echo    - Add release notes from CHANGELOG.md
echo.
echo 3. Distribution
echo    - Share download links
echo    - Update documentation
echo    - Monitor user feedback
echo.
echo Build artifacts: %RELEASE_FOLDER%\
echo.
echo Open release folder?
choice /C YN /M "Open folder"
if errorlevel 2 (
    echo.
    echo Build complete!
) else (
    explorer "%CD%\%RELEASE_FOLDER%"
)

echo.
pause
