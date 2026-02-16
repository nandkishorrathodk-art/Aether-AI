@echo off
setlocal enabledelayedexpansion

:: Aether AI Installer Test Script
:: Tests installation on a simulated clean environment

title Testing Aether AI Installation

echo ============================================
echo    Aether AI Installer Test
echo ============================================
echo.

set ERRORS=0
set WARNINGS=0
set CHECKS=0

:: Change to project root
cd /d "%~dp0"

echo Running pre-installation checks...
echo.

:: Test 1: Check if Python is available
set /a CHECKS+=1
echo [%CHECKS%] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo    [FAIL] Python not found
    set /a ERRORS+=1
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do set PYTHON_VERSION=%%v
    echo    [PASS] !PYTHON_VERSION!
)
echo.

:: Test 2: Check if Node.js is available
set /a CHECKS+=1
echo [%CHECKS%] Checking Node.js installation...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo    [FAIL] Node.js not found
    set /a ERRORS+=1
) else (
    for /f "tokens=*" %%v in ('node --version 2^>^&1') do set NODE_VERSION=%%v
    echo    [PASS] !NODE_VERSION!
)
echo.

:: Test 3: Check npm
set /a CHECKS+=1
echo [%CHECKS%] Checking npm installation...
npm --version >nul 2>&1
if %errorlevel% neq 0 (
    echo    [FAIL] npm not found
    set /a ERRORS+=1
) else (
    for /f "tokens=*" %%v in ('npm --version 2^>^&1') do set NPM_VERSION=%%v
    echo    [PASS] npm !NPM_VERSION!
)
echo.

:: Test 4: Check disk space
set /a CHECKS+=1
echo [%CHECKS%] Checking disk space...
for /f "tokens=3" %%a in ('dir /-c ^| find "bytes free"') do set FREE_SPACE=%%a
set FREE_SPACE=%FREE_SPACE:,=%
if %FREE_SPACE% lss 5000000000 (
    echo    [WARN] Less than 5GB free space
    set /a WARNINGS+=1
) else (
    set /a FREE_GB=%FREE_SPACE:~0,-9%
    echo    [PASS] !FREE_GB!GB free space available
)
echo.

:: Test 5: Check if install.bat exists
set /a CHECKS+=1
echo [%CHECKS%] Checking installer script...
if not exist "install.bat" (
    echo    [FAIL] install.bat not found
    set /a ERRORS+=1
) else (
    echo    [PASS] install.bat exists
)
echo.

:: Test 6: Check if requirements.txt exists
set /a CHECKS+=1
echo [%CHECKS%] Checking Python requirements...
if not exist "requirements.txt" (
    echo    [FAIL] requirements.txt not found
    set /a ERRORS+=1
) else (
    for /f %%i in ('type requirements.txt ^| find /c /v ""') do set REQ_COUNT=%%i
    echo    [PASS] requirements.txt exists ^(!REQ_COUNT! packages^)
)
echo.

:: Test 7: Check if ui/package.json exists
set /a CHECKS+=1
echo [%CHECKS%] Checking Node.js package manifest...
if not exist "ui\package.json" (
    echo    [FAIL] ui/package.json not found
    set /a ERRORS+=1
) else (
    echo    [PASS] ui/package.json exists
)
echo.

:: Test 8: Check if .env.example exists
set /a CHECKS+=1
echo [%CHECKS%] Checking environment template...
if not exist ".env.example" (
    echo    [FAIL] .env.example not found
    set /a ERRORS+=1
) else (
    echo    [PASS] .env.example exists
)
echo.

:: Test 9: Check project structure
set /a CHECKS+=1
echo [%CHECKS%] Checking project structure...
set MISSING_DIRS=0
if not exist "src" set /a MISSING_DIRS+=1
if not exist "ui" set /a MISSING_DIRS+=1
if not exist "tests" set /a MISSING_DIRS+=1
if not exist "scripts" set /a MISSING_DIRS+=1

if %MISSING_DIRS% gtr 0 (
    echo    [FAIL] Missing required directories
    set /a ERRORS+=1
) else (
    echo    [PASS] All required directories present
)
echo.

:: Test 10: Check documentation
set /a CHECKS+=1
echo [%CHECKS%] Checking documentation...
set MISSING_DOCS=0
if not exist "README.md" set /a MISSING_DOCS+=1
if not exist "INSTALLATION.md" set /a MISSING_DOCS+=1
if not exist "QUICKSTART.md" set /a MISSING_DOCS+=1

if %MISSING_DOCS% gtr 0 (
    echo    [WARN] Some documentation files missing
    set /a WARNINGS+=1
) else (
    echo    [PASS] Documentation complete
)
echo.

:: Test 11: Check uninstaller
set /a CHECKS+=1
echo [%CHECKS%] Checking uninstaller...
if not exist "uninstall.bat" (
    echo    [WARN] uninstall.bat not found
    set /a WARNINGS+=1
) else (
    echo    [PASS] uninstall.bat exists
)
echo.

:: Test 12: Check start script
set /a CHECKS+=1
echo [%CHECKS%] Checking start script...
if not exist "start-aether.bat" (
    echo    [WARN] start-aether.bat not found
    set /a WARNINGS+=1
) else (
    echo    [PASS] start-aether.bat exists
)
echo.

:: Test 13: Check build script
set /a CHECKS+=1
echo [%CHECKS%] Checking build script...
if not exist "build-installer.bat" (
    echo    [WARN] build-installer.bat not found
    set /a WARNINGS+=1
) else (
    echo    [PASS] build-installer.bat exists
)
echo.

:: Test 14: Check LICENSE
set /a CHECKS+=1
echo [%CHECKS%] Checking license...
if not exist "LICENSE" (
    echo    [WARN] LICENSE file not found
    set /a WARNINGS+=1
) else (
    echo    [PASS] LICENSE exists
)
echo.

:: Test 15: Check electron-builder config
set /a CHECKS+=1
echo [%CHECKS%] Checking electron-builder configuration...
findstr /C:"electron-builder" "ui\package.json" >nul 2>&1
if %errorlevel% neq 0 (
    echo    [WARN] electron-builder not configured in package.json
    set /a WARNINGS+=1
) else (
    echo    [PASS] electron-builder configured
)
echo.

:: Summary
echo ============================================
echo    Test Results
echo ============================================
echo.
echo Total Checks: %CHECKS%
echo Errors: %ERRORS%
echo Warnings: %WARNINGS%
echo.

if %ERRORS% equ 0 (
    if %WARNINGS% equ 0 (
        echo [SUCCESS] All checks passed! Installation ready.
        echo.
        echo You can now:
        echo   1. Run install.bat to install Aether AI
        echo   2. Run build-installer.bat to create distribution packages
        echo.
    ) else (
        echo [SUCCESS] All critical checks passed ^(%WARNINGS% warnings^)
        echo.
        echo Installation should work, but some optional files are missing.
        echo Review warnings above for details.
        echo.
    )
    
    echo Run installation now?
    choice /C YN /M "Start install.bat"
    if errorlevel 2 (
        echo.
        echo Test complete. Run install.bat when ready.
    ) else (
        echo.
        echo Starting installation...
        call install.bat
    )
    
    exit /b 0
) else (
    echo [FAILURE] %ERRORS% critical errors found
    echo.
    echo Please fix the following before installation:
    if not exist "install.bat" echo   - install.bat is missing
    if not exist "requirements.txt" echo   - requirements.txt is missing
    if not exist "ui\package.json" echo   - ui/package.json is missing
    if not exist ".env.example" echo   - .env.example is missing
    if not exist "src" echo   - src/ directory is missing
    if not exist "ui" echo   - ui/ directory is missing
    echo.
    pause
    exit /b 1
)
