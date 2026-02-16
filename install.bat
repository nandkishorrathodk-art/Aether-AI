@echo off
setlocal enabledelayedexpansion

:: Aether AI Installation Script for Windows
:: Version: 1.0.0

title Aether AI Installation

echo ============================================
echo    Aether AI Installation Wizard
echo    Version 0.1.0 MVP
echo ============================================
echo.

:: Check for Python
echo [1/8] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python 3.8 or higher from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

python --version
echo Python found!
echo.

:: Check for Node.js
echo [2/8] Checking Node.js installation...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed or not in PATH
    echo.
    echo Please install Node.js 18 or higher from:
    echo https://nodejs.org/
    pause
    exit /b 1
)

node --version
npm --version
echo Node.js and npm found!
echo.

:: Check disk space (at least 5GB free)
echo [3/8] Checking disk space...
for /f "tokens=3" %%a in ('dir /-c ^| find "bytes free"') do set FREE_SPACE=%%a
set FREE_SPACE=%FREE_SPACE:,=%
if %FREE_SPACE% lss 5000000000 (
    echo WARNING: Less than 5GB free disk space
    echo Installation may fail due to insufficient space
    echo.
    choice /C YN /M "Continue anyway"
    if errorlevel 2 exit /b 1
)
echo Sufficient disk space available
echo.

:: Create virtual environment
echo [4/8] Creating Python virtual environment...
if exist "venv" (
    echo Virtual environment already exists, skipping...
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created!
)
echo.

:: Activate virtual environment and install Python dependencies
echo [5/8] Installing Python dependencies...
echo This may take 10-15 minutes depending on your internet speed...
echo.

call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo ERROR: Failed to activate virtual environment
    pause
    exit /b 1
)

python -m pip install --upgrade pip
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install Python dependencies
    echo.
    echo Please check your internet connection and try again
    pause
    exit /b 1
)
echo Python dependencies installed!
echo.

:: Install Node.js dependencies
echo [6/8] Installing Node.js dependencies for UI...
echo This may take 5-10 minutes...
echo.

cd ui
call npm install
if %errorlevel% neq 0 (
    echo ERROR: Failed to install Node.js dependencies
    cd ..
    pause
    exit /b 1
)
cd ..
echo Node.js dependencies installed!
echo.

:: Build React app
echo [7/8] Building React application...
cd ui
call npm run build
if %errorlevel% neq 0 (
    echo ERROR: Failed to build React application
    cd ..
    pause
    exit /b 1
)
cd ..
echo React app built successfully!
echo.

:: Create .env file if it doesn't exist
echo [8/8] Setting up configuration...
if not exist ".env" (
    copy .env.example .env
    echo.
    echo IMPORTANT: Configuration file created at .env
    echo.
    echo You MUST add at least ONE AI provider API key to use Aether AI:
    echo   - OpenAI: https://platform.openai.com/api-keys
    echo   - Groq FREE: https://console.groq.com/keys
    echo   - Anthropic: https://console.anthropic.com/
    echo   - Google: https://makersuite.google.com/app/apikey
    echo.
    echo Edit the .env file with your API keys before running Aether AI
    echo.
) else (
    echo Configuration file already exists
)
echo.

:: Create desktop shortcut (optional)
echo Creating desktop shortcut...
set SCRIPT_DIR=%~dp0
set SHORTCUT_PATH=%USERPROFILE%\Desktop\Aether AI.lnk

powershell -Command "$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut('%SHORTCUT_PATH%'); $SC.TargetPath = '%SCRIPT_DIR%start-aether.bat'; $SC.WorkingDirectory = '%SCRIPT_DIR%'; $SC.IconLocation = '%SCRIPT_DIR%ui\assets\icon.ico'; $SC.Save()"

if exist "%SHORTCUT_PATH%" (
    echo Desktop shortcut created!
) else (
    echo WARNING: Could not create desktop shortcut
)
echo.

:: Create start script if it doesn't exist
if not exist "start-aether.bat" (
    (
        echo @echo off
        echo title Aether AI
        echo cd /d "%%~dp0"
        echo.
        echo echo Starting Aether AI...
        echo echo.
        echo.
        echo start /B cmd /c "venv\Scripts\activate.bat && uvicorn src.api.main:app --host 127.0.0.1 --port 8000"
        echo timeout /t 3 /nobreak ^> nul
        echo.
        echo cd ui
        echo npm start
    ) > start-aether.bat
)

echo ============================================
echo    Installation Complete!
echo ============================================
echo.
echo Next steps:
echo.
echo 1. Edit .env file and add your AI provider API keys
echo    - Run: notepad .env
echo.
echo 2. Verify installation:
echo    - Run: venv\Scripts\activate.bat
echo    - Run: python scripts\setup.py
echo.
echo 3. Start Aether AI:
echo    - Double-click "Aether AI" icon on your desktop
echo    - Or run: start-aether.bat
echo.
echo 4. Read the documentation:
echo    - README.md - Quick start guide
echo    - QUICKSTART.md - Step-by-step tutorial
echo    - MULTI_PROVIDER_SETUP.md - Provider configuration
echo.
echo For help and troubleshooting, see README.md
echo.
echo Press any key to open .env file for configuration...
pause >nul

notepad .env

echo.
echo Thank you for installing Aether AI!
echo.
pause
