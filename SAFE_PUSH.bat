@echo off
echo ============================================================
echo SAFE Push: Copy to New Location
echo ============================================================

set TEMP_DIR=%TEMP%\aether-ai-fresh

echo.
echo [1/6] Creating temporary directory...
rmdir /S /Q "%TEMP_DIR%" 2>nul
mkdir "%TEMP_DIR%"

echo.
echo [2/6] Copying Aether AI files (this may take 1-2 minutes)...
xcopy /E /I /H /Y "." "%TEMP_DIR%" /EXCLUDE:exclude_list.txt

echo.
echo [3/6] Changing to temp directory...
cd /d "%TEMP_DIR%"

echo.
echo [4/6] Creating fresh git repository...
rmdir /S /Q .git 2>nul
git init
git add .
git commit -m "Aether AI - JARVIS-Level Virtual Assistant"

echo.
echo [5/6] Pushing to GitHub...
git branch -M main
git remote add origin https://github.com/nandkishorrathodk-art/Aether-AI.git
git push -u origin main --force

echo.
echo [6/6] Cleanup...
cd /d "%~dp0"

echo.
echo ============================================================
echo SUCCESS! View at: https://github.com/nandkishorrathodk-art/Aether-AI
echo ============================================================
echo.
echo Temporary files at: %TEMP_DIR%
echo Delete after confirming GitHub looks good!
echo.
pause
