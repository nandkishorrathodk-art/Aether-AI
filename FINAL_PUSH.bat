@echo off
echo ============================================================
echo Aether AI - Final Push to GitHub
echo ============================================================

echo.
echo [1/5] Setting git identity...
git config --global user.email "nandkishor@aether-ai.com"
git config --global user.name "Nandkishor Rathod"

echo.
echo [2/5] Going to temp directory...
cd /d "%TEMP%\aether-ai-fresh"

echo.
echo [3/5] Creating commit...
git add .
git commit -m "Aether AI - JARVIS-Level Virtual Assistant"

echo.
echo [4/5] Pushing to GitHub...
git branch -M main
git remote add origin https://github.com/nandkishorrathodk-art/Aether-AI.git 2>nul
git push -u origin main --force

echo.
echo [5/5] Success check...
if %ERRORLEVEL% EQU 0 (
    echo ============================================================
    echo SUCCESS! Aether AI is on GitHub!
    echo https://github.com/nandkishorrathodk-art/Aether-AI
    echo ============================================================
) else (
    echo ============================================================
    echo Push failed. Check network connection.
    echo ============================================================
)

echo.
pause
