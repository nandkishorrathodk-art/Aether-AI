@echo off
echo ============================================================
echo Creating Fresh Aether AI Repository
echo ============================================================

echo.
echo [1/5] Removing old git history...
rmdir /S /Q .git 2>nul

echo.
echo [2/5] Initializing new repository...
git init

echo.
echo [3/5] Adding all files...
git add .

echo.
echo [4/5] Creating initial commit...
git commit -m "Aether AI - Complete Virtual Assistant System"

echo.
echo [5/5] Pushing to GitHub...
git branch -M main
git remote add origin https://github.com/nandkishorrathodk-art/Aether-AI.git
git push -u origin main --force

echo.
echo ============================================================
echo Done! Check: https://github.com/nandkishorrathodk-art/Aether-AI
echo ============================================================
pause
