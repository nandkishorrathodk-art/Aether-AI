@echo off
echo ========================================
echo AETHER AI - QUICK PUSH SOLUTION
echo ========================================
echo.
echo This will create a fresh branch without full history
echo (Much faster to push - only current code, no history)
echo.
pause

cd /d "%~dp0"

echo.
echo [1/6] Creating fresh branch without history...
git checkout --orphan aether-fresh

echo.
echo [2/6] Adding all files...
git add -A

echo.
echo [3/6] Creating single commit...
git commit -m "Aether AI v1.5 - Complete System with Bug Bounty Security Audit"

echo.
echo [4/6] Removing old origin...
git remote remove origin 2>nul

echo.
echo [5/6] Adding GitHub remote...
git remote add origin https://github.com/nandkishorrathodk-art/Aether-AI.git

echo.
echo [6/6] Pushing to GitHub (this will be fast - no history)...
git push -u origin aether-fresh:main --force

echo.
echo ========================================
echo DONE! Check GitHub:
echo https://github.com/nandkishorrathodk-art/Aether-AI
echo ========================================
pause
