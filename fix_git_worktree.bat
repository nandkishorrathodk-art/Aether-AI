@echo off
echo ============================================================
echo FIX: Git Worktree Lock Issue
echo ============================================================

echo.
echo [1/3] Stopping git gc process...
taskkill /F /IM git.exe 2>nul
timeout /t 2 /nobreak >nul

echo.
echo [2/3] Removing problematic directory...
rmdir /S /Q "C:\Users\nandk\OneDrive\Desktop\fist code\fist.py\.git\refs\remotes\origin" 2>nul

echo.
echo [3/3] Skip git gc, just push to GitHub...
echo.
echo Run this command:
echo git push -u origin main --force
echo.

pause
