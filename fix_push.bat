@echo off
echo ============================================================
echo AETHER AI - GitHub Push Fix
echo ============================================================

echo.
echo [1/5] Increasing Git buffer size...
git config --global http.postBuffer 524288000
git config --global http.maxRequestBuffer 100M
git config --global core.compression 0

echo.
echo [2/5] Setting timeout values...
git config --global http.lowSpeedLimit 0
git config --global http.lowSpeedTime 999999

echo.
echo [3/5] Attempting push with retry logic...
:RETRY
echo.
echo Attempting push to GitHub...
git push -u origin main 2>error.log

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================================
    echo SUCCESS! Repository pushed to GitHub
    echo ============================================================
    goto END
)

echo.
echo Push failed. Checking error...
type error.log

echo.
echo [4/5] Trying alternative method: Chunked push...
git config --global http.version HTTP/1.1
timeout /t 3 /nobreak >nul
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================================
    echo SUCCESS! Repository pushed to GitHub
    echo ============================================================
    goto END
)

echo.
echo [5/5] Trying with SSH instead of HTTPS...
echo.
echo Would you like to try SSH? (Requires SSH key setup)
echo If yes, run: ssh-keygen -t ed25519 -C "your_email@example.com"
echo Then add the key to GitHub: https://github.com/settings/keys
echo.
echo Alternative: Try pushing from a different network or use GitHub Desktop

:END
echo.
pause
