@echo off
chcp 65001 >nul
title 🔧 Fix Port 8000 Issue
color 0E

echo.
echo ════════════════════════════════════════════════════════════════
echo           🔧 FIXING PORT 8000 CONFLICT 🔧
echo ════════════════════════════════════════════════════════════════
echo.

echo Problem: Port 8000 already in use
echo Solution: Killing process using port 8000
echo.

echo [1] Finding process on port 8000...
netstat -ano | findstr :8000 | findstr LISTENING

echo.
echo [2] Killing the process...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING') do (
    echo    └─ Found PID: %%a
    echo    └─ Killing...
    taskkill /F /PID %%a
)

echo.
echo [3] Verifying port is free...
timeout /t 2 /nobreak >nul

netstat -ano | findstr :8000 | findstr LISTENING >nul 2>&1
if %errorlevel%==0 (
    echo ❌ Port 8000 still in use!
    echo    Try running as Administrator
) else (
    echo ✅ Port 8000 is now free!
    echo    You can start Aether now
)

echo.
echo ════════════════════════════════════════════════════════════════
echo Press any key to start Aether...
pause >nul

call QUICK_START.bat
