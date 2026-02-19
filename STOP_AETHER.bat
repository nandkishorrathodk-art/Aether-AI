@echo off
title Stop Aether AI
color 0C

echo.
echo ================================================================
echo          STOPPING AETHER AI
echo ================================================================
echo.

echo [1/2] Stopping Python backend...
taskkill /F /IM python.exe /T >nul 2>&1
if errorlevel 1 (
    echo       [!] No Python processes found
) else (
    echo       [OK] Backend stopped
)

echo [2/2] Stopping Node.js frontend...
taskkill /F /IM node.exe /T >nul 2>&1
if errorlevel 1 (
    echo       [!] No Node.js processes found
) else (
    echo       [OK] Frontend stopped
)

echo [3/3] Stopping Electron...
taskkill /F /IM electron.exe /T >nul 2>&1
if errorlevel 1 (
    echo       [!] No Electron processes found
) else (
    echo       [OK] Electron stopped
)

echo.
echo ================================================================
echo   [OK] Aether AI stopped
echo ================================================================
echo.
pause
