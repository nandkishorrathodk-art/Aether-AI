@echo off
cls
echo ========================================
echo  ULTIMATE UI FIX - NUCLEAR OPTION
echo ========================================
echo.
echo This will completely reset the UI
echo.
pause

echo [1/8] Killing all Node processes...
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul

echo [2/8] Deleting ALL cache folders...
if exist node_modules\.cache rmdir /S /Q node_modules\.cache 2>nul
if exist .cache rmdir /S /Q .cache 2>nul
if exist build rmdir /S /Q build 2>nul
if exist dist rmdir /S /Q dist 2>nul
if exist .parcel-cache rmdir /S /Q .parcel-cache 2>nul

echo [3/8] Deleting package-lock.json...
if exist package-lock.json del /F /Q package-lock.json 2>nul

echo [4/8] Deleting node_modules...
if exist node_modules (
    echo     This may take a minute...
    rmdir /S /Q node_modules 2>nul
)

echo [5/8] Clearing npm cache...
call npm cache clean --force

echo [6/8] Fresh install of dependencies...
call npm install

echo [7/8] Verifying React installation...
call npm list react react-dom

echo [8/8] Starting development server...
echo.
echo ========================================
echo  UI COMPLETELY RESET - STARTING NOW
echo ========================================
echo.
call npm start
