@echo off
echo ========================================
echo  RESTARTING UI WITH FRESH BUILD
echo ========================================
echo.
echo This will fix compilation errors
echo.

echo [1/6] Killing all Node processes...
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul

echo [2/6] Clearing React cache...
if exist node_modules\.cache (
    echo     Removing node_modules\.cache...
    rmdir /S /Q node_modules\.cache
)
if exist .cache (
    echo     Removing .cache...
    rmdir /S /Q .cache
)

echo [3/6] Clearing build artifacts...
if exist build (
    echo     Removing build folder...
    rmdir /S /Q build
)

echo [4/6] Clearing package-lock...
if exist package-lock.json (
    echo     Removing package-lock.json...
    del /F /Q package-lock.json
)

echo [5/6] Reinstalling dependencies...
call npm install

echo [6/6] Starting development server...
echo.
echo ========================================
echo  Starting React development server...
echo ========================================
echo.
call npm start
