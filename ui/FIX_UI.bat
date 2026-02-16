@echo off
echo ========================================
echo  FIXING UI BUILD ERRORS
echo ========================================
echo.

echo [1/4] Stopping any running servers...
taskkill /F /IM node.exe 2>nul
timeout /t 2 /nobreak >nul

echo [2/4] Clearing React cache...
if exist node_modules\.cache rmdir /S /Q node_modules\.cache
if exist .cache rmdir /S /Q .cache

echo [3/4] Removing build folder...
if exist build rmdir /S /Q build

echo [4/4] Starting development server...
echo.
echo ========================================
echo  UI should now start without errors
echo ========================================
echo.

npm start
