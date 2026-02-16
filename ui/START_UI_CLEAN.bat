@echo off
echo Starting UI with clean cache...
echo.

if exist node_modules\.cache (
    echo Removing React cache...
    rmdir /S /Q node_modules\.cache
)

if exist .cache (
    echo Removing Parcel cache...
    rmdir /S /Q .cache
)

if exist build (
    echo Removing old build...
    rmdir /S /Q build
)

echo Starting development server...
set GENERATE_SOURCEMAP=false
set DISABLE_ESLINT_PLUGIN=true
npm start
