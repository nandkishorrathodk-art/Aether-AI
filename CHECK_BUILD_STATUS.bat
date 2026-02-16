@echo off
title Build Status Checker
color 0B

cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║          📊 BUILD STATUS CHECK 📊                    ║
echo  ╚══════════════════════════════════════════════════════╝
echo.

echo  Checking build progress...
echo.

REM Check React build
if exist "ui\build\index.html" (
    echo  [1] ✅ React Build: COMPLETE
) else (
    echo  [1] ⏳ React Build: IN PROGRESS...
    echo      Wait kar rahe hain...
)

echo.

REM Check Electron build
if exist "ui\dist\Aether AI Setup 0.1.0.exe" (
    echo  [2] ✅ Electron Build: COMPLETE
    echo.
    echo  🎉 INSTALLER READY HAI! 🎉
    echo.
    echo  📂 Location: ui\dist\Aether AI Setup 0.1.0.exe
    echo.
    
    REM Show file size
    for %%A in ("ui\dist\Aether AI Setup 0.1.0.exe") do (
        set SIZE=%%~zA
        set /a SIZE_MB=!SIZE! / 1048576
        echo  📦 Size: !SIZE_MB! MB
    )
    
    echo.
    choice /C YN /M "Installer folder kholein"
    if not errorlevel 2 (
        explorer "ui\dist"
    )
) else if exist "ui\dist" (
    echo  [2] ⏳ Electron Build: IN PROGRESS...
) else (
    echo  [2] ⏸️  Electron Build: NOT STARTED
    echo      Pehle React build complete hone do
)

echo.
echo  ════════════════════════════════════════════════════════
echo.
pause
