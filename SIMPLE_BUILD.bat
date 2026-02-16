@echo off
title Aether AI - Simple Builder
color 0E

cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║       🚀 AETHER AI - SIMPLE BUILD 🚀                ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  Ye script sabkuch step-by-step karega.
echo  Bas wait karo aur dekhte raho!
echo.
timeout /t 3

REM Step 1: Go to UI folder
echo.
echo  [Step 1/3] UI folder mein ja rahe hain...
cd ui
if %errorlevel% neq 0 (
    echo  ❌ UI folder nahi mila!
    cd ..
    pause
    exit /b 1
)
echo  ✅ UI folder mein pahunch gaye
timeout /t 2

REM Step 2: Build React app
echo.
echo  [Step 2/3] React app build kar rahe hain...
echo  ⏰ Ye 2-3 minute lega. Coffee pi lo! ☕
echo.

call npm run build

if %errorlevel% neq 0 (
    echo.
    echo  ❌ React build fail ho gaya!
    echo  Error dekho upar
    cd ..
    pause
    exit /b 1
)

echo.
echo  ✅ React build COMPLETE!
timeout /t 2

REM Step 3: Build Electron installer
echo.
echo  [Step 3/3] Windows installer bana rahe hain...
echo  ⏰ Ye 5-7 minute lega. Thoda aur wait! ⏳
echo.

call npx electron-builder --win

if %errorlevel% neq 0 (
    echo.
    echo  ❌ Installer build fail!
    cd ..
    pause
    exit /b 1
)

cd ..

REM Success!
cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                                                      ║
echo  ║         🎉 BUILD SUCCESSFUL! 🎉                     ║
echo  ║                                                      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  ✅ Aapka Windows installer ready hai!
echo.
echo  📂 Location: ui\dist\
echo.

if exist "ui\dist\*.exe" (
    echo  📦 Installer files:
    dir /b "ui\dist\*.exe"
    echo.
    
    echo  🎯 Next step: ui\dist folder kholo aur installer run karo!
    echo.
    
    choice /C YN /M "Folder kholein abhi"
    if not errorlevel 2 (
        explorer "ui\dist"
    )
) else (
    echo  ⚠️ EXE file nahi bana!
)

echo.
echo  🎊 Congratulations! 🎊
pause
