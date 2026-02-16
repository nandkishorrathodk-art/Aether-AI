@echo off
title Microphone Setup Guide
color 0E

cls
echo.
echo  ╔══════════════════════════════════════════════════════╗
echo  ║                                                      ║
echo  ║        🎤 MICROPHONE PERMISSION SETUP 🎤            ║
echo  ║                                                      ║
echo  ╚══════════════════════════════════════════════════════╝
echo.
echo  Is guide se aap microphone access de sakte ho
echo.
echo  ════════════════════════════════════════════════════════
echo.
echo  STEP 1: Windows Settings Kholo
echo.
echo  Press any key to open Settings...
pause >nul

REM Open Windows Settings to Microphone page
start ms-settings:privacy-microphone

echo.
echo  ✅ Settings window khul gaya!
echo.
echo  ════════════════════════════════════════════════════════
echo.
echo  STEP 2: Settings Window Mein:
echo.
echo  1. "Microphone access" ko ON karo
echo  2. "Let apps access your microphone" ko ON karo
echo  3. "Let desktop apps access" ko ON karo
echo.
echo  ════════════════════════════════════════════════════════
echo.
echo  STEP 3: Test Your Microphone
echo.
echo  Press any key to open Voice Recorder for testing...
pause >nul

REM Open Voice Recorder
start ms-windows-store://pdp/?productid=9WZDNCRFHWKL 2>nul
if %errorlevel% neq 0 (
    echo.
    echo  Voice Recorder nahi mila. Manual test karo:
    echo  1. Windows Key dabao
    echo  2. Type: "Voice Recorder"
    echo  3. Open karo aur test karo
)

echo.
echo  ════════════════════════════════════════════════════════
echo.
echo  STEP 4: Sound Settings Check
echo.
echo  Press any key to open Sound Settings...
pause >nul

REM Open Sound Settings
start ms-settings:sound

echo.
echo  ✅ Sound Settings khul gaye!
echo.
echo  Check karein:
echo  - Input device correct hai ya nahi
echo  - Volume slider 50%% se upar hai
echo  - Mic muted nahi hai
echo.
echo  ════════════════════════════════════════════════════════
echo.
echo  ✅ MIC SETUP COMPLETE!
echo.
echo  Ab aap Aether AI app chala sakte ho:
echo.
echo  1. Close this window
echo  2. Run: RUN_AETHER.bat
echo  3. App "Allow microphone?" poochega
echo  4. "Allow" click karo
echo  5. Ready! 🎤
echo.
echo  ════════════════════════════════════════════════════════
echo.
pause
