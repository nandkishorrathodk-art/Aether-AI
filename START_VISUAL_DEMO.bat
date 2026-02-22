@echo off
title Aether AI v4.5 - Visual Live Execution Demo
color 0A

echo ================================================================================
echo   AETHER AI v4.5 - VISUAL LIVE EXECUTION
echo ================================================================================
echo.
echo [INFO] This will demonstrate REAL visible windows opening
echo [INFO] Everything happens LIVE - no background processes
echo.
echo [FEATURES] What you'll see:
echo   [+] Real CMD windows opening
echo   [+] BurpSuite GUI launching (if installed)
echo   [+] Nuclei scans running in visible windows
echo   [+] Multiple simultaneous windows
echo   [+] Voice AI narrating everything in Hinglish
echo.
echo ================================================================================
echo   PREREQUISITES:
echo ================================================================================
echo.
echo [1] Server must be running in another terminal:
echo     uvicorn src.api.main_clean:app --reload
echo.
echo [2] Optional tools for full demo:
echo     - BurpSuite (Pro or Community)
echo     - Nuclei scanner
echo.
echo ================================================================================
pause
echo.
echo [STARTING] Running visual live demo...
echo.

python demo_visual_live.py

pause
