@echo off
chcp 65001 >nul
title 🔄 Restart Aether AI
color 0E

echo.
echo ════════════════════════════════════════════════════════════════
echo              🔄 RESTARTING AETHER AI 🔄
echo ════════════════════════════════════════════════════════════════
echo.

echo [Step 1] 🛑 Stopping existing instances...
call STOP_AETHER.bat

echo.
echo [Step 2] ⏳ Waiting 3 seconds...
timeout /t 3 /nobreak >nul

echo.
echo [Step 3] 🚀 Starting Aether AI...
call QUICK_START.bat

echo.
echo ✅ Restart complete!
