@echo off
title Chat with Aether AI
color 0B
cls

cd /d "%~dp0"

echo.
echo  ================================================
echo         CHAT WITH AETHER AI
echo  ================================================
echo.
echo   Starting chat interface...
echo.

call venv\Scripts\activate.bat

python chat-with-aether.py

pause
