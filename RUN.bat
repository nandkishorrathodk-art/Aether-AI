@echo off
title Aether AI
cls
echo.
echo  █████╗ ███████╗████████╗██╗  ██╗███████╗██████╗ 
echo ██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗
echo ███████║█████╗     ██║   ███████║█████╗  ██████╔╝
echo ██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗
echo ██║  ██║███████╗   ██║   ██║  ██║███████╗██║  ██║
echo ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
echo.
echo         Advanced AI Assistant v0.1.0
echo.

cd /d "%~dp0"
call venv\Scripts\activate.bat 2>nul

echo Starting server...
echo.
echo API:  http://127.0.0.1:8000
echo Docs: http://127.0.0.1:8000/docs
echo.

python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
