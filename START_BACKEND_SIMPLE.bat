@echo off
title Aether Backend
color 0A

echo Starting Aether AI Backend...
echo.

cd /d "%~dp0"
venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000
