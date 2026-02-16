@echo off
title Test Aether AI Chat
cls

echo.
echo  ================================================
echo   TESTING AETHER AI CHAT
echo  ================================================
echo.

cd /d "%~dp0"
call venv\Scripts\activate.bat

echo  Sending test message to Aether AI...
echo.

python -c "import requests; r = requests.post('http://127.0.0.1:8000/api/v1/chat/conversation', json={'message': 'Hello! Are you working?', 'session_id': 'test'}); print('\nAether AI Response:'); print(r.json()['content'] if r.status_code == 200 else 'Error: ' + str(r.status_code))"

echo.
echo  ================================================
pause
