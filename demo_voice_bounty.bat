@echo off
echo ============================================
echo  AETHER AI - VOICE BUG BOUNTY DEMO
echo  Hindi-English TTS Notifications!
echo ============================================
echo.
echo Aether will SPEAK to you in Hindi-English mix:
echo  - "Ji boss! Program analyze kar raha hoon"
echo  - "Boss! Critical bug mila!"
echo  - "IDOR vulnerability! Payout potential high!"
echo.
echo Make sure your speakers are ON!
echo ============================================
echo.

cd aether-ai-repo

echo Starting Aether backend with voice...
start "Aether Voice Backend" /MIN cmd /k "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"

echo Waiting for backend...
timeout /t 10 /nobreak >nul

echo.
echo ============================================
echo TEST 1: Voice Test (Direct Python)
echo ============================================
echo Running voice notifier test...
echo.

venv\Scripts\python -m src.bugbounty.voice_notifier

echo.
timeout /t 3 /nobreak >nul

echo ============================================
echo TEST 2: Smart Hunt with Voice (API)
echo ============================================
echo.
echo This will:
echo  1. Speak "Analyzing Apple program..."
echo  2. Speak "Analysis complete - 15 targets, $2M max"
echo  3. Speak "www.apple.com in scope!"
echo  4. Speak "Hunt starting..."
echo.
echo Starting smart hunt with VOICE ENABLED...
echo.

curl -X POST http://localhost:8000/api/v1/bugbounty/auto/smart-hunt ^
  -H "Content-Type: application/json" ^
  -d "{\"target_url\": \"https://www.apple.com\", \"program\": \"apple\", \"enable_voice\": true}"

echo.
echo.
echo ============================================
echo VOICE DEMO COMPLETE!
echo ============================================
echo.
echo Aether spoke to you in Hindi-English mix!
echo.
echo To enable voice in your own hunts, add:
echo   "enable_voice": true
echo.
echo Example:
echo.
echo curl -X POST http://localhost:8000/api/v1/bugbounty/auto/smart-hunt \
echo   -H "Content-Type: application/json" \
echo   -d "{\"target_url\": \"https://example.com\", \"program\": \"custom\", \"enable_voice\": true}"
echo.
echo ============================================
echo.

pause
