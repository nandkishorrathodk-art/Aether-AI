@echo off
echo ============================================
echo  AETHER AI - AUTONOMOUS BUG BOUNTY DEMO
echo ============================================
echo.
echo This demo shows Aether's FULLY AUTONOMOUS
echo bug bounty capabilities:
echo.
echo 1. Auto-analyze Apple Security Bounty
echo 2. Check if targets are in scope
echo 3. Start smart hunt (fully autonomous)
echo.
echo ============================================
echo.

echo Starting Aether backend...
echo Press Ctrl+C to stop after viewing results
echo.

cd aether-ai-repo

REM Start backend in background
start "Aether Backend" /MIN cmd /k "venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000"

echo Waiting for backend to initialize...
timeout /t 10 /nobreak >nul

echo.
echo ============================================
echo TEST 1: Get Known Programs
echo ============================================
curl -s http://localhost:8000/api/v1/bugbounty/auto/known-programs
echo.
echo.

timeout /t 3 /nobreak >nul

echo ============================================
echo TEST 2: Analyze Apple Security Bounty
echo          (FULLY AUTONOMOUS)
echo ============================================
echo.
echo Aether will:
echo  1. Fetch https://security.apple.com/bounty/
echo  2. Read the entire page
echo  3. Extract scope (in-scope/out-of-scope)
echo  4. Extract rules (allowed/forbidden)
echo  5. Extract payouts
echo  6. Return structured data
echo.
echo Starting autonomous analysis...
echo.

curl -X POST http://localhost:8000/api/v1/bugbounty/auto/analyze-program ^
  -H "Content-Type: application/json" ^
  -d "{\"program_url\": \"https://security.apple.com/bounty/\"}"

echo.
echo.
timeout /t 5 /nobreak >nul

echo ============================================
echo TEST 3: Check Scope (www.apple.com)
echo ============================================
echo.

curl -X POST http://localhost:8000/api/v1/bugbounty/auto/check-scope ^
  -H "Content-Type: application/json" ^
  -d "{\"program_url\": \"https://security.apple.com/bounty/\", \"target_url\": \"www.apple.com\"}"

echo.
echo.
timeout /t 3 /nobreak >nul

echo ============================================
echo TEST 4: Check Scope (google.com - should fail)
echo ============================================
echo.

curl -X POST http://localhost:8000/api/v1/bugbounty/auto/check-scope ^
  -H "Content-Type: application/json" ^
  -d "{\"program_url\": \"https://security.apple.com/bounty/\", \"target_url\": \"google.com\"}"

echo.
echo.
echo ============================================
echo DEMO COMPLETE!
echo ============================================
echo.
echo Aether AI can now:
echo  - Read bug bounty program pages autonomously
echo  - Extract scope, rules, payouts automatically  
echo  - Validate targets against program rules
echo  - Run fully autonomous smart hunts
echo.
echo NO HUMAN INPUT NEEDED!
echo.
echo To run a SMART HUNT (requires Burp Suite Pro):
echo.
echo curl -X POST http://localhost:8000/api/v1/bugbounty/auto/smart-hunt \
echo   -H "Content-Type: application/json" \
echo   -d "{\"target_url\": \"https://www.apple.com\", \"program\": \"apple\"}"
echo.
echo ============================================
echo.

pause
