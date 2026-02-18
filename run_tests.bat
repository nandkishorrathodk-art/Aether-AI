@echo off
REM Aether AI v2.0 - Test Runner
REM Runs all test suites for autonomous system

echo.
echo ========================================
echo   Aether AI v2.0 - Test Suite
echo ========================================
echo.

echo [1/3] Running Autonomous System Tests...
pytest tests/test_autonomous_system.py -v --tb=short --color=yes

echo.
echo [2/3] Running Bug Bounty Enhancement Tests...
pytest tests/test_bugbounty_enhancements.py -v --tb=short --color=yes

echo.
echo [3/3] Running Coverage Report...
pytest tests/ --cov=src --cov-report=html --cov-report=term

echo.
echo ========================================
echo   Tests Complete!
echo ========================================
echo   Coverage report: htmlcov/index.html
echo ========================================
echo.

pause
