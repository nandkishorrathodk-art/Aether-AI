@echo off
echo Starting Aether Monitoring Microservices...
echo.

set MONITOR_PORT=9001
set DETECTOR_PORT=9002

echo Starting Go Screen Monitor on port %MONITOR_PORT%...
start "Aether Monitor" cmd /k "cd go-monitor && monitor.exe"

echo Starting Rust App Detector on port %DETECTOR_PORT%...
start "Aether Detector" cmd /k "cd rust-detector\target\release && aether-app-detector.exe"

echo.
echo Services starting...
echo - Monitor: http://127.0.0.1:%MONITOR_PORT%
echo - Detector: http://127.0.0.1:%DETECTOR_PORT%
echo.
echo Press any key to stop services...
pause >nul

taskkill /FI "WINDOWTITLE eq Aether Monitor*" /F
taskkill /FI "WINDOWTITLE eq Aether Detector*" /F

echo Services stopped.
