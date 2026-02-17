@echo off
echo Building Aether Monitoring Microservices...
echo.

echo [1/2] Building Go Screen Monitor...
cd go-monitor
go mod download
go build -o monitor.exe main.go
if %errorlevel% neq 0 (
    echo Go build failed!
    exit /b 1
)
echo Go service built: go-monitor\monitor.exe
cd ..

echo.
echo [2/2] Building Rust App Detector...
cd rust-detector
cargo build --release
if %errorlevel% neq 0 (
    echo Rust build failed!
    exit /b 1
)
echo Rust service built: rust-detector\target\release\aether-app-detector.exe
cd ..

echo.
echo ✓ All microservices built successfully!
echo.
echo To start services:
echo   - Go Monitor:   go-monitor\monitor.exe
echo   - Rust Detector: rust-detector\target\release\aether-app-detector.exe
echo.
