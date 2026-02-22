# Aether Doctor - System Diagnostic Utility
# Purpose: Check Aether's health across the system stack.

$ErrorActionPreference = "SilentlyContinue"
$Header = @"
***************************************************
*            ⚡ AETHER SYSTEM DOCTOR              *
***************************************************
"@

Write-Host $Header -ForegroundColor Cyan

# 1. Environment Check
Write-Host "`n[1] Checking Environment..." -ForegroundColor Yellow
$PythonVer = python --version
if ($PythonVer) { Write-Host "✅ Python: $PythonVer" -ForegroundColor Green } else { Write-Host "❌ Python Not Found" -ForegroundColor Red }

$NodeVer = node --version
if ($NodeVer) { Write-Host "✅ Node.js: $NodeVer" -ForegroundColor Green } else { Write-Host "❌ Node.js Not Found" -ForegroundColor Red }

# 2. Process Check
Write-Host "`n[2] Checking Active Processes..." -ForegroundColor Yellow
$AetherProc = Get-Process "python" | Where-Object { $_.CommandLine -like "*main.py*" }
if ($AetherProc) { Write-Host "✅ Aether Backend: RUNNING (PID: $($AetherProc.Id))" -ForegroundColor Green } else { Write-Host "⚠️ Aether Backend: NOT RUNNING" -ForegroundColor Gray }

$UIProc = Get-Process "electron"
if ($UIProc) { Write-Host "✅ Aether UI: RUNNING" -ForegroundColor Green } else { Write-Host "⚠️ Aether UI: NOT RUNNING" -ForegroundColor Gray }

# 3. Resource Check
Write-Host "`n[3] Checking System Resources..." -ForegroundColor Yellow
$OS = Get-WmiObject Win32_OperatingSystem
$FreeMem = [Math]::Round($OS.FreePhysicalMemory / 1024 / 1024, 2)
$CPU = (Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
Write-Host "📊 CPU Load: $CPU%"
Write-Host "📊 Free RAM: $FreeMem GB"

# 4. Dependency Check
Write-Host "`n[4] Checking Data Integrity..." -ForegroundColor Yellow
$Dirs = @("data/tts_cache", "data/memory", "logs")
foreach ($d in $Dirs) {
    if (Test-Path $d) { Write-Host "✅ Directory $d: EXISTS" -ForegroundColor Green } else { Write-Host "❌ Directory $d: MISSING" -ForegroundColor Red }
}

Write-Host "`n*** Diagnosis Complete ***" -ForegroundColor Cyan
