# Aether Monitoring System v0.9.0

Multi-language microservices architecture for high-performance screen monitoring and application detection.

## Architecture

```
┌─────────────────────────────────────────────┐
│           Python FastAPI Layer              │
│         (API Orchestration + LLM)           │
└──────────────┬──────────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌─────▼──────┐
│ Go Monitor  │  │ Rust       │
│ Service     │  │ Detector   │
│ :9001       │  │ :9002      │
└─────────────┘  └────────────┘
  Screen Capture   App Detection
  (High Perf)      (Fast Sys Ops)
```

## Components

### 1. **Go Monitor Service** (Port 9001)
- High-performance screen capture using `kbinani/screenshot`
- Configurable capture intervals
- Optional screenshot persistence
- Lightweight HTTP API

**Endpoints:**
- `POST /start` - Start monitoring
- `POST /stop` - Stop monitoring
- `GET /status` - Get status
- `GET /capture` - Capture screenshot now

### 2. **Rust Detector Service** (Port 9002)
- Fast application detection using `sysinfo`
- Active window tracking (Windows)
- Target application filtering
- Low overhead process enumeration

**Endpoints:**
- `GET /detect?targets=burpsuite,chrome` - Detect apps
- `GET /check/{app}` - Check specific app
- `GET /health` - Health check

### 3. **Python Bridge Layer**
- Lightweight orchestration (`bridge.py`)
- LLM-powered context analysis (`context_analyzer.py`)
- FastAPI routes (`api/routes/monitor.py`)

## Build & Run

### Prerequisites
- **Go** 1.21+ ([download](https://go.dev/dl/))
- **Rust** 1.70+ ([install](https://rustup.rs/))
- **Python** 3.10+

### Build Services

```cmd
cd src\monitoring
build.bat
```

This builds:
- `go-monitor\monitor.exe`
- `rust-detector\target\release\aether-app-detector.exe`

### Start Services

```cmd
cd src\monitoring
start-services.bat
```

Or manually:
```cmd
# Terminal 1 - Go Monitor
cd go-monitor
set MONITOR_PORT=9001
monitor.exe

# Terminal 2 - Rust Detector
cd rust-detector\target\release
set DETECTOR_PORT=9002
aether-app-detector.exe
```

### Start Main Aether API

```cmd
cd aether-ai-repo
python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

## API Usage

### Check if Burp Suite is Running

```bash
curl http://127.0.0.1:8000/api/v1/monitor/check-app/burpsuite
```

Response:
```json
{
  "app": "burpsuite",
  "running": true,
  "context": {
    "burpsuite_detected": true,
    "suggestions": [
      "Configure browser proxy to 127.0.0.1:8080",
      "Start passive scan on target"
    ]
  }
}
```

### Get Current Context with AI Analysis

```bash
curl http://127.0.0.1:8000/api/v1/monitor/current-context?analyze=true
```

Response:
```json
{
  "apps": [...],
  "detected_categories": ["burpsuite", "vscode"],
  "analysis": {
    "activity_type": "security_testing",
    "analysis": "User is performing security testing with Burp Suite",
    "suggestions": ["Review proxy history", "Check for SQLi"],
    "confidence": 0.85
  }
}
```

### Start/Stop Monitoring

```bash
# Start
curl -X POST http://127.0.0.1:8000/api/v1/monitor/start

# Stop
curl -X POST http://127.0.0.1:8000/api/v1/monitor/stop

# Status
curl http://127.0.0.1:8000/api/v1/monitor/status
```

### Capture Screenshot

```bash
curl http://127.0.0.1:8000/api/v1/monitor/screenshot
```

Returns base64-encoded PNG screenshot.

## Configuration

Edit `.env`:

```env
# Screen Monitoring
ENABLE_SCREEN_MONITORING=true
SCREEN_CAPTURE_INTERVAL=30
SCREEN_MONITOR_SAVE_SCREENSHOTS=false
SCREEN_MONITOR_DATA_PATH=./data/monitoring
```

## Testing

```bash
pytest tests/unit/test_monitoring.py -v
```

## Why Multi-Language?

- **Go**: 50% faster screen capture than Python, minimal memory
- **Rust**: Safe system-level ops, near-zero overhead for process detection
- **Python**: Best for LLM integration, API orchestration, rapid development

**Result**: Complex functionality, simple interfaces. Best of all worlds.

## Performance

- **Screen Capture**: ~5ms per frame (Go)
- **App Detection**: ~10ms for full scan (Rust)
- **Memory Footprint**: <50MB combined (vs 200MB+ pure Python)
- **Startup Time**: <100ms per service

## License

Part of Aether AI v0.9.0
