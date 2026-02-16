# Aether AI Installation Guide

Complete installation guide for Aether AI virtual assistant.

## Table of Contents

- [Quick Install (Recommended)](#quick-install-recommended)
- [Manual Installation](#manual-installation)
- [First-Time Configuration](#first-time-configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Uninstallation](#uninstallation)

---

## Quick Install (Recommended)

### Prerequisites

1. **Python 3.8+**: [Download from python.org](https://www.python.org/downloads/)
   - ⚠️ **IMPORTANT**: Check "Add Python to PATH" during installation

2. **Node.js 18+**: [Download from nodejs.org](https://nodejs.org/)
   - Includes npm automatically

3. **5GB Free Disk Space**

4. **At Least One AI Provider API Key** (see [Getting API Keys](#getting-api-keys))

### Installation Steps

1. **Download Aether AI**:
   ```bash
   # Clone from GitHub (or download ZIP)
   git clone <repository-url>
   cd nitro-v-f99b
   ```

2. **Run Installer**:
   ```bash
   # Double-click install.bat
   # OR run from command line:
   install.bat
   ```

3. **Wait for Installation**:
   - Creates Python virtual environment (2-3 min)
   - Installs Python dependencies (10-15 min)
   - Installs Node.js dependencies (5-10 min)
   - Builds React application (3-5 min)
   - **Total time**: 20-30 minutes

4. **Configure API Keys**:
   - Installer will open `.env` file
   - Add at least ONE API key (see [Getting API Keys](#getting-api-keys))
   - Save and close

5. **Launch Aether AI**:
   - Double-click desktop shortcut **"Aether AI"**
   - OR run: `start-aether.bat`

---

## Manual Installation

### Step 1: Install Python Dependencies

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 2: Install Node.js Dependencies

```bash
cd ui
npm install
cd ..
```

### Step 3: Build React App

```bash
cd ui
npm run build
cd ..
```

### Step 4: Create Configuration File

```bash
# Copy example configuration
copy .env.example .env

# Edit with your API keys
notepad .env
```

### Step 5: Verify Installation

```bash
venv\Scripts\activate
python scripts\verify_installation.py
```

---

## First-Time Configuration

### Getting API Keys

You need **at least ONE** API key from these providers:

#### 1. Groq (FREE - Recommended for Testing)
- **URL**: https://console.groq.com/keys
- **Cost**: **FREE** (generous rate limits)
- **Speed**: Ultra-fast (300+ tokens/sec)
- **Best for**: Conversations, quick responses

#### 2. OpenAI
- **URL**: https://platform.openai.com/api-keys
- **Cost**: Pay-per-use (GPT-3.5: ~$0.001/1K tokens)
- **Best for**: Complex tasks, code generation

#### 3. Anthropic (Claude)
- **URL**: https://console.anthropic.com/
- **Cost**: Pay-per-use (similar to OpenAI)
- **Best for**: Analysis, long conversations

#### 4. Google (Gemini)
- **URL**: https://makersuite.google.com/app/apikey
- **Cost**: **FREE** tier available
- **Best for**: Multimodal tasks

#### 5. Fireworks AI
- **URL**: https://fireworks.ai/api-keys
- **Cost**: Pay-per-use (cheaper than OpenAI)
- **Best for**: Fast inference

#### 6. OpenRouter
- **URL**: https://openrouter.ai/keys
- **Cost**: Varies by model
- **Best for**: Access to 50+ models

### Configuring `.env` File

1. **Open `.env`**:
   ```bash
   notepad .env
   ```

2. **Add Your API Key(s)**:
   ```env
   # Add at least ONE of these:
   OPENAI_API_KEY=sk-proj-...
   GROQ_API_KEY=gsk_...
   ANTHROPIC_API_KEY=sk-ant-...
   GOOGLE_API_KEY=...
   FIREWORKS_API_KEY=...
   OPENROUTER_API_KEY=...
   ```

3. **Optional Settings**:
   ```env
   # Cost limits
   MAX_COST_PER_DAY_USD=10.0
   
   # Wake word (default: "hey aether")
   WAKE_WORD=hey aether
   
   # Voice settings
   TTS_PROVIDER=openai
   TTS_VOICE=nova
   
   # Performance
   MAX_CONVERSATION_HISTORY=10
   ```

4. **Save and Close**

### Testing Configuration

```bash
# Activate virtual environment
venv\Scripts\activate

# Test API providers
python scripts\test_providers.py

# Expected output:
# ✓ OpenAI: GPT-4 working
# ✓ Groq: Llama-3 working
# ...
```

---

## Verification

### Automated Verification

```bash
# Activate virtual environment
venv\Scripts\activate

# Run verification script
python scripts\verify_installation.py
```

**Expected output**:
```
============================================
  AETHER AI INSTALLATION VERIFICATION
============================================

System Requirements:
✓ PASS - Python Version (Python 3.11.5)
✓ PASS - Node.js (Node.js v20.10.0)
✓ PASS - npm (npm 10.2.3)

Python Dependencies:
✓ PASS - fastapi (0.109.0)
✓ PASS - uvicorn (0.27.0)
...

Project Structure:
✓ PASS - src/ (exists)
✓ PASS - ui/ (exists)
...

Configuration:
✓ PASS - .env Configuration (API keys configured: Groq, OpenAI)

============================================
          VERIFICATION RESULT
============================================
✓ All checks passed!
```

### Manual Verification

#### 1. Test Backend API

```bash
# Terminal 1: Start backend
venv\Scripts\activate
uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

**Open browser**: http://localhost:8000/docs

**Test endpoint**: POST `/api/v1/chat`
```json
{
  "prompt": "Hello, introduce yourself",
  "task_type": "conversation"
}
```

#### 2. Test Frontend

```bash
# Terminal 2: Start frontend
cd ui
npm start
```

**Electron window should open** with Aether AI interface

#### 3. Test Voice Pipeline

```bash
# Activate virtual environment
venv\Scripts\activate

# Run voice pipeline test
python scripts\test_voice_pipeline_integration.py
```

---

## Troubleshooting

### Installation Issues

#### "Python not found"

**Problem**: Python not installed or not in PATH

**Solution**:
1. Install Python from https://www.python.org/downloads/
2. ⚠️ **Check "Add Python to PATH"** during installation
3. Restart command prompt
4. Verify: `python --version`

#### "Node.js not found"

**Problem**: Node.js not installed or not in PATH

**Solution**:
1. Install Node.js from https://nodejs.org/
2. Restart command prompt
3. Verify: `node --version` and `npm --version`

#### "Failed to install Python dependencies"

**Problem**: Network issues or package conflicts

**Solution**:
```bash
# Clear pip cache
pip cache purge

# Upgrade pip
python -m pip install --upgrade pip

# Retry installation
pip install -r requirements.txt --no-cache-dir
```

#### "PyAudio installation fails"

**Problem**: PyAudio requires PortAudio binaries

**Solution (Windows)**:
```bash
# Install pre-built wheel
pip install pipwin
pipwin install pyaudio

# OR download wheel from:
# https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyaudio
pip install path\to\PyAudio‑0.2.14‑cp311‑cp311‑win_amd64.whl
```

### Configuration Issues

#### "No AI providers configured"

**Problem**: No API keys in `.env`

**Solution**:
1. Open `.env`: `notepad .env`
2. Add at least ONE API key
3. Save and restart Aether AI

#### "API key invalid"

**Problem**: Incorrect or expired API key

**Solution**:
1. Verify key is correct (no extra spaces)
2. Check key hasn't been revoked
3. Generate new key from provider dashboard

### Runtime Issues

#### "Backend server won't start"

**Problem**: Port 8000 already in use

**Solution**:
```bash
# Find process using port 8000
netstat -ano | findstr :8000

# Kill process (use PID from above)
taskkill /PID <PID> /F

# OR use different port
uvicorn src.api.main:app --host 127.0.0.1 --port 8001
```

#### "Frontend can't connect to backend"

**Problem**: Backend not running or CORS issue

**Solution**:
1. Verify backend is running: http://localhost:8000/docs
2. Check backend logs in `logs/backend.log`
3. Verify CORS settings in `src/api/main.py`

#### "Voice features not working"

**Problem**: Microphone permissions or PyAudio issues

**Solution**:
1. **Check microphone permissions**:
   - Windows Settings → Privacy → Microphone
   - Allow desktop apps to access microphone

2. **Test microphone**:
   ```bash
   python scripts\test_voice_pipeline.py
   ```

3. **Reinstall PyAudio** (see PyAudio installation above)

### Performance Issues

#### "Slow AI responses"

**Solution**:
- Use Groq for fast responses: Set `ROUTER_FAST=groq` in `.env`
- Enable streaming: API request with `"stream": true`
- Reduce conversation history: `MAX_CONVERSATION_HISTORY=5`

#### "High memory usage"

**Solution**:
- Clear TTS cache: `http://localhost:8000/api/v1/voice/tts/cache/clear`
- Reduce conversation history
- Restart application periodically

---

## Uninstallation

### Option 1: Keep Configuration (Recommended)

```bash
# Removes software but keeps .env and data
uninstall.bat
# Select "No" when asked to remove data
```

### Option 2: Complete Removal

```bash
# Removes everything including configuration
uninstall.bat
# Select "Yes" when asked to remove data
```

### Manual Uninstallation

```bash
# Stop processes
taskkill /F /IM python.exe /FI "WINDOWTITLE eq Aether*"
taskkill /F /IM electron.exe

# Remove virtual environment
rmdir /S /Q venv

# Remove node_modules
rmdir /S /Q ui\node_modules

# Remove build files
rmdir /S /Q ui\build
rmdir /S /Q ui\dist

# Remove desktop shortcut
del "%USERPROFILE%\Desktop\Aether AI.lnk"

# Optional: Remove data and configuration
del .env
rmdir /S /Q data
rmdir /S /Q logs
rmdir /S /Q models
```

---

## Advanced Configuration

### Multi-Provider Routing

Configure which provider to use for each task:

```env
# In .env file
ROUTER_CONVERSATION=groq        # Fast conversations
ROUTER_CODE=gpt-4              # Code generation
ROUTER_ANALYSIS=claude-3-opus  # Complex analysis
ROUTER_CREATIVE=gpt-4          # Creative writing
```

See [MULTI_PROVIDER_SETUP.md](./MULTI_PROVIDER_SETUP.md) for details.

### Cost Optimization

```env
# Daily spending limit
MAX_COST_PER_DAY_USD=5.0

# Enable cost tracking
ENABLE_COST_TRACKING=true

# Prefer cheaper providers
ROUTER_FAST=groq
ROUTER_CHEAP=groq
```

Monitor costs: http://localhost:8000/api/v1/chat/cost-stats

### Voice Customization

```env
# Wake word options:
# jarvis, alexa, computer, hey google, ok google, hey siri, hey aether
WAKE_WORD=jarvis

# TTS voice options (OpenAI):
# alloy, echo, fable, onyx, nova, shimmer
TTS_VOICE=nova

# TTS speed (0.25 to 4.0)
TTS_SPEED=1.0
```

---

## Next Steps

After successful installation:

1. **Read Quick Start**: [QUICKSTART.md](./QUICKSTART.md)
2. **Explore Features**: Try voice commands, chat interface
3. **Configure Providers**: [MULTI_PROVIDER_SETUP.md](./MULTI_PROVIDER_SETUP.md)
4. **Join Community**: GitHub Discussions, Discord (TBD)
5. **Provide Feedback**: GitHub Issues

---

## Support

- **Documentation**: README.md, QUICKSTART.md, docs/
- **GitHub Issues**: Report bugs and request features
- **Verification Script**: `python scripts\verify_installation.py`

---

**Welcome to Aether AI!** 🚀
