# Aether AI v0.9.0 - Quick Start Guide

**Get up and running with ULTIMATE PERSONAL OMEGA JARVIS in 5 minutes! 🚀**

---

## Prerequisites

- **OS**: Windows 10/11 (64-bit)
- **Python**: 3.11+ ([Download](https://www.python.org/downloads/))
- **Node.js**: 18+ ([Download](https://nodejs.org/))
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 2GB free space

---

## Step 1: Clone & Install (2 minutes)

```bash
# Clone repository
git clone https://github.com/nandkishorrathodk-art/Aether-AI.git
cd Aether-AI

# Run automated installer (handles everything!)
install.bat
```

The installer will:
- ✅ Check Python and Node.js versions
- ✅ Create virtual environment
- ✅ Install all dependencies (89 packages)
- ✅ Build React UI
- ✅ Create desktop shortcut
- ✅ Open `.env` configuration file

**Time**: 2-3 minutes (depending on internet speed)

---

## Step 2: Configure API Keys (1 minute)

Open the `.env` file (automatically opened by installer) and add at least **ONE** AI provider key:

```env
# Required: At least one AI provider
OPENAI_API_KEY=sk-...
# OR
GROQ_API_KEY=gsk_...         # FREE tier available!
# OR
ANTHROPIC_API_KEY=sk-ant-...

# Optional: Enable v0.9.0 features
ENABLE_PROACTIVE_MODE=true
ENABLE_SCREEN_MONITORING=false   # Set to true for screen awareness
ENABLE_PC_CONTROL=false          # Set to true for PC automation
ENABLE_BUGBOUNTY_AUTOPILOT=false # Set to true for bug bounty
ENABLE_DAILY_REPORTS=true
```

**Get FREE API Keys**:
- **Groq**: https://console.groq.com/keys (FREE, fast, recommended for beginners)
- **OpenAI**: https://platform.openai.com/api-keys (Pay-as-you-go)
- **Anthropic**: https://console.anthropic.com/ (Claude - powerful)

---

## Step 3: Launch Aether AI (30 seconds)

### Option A: Desktop Shortcut
Double-click the **Aether AI** shortcut on your desktop

### Option B: Command Line
```bash
# Activate virtual environment
venv\Scripts\activate

# Start backend API
uvicorn src.api.main:app --host 127.0.0.1 --port 8000

# In another terminal, start UI
cd ui
npm start
```

### Option C: All-in-One Launcher
```bash
START_AETHER.bat
```

---

## Step 4: Test Core Features (1 minute)

### Test Chat (Basic AI)
```bash
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello! Who are you?", "task_type": "conversation"}'
```

**Expected Response**: Friendly introduction from Aether AI

### Test Proactive Brain (v0.9.0 NEW!)
```bash
curl http://localhost:8000/api/v1/proactive/suggestions
```

**Expected Response**: Time-aware suggestions based on current time

### Test Daily Plan (v0.9.0 NEW!)
```bash
curl http://localhost:8000/api/v1/proactive/daily-plan
```

**Expected Response**: Generated daily plan with goals and schedule

---

## Step 5: Enable v0.9.0 God-Mode Features (Optional)

### Enable Screen Monitoring
```env
# In .env file
ENABLE_SCREEN_MONITORING=true
SCREEN_CAPTURE_INTERVAL=30
```

**Restart Aether**, then test:
```bash
# Start monitoring
curl -X POST http://localhost:8000/api/v1/monitor/start

# Get current screen context
curl http://localhost:8000/api/v1/monitor/current-context
```

### Enable PC Control (USE WITH CAUTION!)
```env
# In .env file
ENABLE_PC_CONTROL=true
PC_CONTROL_REQUIRE_CONFIRMATION=true
```

**Restart Aether**, then test:
```bash
# Launch Notepad (safe test)
curl -X POST http://localhost:8000/api/v1/control/app/launch \
  -H "Content-Type: application/json" \
  -d '{"app": "notepad"}'
```

### Enable Bug Bounty Autopilot (Requires Burp Suite Pro)
```env
# In .env file
ENABLE_BUGBOUNTY_AUTOPILOT=true
BURPSUITE_API_URL=http://127.0.0.1:1337
BURPSUITE_API_KEY=your-burp-api-key
```

**Prerequisites**: 
1. Install Burp Suite Professional
2. Enable REST API in Burp (User options → Misc → REST API)
3. Set API key in Burp settings

**Test**:
```bash
# Check status
curl http://localhost:8000/api/v1/bugbounty/auto/status
```

See [BUGBOUNTY_AUTOPILOT.md](./BUGBOUNTY_AUTOPILOT.md) for complete guide.

---

## Quick Command Reference

### Start Aether
```bash
START_AETHER.bat
```

### Stop Aether
```bash
STOP_AETHER.bat
# Or press Ctrl+C in terminal
```

### Restart Aether
```bash
RESTART_AETHER.bat
```

### Test All Features
```bash
test-all-features.py
```

### Check Logs
```bash
type logs\aether.log
```

---

## Interactive API Documentation

Once Aether is running, visit:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

---

## Common Issues & Solutions

### Issue: "Python not found"
**Solution**: Install Python 3.11+ from https://www.python.org/downloads/
- ✅ Check "Add Python to PATH" during installation

### Issue: "Node.js not found"
**Solution**: Install Node.js 18+ from https://nodejs.org/

### Issue: "Port 8000 already in use"
**Solution**: 
```bash
# Kill process on port 8000
netstat -ano | findstr :8000
taskkill /PID <process_id> /F
```

### Issue: "ModuleNotFoundError"
**Solution**:
```bash
venv\Scripts\activate
pip install -r requirements.txt
```

### Issue: "Screen monitoring not working"
**Solution**: 
- Ensure `ENABLE_SCREEN_MONITORING=true` in `.env`
- Restart Aether after changing `.env`
- Check logs for errors: `type logs\aether.log`

### Issue: "PC control actions not executing"
**Solution**:
- Ensure `ENABLE_PC_CONTROL=true` in `.env`
- Check `PC_CONTROL_ALLOWED_ACTIONS` includes the action
- If `PC_CONTROL_REQUIRE_CONFIRMATION=true`, check prompts
- Review audit log: `type data\control_audit.log`

---

## Next Steps

### Explore v0.9.0 Features
- 📖 Read [FEATURES_v0.9.0.md](./FEATURES_v0.9.0.md) for comprehensive guide
- 🐛 Set up [Bug Bounty Autopilot](./BUGBOUNTY_AUTOPILOT.md)
- 🎮 Configure [PC Control](./PC_CONTROL_GUIDE.md)
- 🎭 Customize [Personality](./PERSONALITY_CUSTOMIZATION.md)

### Customize Personality
```env
# In .env file
PERSONALITY_MODE=friendly
PERSONALITY_ENABLE_HINDI_ENGLISH=true
PERSONALITY_EMOJI_ENABLED=true
PERSONALITY_MOTIVATIONAL_ENABLED=true
PERSONALITY_HUMOR_ENABLED=true
```

**Chat with Hinglish personality**:
```bash
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Aaj mera mood thik nahi hai", "task_type": "conversation"}'
```

**Expected Response**: Supportive response in Hindi-English mix with motivation

### Set Up Daily Reports
```env
# In .env file
ENABLE_DAILY_REPORTS=true
DAILY_REPORT_TIME=20:00  # 8 PM daily report
```

**View reports**:
```bash
curl http://localhost:8000/api/v1/intelligence/daily-report
```

### Track Earnings (Bug Bounty)
```bash
# View earnings stats
curl http://localhost:8000/api/v1/intelligence/earnings
```

### Get Trending Topics
```bash
# Get current trends
curl http://localhost:8000/api/v1/intelligence/trends
```

---

## Usage Examples

### Example 1: Morning Routine
```bash
# Get daily plan
curl http://localhost:8000/api/v1/proactive/daily-plan

# Get suggestions
curl http://localhost:8000/api/v1/proactive/suggestions

# Check trends
curl http://localhost:8000/api/v1/intelligence/trends
```

### Example 2: Bug Bounty Session
```bash
# Start screen monitoring
curl -X POST http://localhost:8000/api/v1/monitor/start

# Launch Burp Suite
curl -X POST http://localhost:8000/api/v1/control/app/launch \
  -H "Content-Type: application/json" \
  -d '{"app": "burpsuite"}'

# Start auto hunting
curl -X POST http://localhost:8000/api/v1/bugbounty/auto/start \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "active"}'

# Check progress
curl http://localhost:8000/api/v1/bugbounty/auto/status

# Generate report
curl -X POST http://localhost:8000/api/v1/bugbounty/auto/generate-report \
  -H "Content-Type: application/json" \
  -d '{"format": "html"}'
```

### Example 3: Content Creation Session
```bash
# Get YouTube trends
curl http://localhost:8000/api/v1/intelligence/trends

# Ask for content ideas
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Give me 10 YouTube video ideas for high CPM niches in February 2026", "task_type": "creative"}'

# Get daily plan for content creation
curl http://localhost:8000/api/v1/proactive/daily-plan
```

---

## Performance Tips

### Optimize for Low-End Systems
```env
# In .env file
SCREEN_CAPTURE_INTERVAL=60  # Reduce frequency
ENABLE_SCREEN_MONITORING=false  # Disable if not needed
LLM_MAX_TOKENS=1024  # Reduce token limit
```

### Optimize for Speed
```env
# Use fastest providers
ROUTER_FAST=groq
ROUTER_CONVERSATION=groq
AI_PROVIDER=groq
```

### Optimize for Quality
```env
# Use best models
DEFAULT_MODEL=gpt-4-turbo-preview
ROUTER_ANALYSIS=claude
ROUTER_CODE=gpt-4
```

---

## Security Best Practices

1. **Never share your `.env` file** - Contains API keys
2. **Keep PC control disabled** unless actively using it
3. **Use confirmation prompts** for PC control: `PC_CONTROL_REQUIRE_CONFIRMATION=true`
4. **Review audit logs** regularly: `data\control_audit.log`
5. **Use screen monitoring selectively** - Can capture sensitive data
6. **Set cost limits**: `MAX_COST_PER_DAY_USD=10.0`
7. **Keep API keys secure** - Don't commit to Git

---

## Support & Resources

- **Documentation**: [README.md](./README.md)
- **API Reference**: http://localhost:8000/docs (when running)
- **Changelog**: [CHANGELOG.md](./CHANGELOG.md)
- **Bug Reports**: GitHub Issues
- **Feature Requests**: GitHub Discussions

---

## What's Next?

You're now ready to use Aether AI v0.9.0! Here's what you can explore:

1. ✅ **Basic Chat** - Talk to Aether like a friend
2. ✅ **Proactive Suggestions** - Let Aether suggest what to do
3. ✅ **Daily Planning** - Get automated daily plans
4. ✅ **Trend Analysis** - Stay updated with latest trends
5. 🔧 **Screen Monitoring** - Enable contextual awareness (optional)
6. 🔧 **PC Control** - Automate your workflows (use with caution)
7. 🔧 **Bug Bounty Autopilot** - Automate vulnerability hunting (requires Burp Pro)

**Happy hacking! 🚀**

---

*Aether AI v0.9.0 - ULTIMATE PERSONAL OMEGA JARVIS*  
*"Ji boss! Main aapke saath hoon 24/7!" (Boss, I'm with you 24/7!)*
