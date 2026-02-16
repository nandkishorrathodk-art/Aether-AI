# Quick Start Guide - Aether AI

Get your AI assistant running in **5 minutes**!

## Step 1: Install Dependencies

```bash
# Install Python packages
pip install -r requirements.txt
```

## Step 2: Get API Keys

**Choose at least ONE provider** (Groq has FREE tier!):

| Provider | Free Tier | Sign Up Link |
|----------|-----------|--------------|
| **Groq** | ✅ FREE | https://console.groq.com/keys |
| **OpenAI** | $5 credit | https://platform.openai.com/api-keys |
| **Anthropic** | No free tier | https://console.anthropic.com/ |
| **Google** | ✅ FREE | https://makersuite.google.com/app/apikey |
| **Fireworks** | $1 credit | https://fireworks.ai/api-keys |
| **OpenRouter** | Trial credits | https://openrouter.ai/keys |

**Recommendation**: Start with **Groq** (free + ultra-fast) or **Google Gemini** (free + powerful)

## Step 3: Configure

Edit `.env` file and add your API key:

```env
# For Groq (FREE and fast!)
GROQ_API_KEY=gsk_your_key_here

# Or for OpenAI
OPENAI_API_KEY=sk_your_key_here

# Or for Google Gemini (FREE!)
GOOGLE_API_KEY=your_key_here
```

## Step 4: Verify Setup

```bash
python scripts/setup.py
```

Or on Windows, double-click: `test_setup.bat`

## Step 5: Start Server

```bash
uvicorn src.api.main:app --reload
```

Or on Windows, double-click: `start_server.bat`

**Server will run at**: http://localhost:8000
**API Docs**: http://localhost:8000/docs

## Step 6: Test It!

### Option 1: Browser (Interactive Docs)

1. Open http://localhost:8000/docs
2. Click on `POST /api/v1/chat`
3. Click "Try it out"
4. Paste this JSON:
```json
{
  "prompt": "What is 2+2?",
  "task_type": "conversation"
}
```
5. Click "Execute"

### Option 2: Command Line

```bash
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -d "{\"prompt\": \"What is 2+2?\", \"task_type\": \"conversation\"}"
```

### Option 3: Python Script

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/chat",
    json={
        "prompt": "Explain quantum computing in one sentence",
        "task_type": "conversation"
    }
)

data = response.json()
print(data["content"])
print(f"Provider: {data['provider']}, Cost: ${data['cost_usd']:.6f}")
```

## Common Use Cases

### Fast Conversation (Groq)
```json
{
  "prompt": "Tell me a joke",
  "task_type": "fast"
}
```

### Code Generation (GPT-4)
```json
{
  "prompt": "Write a Python function to calculate fibonacci",
  "task_type": "code"
}
```

### Analysis (Claude)
```json
{
  "prompt": "Analyze the pros and cons of remote work",
  "task_type": "analysis"
}
```

### Creative Writing (Gemini)
```json
{
  "prompt": "Write a short sci-fi story about AI",
  "task_type": "creative"
}
```

### Force Specific Provider
```json
{
  "prompt": "Hello",
  "provider": "groq",
  "model": "llama3-70b-8192"
}
```

## Monitor Costs

Check your spending:

```bash
curl http://localhost:8000/api/v1/chat/cost-stats?hours=24
```

Response:
```json
{
  "total_cost": 0.0023,
  "total_requests": 5,
  "avg_cost_per_request": 0.00046,
  "by_provider": {
    "groq": 0.0008,
    "openai": 0.0015
  }
}
```

## Troubleshooting

### "No AI providers configured"
➜ Add at least one API key to `.env`

### Server won't start
➜ Run: `pip install -r requirements.txt`

### API key errors
➜ Verify your key is correct and has credits

### Slow responses
➜ Use Groq: Set `ROUTER_FAST=groq` in `.env`

## Next Steps

1. ✅ **Working?** Great! Now explore the [API docs](http://localhost:8000/docs)
2. 📊 **Check costs**: `curl http://localhost:8000/api/v1/chat/cost-stats`
3. 🎤 **Add voice**: See voice integration guide (coming soon)
4. 🔧 **Customize**: Edit `.env` to configure task routing
5. 📖 **Learn more**: Read [MULTI_PROVIDER_SETUP.md](./MULTI_PROVIDER_SETUP.md)

## Quick Reference

| Action | Command |
|--------|---------|
| **Install** | `pip install -r requirements.txt` |
| **Setup check** | `python scripts/setup.py` |
| **Start server** | `uvicorn src.api.main:app --reload` |
| **Test providers** | `python scripts/test_providers.py` |
| **View docs** | http://localhost:8000/docs |
| **Check costs** | `curl http://localhost:8000/api/v1/chat/cost-stats` |

---

**Need help?** Check the [README.md](./README.md) or [MULTI_PROVIDER_SETUP.md](./MULTI_PROVIDER_SETUP.md)
