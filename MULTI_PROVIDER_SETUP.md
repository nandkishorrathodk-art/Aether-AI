# Aether AI - Multi-Provider Setup Guide

## Overview

Aether AI now supports **6 AI providers** with intelligent routing, automatic fallback, and cost tracking:

- **OpenAI** (GPT-4, GPT-3.5)
- **Anthropic** (Claude 3 Opus/Sonnet/Haiku)
- **Google** (Gemini Pro/Flash)
- **Groq** (Ultra-fast Llama 3, Mixtral)
- **Fireworks AI** (Optimized open models)
- **OpenRouter** (Access to 50+ models)

## Quick Start

### 1. Get API Keys

Sign up and get API keys from providers you want to use:

- **OpenAI**: https://platform.openai.com/api-keys
- **Anthropic**: https://console.anthropic.com/
- **Google**: https://makersuite.google.com/app/apikey
- **Groq**: https://console.groq.com/keys
- **Fireworks**: https://fireworks.ai/api-keys
- **OpenRouter**: https://openrouter.ai/keys

### 2. Configure Environment

Copy `.env.example` to `.env` and add your API keys:

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Add at least ONE provider key
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=...
GROQ_API_KEY=gsk_...
FIREWORKS_API_KEY=fw_...
OPENROUTER_API_KEY=sk-or-v1-...

# Intelligent Routing (which provider for each task type)
ROUTER_CONVERSATION=groq          # Fast conversations
ROUTER_ANALYSIS=claude            # Deep analysis/SWOT
ROUTER_CODE=gpt-4                 # Code generation
ROUTER_CREATIVE=gemini            # Creative writing
ROUTER_FAST=groq                  # Speed priority
ROUTER_VISION=gpt-4-vision        # Image understanding

# Cost Management
ENABLE_COST_TRACKING=true
MAX_COST_PER_DAY_USD=10.0
FALLBACK_PROVIDER=groq
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Python API

```python
from src.cognitive.llm import model_loader, TaskType

# Simple conversation
response = await model_loader.generate(
    prompt="What is quantum computing?",
    task_type=TaskType.CONVERSATION
)
print(response.content)

# Code generation (automatically uses GPT-4)
response = await model_loader.generate(
    prompt="Write a binary search function in Python",
    task_type=TaskType.CODE
)

# Force specific provider
response = await model_loader.generate(
    prompt="Explain AI",
    provider="claude",
    model="claude-3-opus-20240229"
)

# Streaming response
async for chunk in model_loader.stream_generate(
    prompt="Tell me a story",
    task_type=TaskType.CREATIVE
):
    print(chunk, end="")
```

### REST API

Start the server:

```bash
python -m uvicorn src.api.main:app --reload
```

**Chat endpoint:**

```bash
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is 2+2?",
    "task_type": "conversation",
    "temperature": 0.7
  }'
```

**Get available providers:**

```bash
curl http://localhost:8000/api/v1/chat/providers
```

**Cost statistics:**

```bash
curl http://localhost:8000/api/v1/chat/cost-stats?hours=24
```

**Recommended provider for task:**

```bash
curl http://localhost:8000/api/v1/chat/recommended-provider/code
```

## Provider Comparison

| Provider | Speed | Cost | Quality | Best For |
|----------|-------|------|---------|----------|
| **Groq** | ⚡⚡⚡⚡⚡ | 💰 | ⭐⭐⭐⭐ | Fast conversations, real-time |
| **Claude** | ⚡⚡⚡ | 💰💰💰 | ⭐⭐⭐⭐⭐ | Analysis, reasoning, safety |
| **GPT-4** | ⚡⚡ | 💰💰💰💰 | ⭐⭐⭐⭐⭐ | Code, vision, complex tasks |
| **Gemini** | ⚡⚡⚡⚡ | 💰 | ⭐⭐⭐⭐ | Creative, multimodal, long context |
| **Fireworks** | ⚡⚡⚡⚡ | 💰 | ⭐⭐⭐ | Open models, customization |
| **OpenRouter** | ⚡⚡⚡ | 💰💰 | ⭐⭐⭐⭐ | Access to all models |

## Cost Optimization

The system automatically tracks costs and optimizes:

1. **Intelligent Routing**: Uses cheapest suitable provider for each task
2. **Automatic Fallback**: Switches to backup if primary fails
3. **Cost Tracking**: Monitors spend per provider/model/task
4. **Daily Limits**: Warns when approaching budget cap
5. **Recommendations**: Suggests most cost-effective provider based on usage

**View cost analytics:**

```python
from src.cognitive.llm import cost_tracker

# Last 24 hours
stats = cost_tracker.get_stats(hours=24)
print(f"Total: ${stats['total_cost']:.2f}")
print(f"By Provider: {stats['by_provider']}")

# Get cheapest provider for task type
best = cost_tracker.get_most_cost_effective_provider("conversation")
print(f"Best for conversation: {best}")
```

## Advanced Features

### Task-Type Routing

Configure which provider to use for each task type:

```python
# In .env
ROUTER_CONVERSATION=groq      # Groq is fast & cheap
ROUTER_ANALYSIS=claude        # Claude excels at reasoning
ROUTER_CODE=gpt-4            # GPT-4 best for code
ROUTER_CREATIVE=gemini       # Gemini great for creativity
ROUTER_VISION=gpt-4-vision   # Only GPT-4 has vision API
```

### Fallback & Retry

Automatic failover if provider is down:

```python
# Tries primary → fallback → any available
response = await model_loader.generate(
    prompt="Hello",
    task_type=TaskType.CONVERSATION
)
# Automatically retries with different providers on failure
```

### Conversation History

Maintain context across messages:

```python
history = [
    {"role": "user", "content": "My name is Alice"},
    {"role": "assistant", "content": "Nice to meet you, Alice!"}
]

response = await model_loader.generate(
    prompt="What's my name?",
    conversation_history=history
)
# Response: "Your name is Alice"
```

## Testing

Run the test script:

```bash
python scripts/test_providers.py
```

This will:
- List all configured providers
- Test conversation task
- Test code generation task
- Show cost statistics

## Troubleshooting

**Error: No AI providers configured**
- Add at least one API key to `.env`

**Error: Provider X failed**
- Check API key is valid
- Verify internet connection
- Check provider status page

**High costs**
- Adjust `MAX_COST_PER_DAY_USD` in `.env`
- Use cheaper providers (Groq, Gemini) for simple tasks
- Enable `ENABLE_COST_TRACKING=true`

**Slow responses**
- Use Groq for speed: `ROUTER_FAST=groq`
- Reduce `max_tokens` parameter
- Use streaming: `stream=True`

## Next Steps

1. Configure your preferred providers in `.env`
2. Test with `python scripts/test_providers.py`
3. Start the API: `uvicorn src.api.main:app --reload`
4. Build your AI assistant features!

## Architecture

```
┌─────────────────────────────────────┐
│         FastAPI Endpoint            │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│        Model Loader                 │
│  (Main Interface)                   │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│        Model Router                 │
│  (Intelligent Routing)              │
└────┬──────┬──────┬──────┬──────┬───┘
     │      │      │      │      │
  ┌──▼──┐┌─▼──┐┌──▼─┐┌──▼─┐┌───▼──┐
  │OpenAI││Claude││Gemini││Groq││...│
  └─────┘└────┘└────┘└────┘└──────┘
             │
┌────────────▼────────────────────────┐
│       Cost Tracker                  │
│  (Usage & Optimization)             │
└─────────────────────────────────────┘
```

For more details, see the main [README.md](./README.md)
