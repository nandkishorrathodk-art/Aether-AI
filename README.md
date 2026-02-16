# Aether AI - Hyper-Advanced Virtual Assistant

**The world's most advanced AI assistant** with human-level reasoning, multi-language support, and professional-grade analytics.

## 🚀 Version 0.2.0 - Hyper-Advanced

Aether AI has evolved from a basic assistant to an **unbeatable, enterprise-ready AI system** that combines advanced reasoning, global language support, and professional business intelligence.

## ✨ Key Differentiators

🧠 **Human-Level Reasoning** - Only AI with Chain-of-Thought + Tree-of-Thought + Self-Reflection  
🌍 **30+ Languages** - Global voice support (most competitors: 8-12)  
💼 **Business Intelligence** - Built-in SWOT, financial analysis, market research  
🔄 **Self-Aware** - Reflects on own outputs and improves them  
🎯 **Multi-Skilled** - Analytics + Reasoning + Voice + Automation  
🛡️ **Privacy-First** - Cloud-optional architecture  

## 🎯 Features (v0.2.0 Hyper-Advanced)

### 🧠 Advanced Reasoning Engine (NEW)
- **Chain-of-Thought**: Step-by-step problem solving with explicit reasoning
- **Tree-of-Thought**: Explores multiple solution paths simultaneously
- **Self-Reflection**: Analyzes own responses, detects errors, generates improvements
- **Metacognition**: Monitors thinking process, assesses certainty
- **Problem Decomposition**: Breaks complex tasks into manageable subproblems

### 🌐 Multi-Language Support (NEW - 30+ Languages)
- **European**: English, Spanish, French, German, Italian, Portuguese, Russian, Dutch, Polish, Ukrainian, Turkish
- **Asian**: Chinese, Japanese, Korean, Hindi, Bengali, Punjabi, Telugu, Marathi, Tamil, Urdu, Gujarati, Kannada, Vietnamese, Thai, Indonesian, Malay, Filipino
- **Middle Eastern/African**: Arabic, Urdu, Swahili
- Language-specific TTS voices (male/female)
- Automatic language detection
- RTL support for Arabic/Urdu

### 📊 Business Intelligence Suite (NEW)
- **SWOT Analysis**: Automated strategic analysis with insights and recommendations
- **Data Analytics**: CSV/Excel analysis with ML (PCA, K-Means clustering)
- **Financial Analysis**: Stock analysis, portfolio management, trend prediction
- **Market Research**: Competitive intelligence, market sizing, opportunity identification

### 🎤 Core Capabilities (v0.1.0)
- **Multi-Provider AI**: 6 providers (OpenAI, Claude, Gemini, Groq, Fireworks, OpenRouter)
- **Intelligent Routing**: Automatically selects best AI provider for each task
- **Cost Optimization**: Tracks spending and optimizes provider selection
- **Voice Interaction**: Natural conversation with wake word activation
- **Semantic Memory**: Remembers context and personalizes responses
- **Task Automation**: Controls applications and executes system tasks
- **Bug Bounty Automation**: BurpSuite integration with AI-powered vulnerability analysis
- **Modern UI**: Electron-based desktop application

## System Requirements

### Minimum
- **CPU**: Intel Core Ultra 5 or AMD Ryzen 7
- **RAM**: 8-16GB DDR4/DDR5
- **Storage**: 256GB SSD
- **OS**: Windows 10/11 (64-bit)
- **Internet**: Stable connection for AI API calls

### Recommended
- **CPU**: Intel Core Ultra 7 or AMD Ryzen 9
- **RAM**: 16-32GB DDR5
- **Storage**: 512GB SSD
- **Internet**: High-speed broadband

## Installation

### Quick Install (Recommended)

**Automated installer for Windows**:

```bash
# 1. Clone repository
git clone <repository-url>
cd nitro-v-f99b

# 2. Run installer
install.bat
```

The installer will:
- ✓ Check Python and Node.js
- ✓ Create virtual environment
- ✓ Install all dependencies (20-30 min)
- ✓ Build React application
- ✓ Create desktop shortcut
- ✓ Open configuration file for API keys

**After installation**:
1. Add API key(s) to `.env` file
2. Launch from desktop shortcut or run `start-aether.bat`

📖 **Detailed Instructions**: See [INSTALLATION.md](./INSTALLATION.md)

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

#### 1. Clone Repository
```bash
git clone <repository-url>
cd nitro-v-f99b
```

#### 2. Set Up Python Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### 3. Configure AI Providers
```bash
# Copy example configuration
copy .env.example .env

# Edit .env and add your API keys
notepad .env
```

**Get API Keys** (add at least ONE):
- **OpenAI**: https://platform.openai.com/api-keys
- **Anthropic**: https://console.anthropic.com/
- **Google**: https://makersuite.google.com/app/apikey
- **Groq**: https://console.groq.com/keys (FREE tier available!)
- **Fireworks**: https://fireworks.ai/api-keys
- **OpenRouter**: https://openrouter.ai/keys

Example `.env`:
```env
OPENAI_API_KEY=sk-...
GROQ_API_KEY=gsk_...
ANTHROPIC_API_KEY=sk-ant-...
```

#### 4. Set Up UI (Electron/React)
```bash
cd ui
npm install
```

#### 5. Verify Installation
```bash
venv\Scripts\activate
python scripts\verify_installation.py
```

</details>

## Quick Start

### Test AI Providers
```bash
# Activate virtual environment
venv\Scripts\activate

# Test your configured providers
python scripts/test_providers.py
```

### Run API Server
```bash
# Activate virtual environment
venv\Scripts\activate

# Start FastAPI server
uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000

# API will be available at: http://localhost:8000
# Interactive docs: http://localhost:8000/docs
```

### Run Frontend (Development)
```bash
cd ui
npm start
```

### Example API Usage

**Chat request:**
```bash
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Explain quantum computing in simple terms",
    "task_type": "conversation"
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

## Project Structure

```
nitro-v-f99b/
├── src/                    # Main application source
│   ├── api/               # FastAPI REST API
│   ├── cognitive/         # LLM and reasoning
│   │   ├── llm/          # Language model integration
│   │   └── memory/       # Vector DB and knowledge
│   ├── perception/        # Input processing
│   │   └── voice/        # STT and wake word
│   ├── action/           # Task execution
│   │   └── automation/   # System automation
│   ├── utils/            # Utilities and helpers
│   ├── config.py         # Configuration management
│   └── main.py           # Application entry point
├── ui/                    # Electron desktop app
│   ├── src/              # React components
│   └── main.js           # Electron main process
├── tests/                # Test suites
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
├── models/               # AI model weights (gitignored)
├── data/                 # User data and databases (gitignored)
├── logs/                 # Application logs (gitignored)
├── scripts/              # Setup and utility scripts
└── requirements.txt      # Python dependencies
```

## Configuration

Edit `.env` file to customize:

### AI Provider Settings
- **API Keys**: Add keys for providers you want to use
- **Task Routing**: Which provider for each task type (conversation, code, analysis, etc.)
- **Cost Limits**: `MAX_COST_PER_DAY_USD=10.0`
- **Fallback Provider**: Backup if primary fails

### Voice Settings
- **Wake Word**: Change `WAKE_WORD` (default: "hey aether")
- **Voice Provider**: `openai` (uses OpenAI TTS/STT)
- **Voice Settings**: Toggle input/output, select voice gender

### Performance
- **Temperature**: Adjust creativity (0.0-2.0)
- **Max Tokens**: Response length limit
- **Security**: Set secret key and allowed origins

See [MULTI_PROVIDER_SETUP.md](./MULTI_PROVIDER_SETUP.md) for detailed configuration guide.

## Development

### Running Tests
```bash
# All tests
pytest tests/ -v

# Unit tests only
pytest tests/unit/ -v

# With coverage
pytest tests/ -v --cov=src --cov-report=html
```

### Code Quality
```bash
# Linting
flake8 src/ --max-line-length=100

# Type checking
mypy src/

# Code formatting
black src/
```

## Troubleshooting

### Common Issues

**Issue**: "No AI providers configured"
- **Solution**: Add at least one API key to `.env` file

**Issue**: High API costs
- **Solution**: Adjust `MAX_COST_PER_DAY_USD` in `.env`
- Use cheaper providers (Groq, Gemini) for simple tasks
- Enable cost tracking: `ENABLE_COST_TRACKING=true`

**Issue**: Provider API errors
- **Solution**: Verify API key is valid
- Check provider status page
- System will auto-fallback to other providers

**Issue**: Slow responses
- **Solution**: Use Groq for speed (set `ROUTER_FAST=groq`)
- Enable streaming: `"stream": true` in API request

### Performance Optimization

- Use Groq for fast conversations (300+ tokens/sec)
- Use GPT-3.5-turbo instead of GPT-4 for simple tasks
- Enable intelligent routing to auto-select best provider
- Monitor costs with `/api/v1/chat/cost-stats`

## Deployment

### Building Installer

Create Windows installer for distribution:

```bash
# Build NSIS installer and portable executable
build-installer.bat
```

**Output**:
- `ui/dist/Aether AI Setup 0.1.0.exe` - NSIS installer
- `ui/dist/AetherAI-0.1.0-portable.exe` - Portable version

📖 **Full Guide**: See [docs/DEPLOYMENT.md](./docs/DEPLOYMENT.md)

## Bug Bounty Automation

Aether AI includes powerful bug bounty automation with **BurpSuite integration** and **AI-powered vulnerability analysis**.

### Features

- **🔍 Reconnaissance**: Automated subdomain enumeration and asset discovery
- **🛡️ BurpSuite Integration**: Automated security scanning with BurpSuite Pro API
- **🧠 AI Analysis**: Intelligent vulnerability classification and false positive filtering
- **💥 Exploit Generation**: Safe POC exploits with WAF bypass techniques
- **📝 Report Generation**: Professional bug bounty reports for HackerOne, Bugcrowd, etc.
- **✅ Scope Validation**: Automatic out-of-scope detection for ethical testing

### Quick Start

```bash
# Test bug bounty features
test-bugbounty.bat

# Configure BurpSuite (requires BurpSuite Pro running)
# Then use API endpoints or Python scripts
```

### Example Usage

```python
import requests

# Start reconnaissance
recon = requests.post("http://localhost:8000/api/v1/bugbounty/recon", json={
    "domain": "example.com",
    "program_name": "Example Bug Bounty",
    "scope": ["*.example.com"]
})

# Start automated scan
scan = requests.post("http://localhost:8000/api/v1/bugbounty/scan", json={
    "target_url": "https://app.example.com",
    "scan_type": "CrawlAndAudit"
})

# Get vulnerabilities and generate report
scan_id = scan.json()["scan_id"]
# ... wait for scan ...
vulns = requests.get(f"http://localhost:8000/api/v1/bugbounty/scan/{scan_id}/issues")
```

### ⚠️ Ethical Use Only

**WARNING**: Only use on authorized targets (bug bounty programs, pentests with permission, personal projects).

📖 **Complete Guide**: [docs/BUGBOUNTY_AUTOMATION.md](./docs/BUGBOUNTY_AUTOMATION.md)

### Distribution Package

The build script creates a release folder with:
- Installers (NSIS + Portable)
- Documentation (README, QUICKSTART, CHANGELOG)
- License

Ready to upload to GitHub Releases or distribute.

## Uninstallation

### Quick Uninstall

```bash
# Removes Aether AI but keeps configuration
uninstall.bat
```

Choose whether to keep or remove:
- `.env` file (API keys)
- `data/` folder (conversations, memory)
- `logs/` folder (application logs)

📖 **Details**: See [INSTALLATION.md](./INSTALLATION.md#uninstallation)

## Roadmap

- **Phase 1 (Current)**: MVP - Core voice assistant functionality
- **Phase 2**: Enhanced intelligence with chain-of-thought reasoning
- **Phase 3**: Professional tools (SWOT, analytics, automation suite)
- **Phase 4**: Advanced features (self-improvement, quantum integration)

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Acknowledgments

- Inspired by Marvel's Jarvis AI
- Built with FastAPI, Electron, and React
- Powered by OpenAI, Anthropic, Google, Groq, Fireworks, and OpenRouter
- Multi-provider architecture for reliability and cost optimization

## Support

For issues, questions, or feature requests:
- Open an issue on GitHub
- Contact: [your-email@example.com]

---

**Note**: This is an MVP (v0.1.0) release. Advanced features like SWOT analysis, quantum integration, and self-evolution will be added in future phases.
#   A e t h e r - A I  
 