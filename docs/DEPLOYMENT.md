# Aether AI Deployment Guide

Complete guide for packaging and deploying Aether AI.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Development Build](#development-build)
- [Production Build](#production-build)
- [Creating Installer](#creating-installer)
- [Distribution](#distribution)
- [Auto-Update Configuration](#auto-update-configuration)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

- **Python 3.8+**: [Download](https://www.python.org/downloads/)
- **Node.js 18+**: [Download](https://nodejs.org/)
- **Git**: [Download](https://git-scm.com/)

### Required API Keys

At least ONE AI provider API key:
- **OpenAI**: https://platform.openai.com/api-keys
- **Groq** (FREE): https://console.groq.com/keys
- **Anthropic**: https://console.anthropic.com/
- **Google**: https://makersuite.google.com/app/apikey
- **Fireworks**: https://fireworks.ai/api-keys
- **OpenRouter**: https://openrouter.ai/keys

---

## Development Build

### 1. Clone Repository

```bash
git clone <repository-url>
cd nitro-v-f99b
```

### 2. Install Dependencies

```bash
# Run automated installer
install.bat

# OR manual installation:

# Python dependencies
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Node.js dependencies
cd ui
npm install
cd ..
```

### 3. Configure Environment

```bash
# Copy example configuration
copy .env.example .env

# Edit .env and add API keys
notepad .env
```

### 4. Verify Installation

```bash
venv\Scripts\activate
python scripts\setup.py
```

### 5. Run Development Server

```bash
# Terminal 1: Backend
venv\Scripts\activate
uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2: Frontend
cd ui
npm run dev
```

---

## Production Build

### 1. Build React Application

```bash
cd ui
npm run build
```

This creates optimized production files in `ui/build/`.

### 2. Test Production Build

```bash
# Start backend
venv\Scripts\activate
uvicorn src.api.main:app --host 127.0.0.1 --port 8000

# Start Electron with production build
cd ui
npm start
```

### 3. Run Tests

```bash
# Python tests
venv\Scripts\activate
pytest tests/ -v --cov=src --cov-report=html

# Frontend tests
cd ui
npm test
npm run test:e2e
```

### 4. Code Quality Checks

```bash
# Linting
flake8 src/ --max-line-length=100

# Type checking
mypy src/

# Code formatting
black src/ --check
```

---

## Creating Installer

### 1. Prepare for Packaging

```bash
# Ensure all dependencies are installed
cd ui
npm install electron-builder --save-dev

# Build React app
npm run build
```

### 2. Build Windows Installer

```bash
cd ui
npm run package
```

This creates:
- **NSIS Installer**: `ui/dist/Aether AI Setup 0.1.0.exe`
- **Portable Version**: `ui/dist/AetherAI-0.1.0-portable.exe`

### 3. Installer Features

**NSIS Installer** (`Aether AI Setup 0.1.0.exe`):
- Custom installation directory
- Desktop and Start Menu shortcuts
- Uninstaller included
- No admin privileges required
- Auto-run after installation

**Portable Version** (`AetherAI-0.1.0-portable.exe`):
- No installation required
- Run from USB drive
- Portable configuration
- All data in single folder

### 4. Test Installer

```bash
# Test on clean Windows VM or another PC
1. Copy installer to test machine
2. Run installer
3. Verify installation completes
4. Launch Aether AI from desktop shortcut
5. Test core functionality
6. Run uninstaller
7. Verify complete removal
```

---

## Distribution

### File Structure

```
Aether-AI-v0.1.0-Release/
├── Aether AI Setup 0.1.0.exe     # Main installer (NSIS)
├── AetherAI-0.1.0-portable.exe   # Portable version
├── README.md                      # Installation instructions
├── QUICKSTART.md                  # Getting started guide
├── CHANGELOG.md                   # Version history
└── LICENSE                        # MIT License
```

### Distribution Checklist

- [ ] Build installers (NSIS + Portable)
- [ ] Test on clean Windows 10/11 machines
- [ ] Verify all features work
- [ ] Include documentation (README, QUICKSTART, CHANGELOG)
- [ ] Create release notes
- [ ] Sign executables (optional for MVP)
- [ ] Upload to distribution platform (GitHub Releases, website)

### GitHub Release

1. **Create Release Tag**:
   ```bash
   git tag -a v0.1.0 -m "MVP Release v0.1.0"
   git push origin v0.1.0
   ```

2. **Upload Artifacts**:
   - Go to GitHub → Releases → Create New Release
   - Select tag: `v0.1.0`
   - Title: `Aether AI v0.1.0 - MVP Release`
   - Upload:
     - `Aether AI Setup 0.1.0.exe`
     - `AetherAI-0.1.0-portable.exe`
     - `README.md`
     - `QUICKSTART.md`
     - `CHANGELOG.md`

3. **Write Release Notes**:
   ```markdown
   ## Aether AI v0.1.0 - MVP Release
   
   First public release of Aether AI virtual assistant!
   
   ### Features
   - Multi-provider AI support (OpenAI, Claude, Gemini, Groq, etc.)
   - Voice interaction with wake word detection
   - Semantic memory and context awareness
   - Task automation and system control
   - Modern Electron-based UI
   
   ### Installation
   1. Download `Aether AI Setup 0.1.0.exe`
   2. Run installer (no admin required)
   3. Add API keys to .env file
   4. Launch from desktop shortcut
   
   ### Requirements
   - Windows 10/11 (64-bit)
   - 8-16GB RAM
   - 256GB SSD
   - Internet connection
   
   ### Known Issues
   - See GitHub Issues for current bugs
   
   ### Documentation
   - [Quick Start Guide](QUICKSTART.md)
   - [README](README.md)
   - [Multi-Provider Setup](MULTI_PROVIDER_SETUP.md)
   ```

---

## Auto-Update Configuration

### Enable Auto-Updates

Edit `ui/main.js` to add auto-updater:

```javascript
const { app, autoUpdater } = require('electron');

// Configure update server
const server = 'https://your-update-server.com';
const feed = `${server}/update/${process.platform}/${app.getVersion()}`;

autoUpdater.setFeedURL({ url: feed });

// Check for updates on startup
app.on('ready', () => {
  autoUpdater.checkForUpdates();
});

// Handle update events
autoUpdater.on('update-downloaded', () => {
  dialog.showMessageBox({
    type: 'info',
    title: 'Update Available',
    message: 'A new version of Aether AI is ready to install.',
    buttons: ['Restart', 'Later']
  }).then((result) => {
    if (result.response === 0) {
      autoUpdater.quitAndInstall();
    }
  });
});
```

### Configure Update Server

Update `ui/package.json`:

```json
"build": {
  "publish": {
    "provider": "github",
    "owner": "your-username",
    "repo": "aether-ai",
    "releaseType": "release"
  }
}
```

For GitHub releases, electron-builder automatically handles updates.

---

## Troubleshooting

### Build Issues

**Issue**: `electron-builder` fails with "Cannot find module"
- **Solution**: Run `npm install` in `ui/` directory

**Issue**: Build fails due to missing icon
- **Solution**: Ensure `ui/assets/icon.ico` exists (256x256 PNG converted to ICO)

**Issue**: Python dependencies not bundled
- **Solution**: Python environment is NOT bundled in Electron app. Users must install Python separately via `install.bat`

### Installer Issues

**Issue**: Installer requires admin privileges
- **Solution**: Set `"allowElevation": false` in `package.json` NSIS config

**Issue**: Antivirus flags installer
- **Solution**: 
  - Code sign the executable
  - Submit to antivirus vendors for whitelisting
  - Build on clean machine without dev tools

**Issue**: Uninstaller doesn't remove shortcuts
- **Solution**: Ensure NSIS config has `createDesktopShortcut: true`

### Runtime Issues

**Issue**: Backend server doesn't start
- **Solution**: Check `logs/backend.log` for errors. Verify Python virtual environment is activated.

**Issue**: Frontend can't connect to backend
- **Solution**: Verify backend is running on `http://localhost:8000`. Check CORS settings in `src/api/main.py`.

**Issue**: Voice features not working
- **Solution**: 
  - Check microphone permissions
  - Verify PyAudio is installed: `pip install pyaudio`
  - On Windows, may need to install PortAudio

---

## Performance Optimization

### Backend Optimization

1. **Use Groq for speed**: Set `ROUTER_FAST=groq` in `.env`
2. **Enable caching**: TTS cache is enabled by default
3. **Limit conversation history**: Set `MAX_CONVERSATION_HISTORY=10` in `.env`

### Frontend Optimization

1. **Enable production build**: `npm run build` instead of `npm run dev`
2. **Reduce bundle size**: Use code splitting in React components
3. **Lazy loading**: Load components on demand

### Resource Usage

- **Memory**: 200-500MB (depends on model size)
- **CPU**: 5-15% idle, 30-60% during inference
- **Disk**: 2-5GB (with models and cache)

---

## Security Considerations

### Code Signing

For production releases, sign executables:

1. **Acquire Code Signing Certificate**:
   - Purchase from DigiCert, Sectigo, or other CA
   - Cost: ~$100-300/year

2. **Configure electron-builder**:
   ```json
   "win": {
     "certificateFile": "path/to/certificate.pfx",
     "certificatePassword": "your-password",
     "signAndEditExecutable": true
   }
   ```

3. **Sign after build**:
   ```bash
   signtool sign /f certificate.pfx /p password /tr http://timestamp.digicert.com /td sha256 /fd sha256 "Aether AI Setup 0.1.0.exe"
   ```

### Environment Security

- **Never commit `.env`**: Add to `.gitignore`
- **Never bundle API keys**: Users must provide their own
- **Encrypt sensitive data**: Use encryption for stored credentials
- **Validate inputs**: All user inputs sanitized in backend

---

## Deployment Metrics

Track these metrics post-deployment:

- **Download count**: GitHub release downloads
- **Installation success rate**: User feedback
- **Crash reports**: Integrate Sentry or similar
- **API usage**: Track provider costs
- **User retention**: Active users per week

---

## Support and Maintenance

### User Support

- **Documentation**: Keep README, QUICKSTART, and docs updated
- **GitHub Issues**: Monitor and respond to bug reports
- **Discord/Slack**: Community support channel
- **Email**: Support email for critical issues

### Maintenance Schedule

- **Weekly**: Check GitHub issues, respond to user feedback
- **Monthly**: Review and update dependencies
- **Quarterly**: Major feature releases, security audits
- **Yearly**: Review architecture, plan major refactors

---

## Next Steps

After successful deployment:

1. **Gather user feedback**: Surveys, analytics, GitHub issues
2. **Plan Phase 2**: Enhanced intelligence features
3. **Improve documentation**: Video tutorials, blog posts
4. **Build community**: Discord server, contributor guide
5. **Marketing**: Social media, product hunt, tech blogs

---

**Questions or issues?** Open an issue on GitHub or contact the team.

Happy deploying! 🚀
