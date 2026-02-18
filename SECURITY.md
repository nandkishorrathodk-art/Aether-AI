# 🛡️ Aether AI Security Documentation

**Version**: v0.9.0  
**Last Updated**: February 2026

## Overview

Aether AI v0.9.0 introduces powerful features including screen monitoring, PC control, and automated bug bounty hunting. This document outlines security measures, best practices, and potential risks.

---

## 🔐 Core Security Principles

### 1. **Permission-Based Architecture**
- All sensitive actions require explicit user permission
- Whitelist/blacklist system for PC control actions
- Audit logging for all system interactions

### 2. **Data Privacy**
- Screenshots stored locally, never sent to external servers without consent
- Conversation history encrypted at rest
- API keys stored in `.env` (never committed to version control)

### 3. **Safe Defaults**
- Screen monitoring disabled by default
- PC control requires confirmation for destructive actions
- Bug bounty targets must be explicitly authorized

---

## 🖥️ Screen Monitoring Security

### **Privacy Considerations**

**What is captured:**
- Desktop screenshots at configurable intervals (default: 30 seconds)
- Active window titles and running application names
- Context analysis via LLM (local processing)

**Data Storage:**
- Screenshots: `data/screenshots/` (configurable retention)
- Metadata: SQLite database with timestamps
- Automatic cleanup after 7 days (configurable)

**User Controls:**
```python
# In .env
ENABLE_SCREEN_MONITORING=false  # Must be explicitly enabled
SCREENSHOT_INTERVAL=30          # Seconds between captures
SCREENSHOT_RETENTION_DAYS=7     # Auto-delete old screenshots
SCREENSHOT_SAVE_TO_DISK=false   # Keep in memory only
```

### **Best Practices**
- ✅ Enable only when actively working on tasks requiring context
- ✅ Use in-memory mode for sensitive work (no disk storage)
- ✅ Review and delete screenshots regularly
- ✅ Disable before video calls or sharing screen
- ❌ Never enable on shared computers
- ❌ Never run with elevated privileges unless necessary

---

## 🎮 PC Control Security

### **Permission System**

All PC control actions go through the Permission Manager:

```python
# src/control/permission_manager.py
WHITELIST = ["notepad", "chrome", "burpsuite"]  # Allowed apps
BLACKLIST = ["regedit", "cmd", "powershell"]    # Blocked apps
REQUIRE_CONFIRMATION = True                      # Prompt before execution
```

### **Action Categories**

| Action Type | Risk Level | Default Permission |
|-------------|------------|-------------------|
| Mouse Click | Low | Allowed |
| Keyboard Type | Medium | Allowed with confirmation |
| Launch App | Medium | Whitelist only |
| Close App | Medium | Confirmation required |
| File Delete | High | Blocked by default |
| System Command | Critical | Blocked by default |

### **Audit Logging**

All actions logged to `data/control_audit.log`:

```log
2026-02-18 12:30:45 | ACTION:mouse_click | X:100 Y:200 | STATUS:success | USER:approved
2026-02-18 12:31:10 | ACTION:app_launch | APP:burpsuite | STATUS:success | USER:approved
2026-02-18 12:32:00 | ACTION:keyboard_type | TEXT:test | STATUS:success | USER:approved
```

### **Security Features**
- 🔒 Sandboxed execution (no elevated privileges)
- 🔒 Action rollback for reversible operations
- 🔒 Rate limiting (max 10 actions/minute)
- 🔒 Timeout protection (5-second execution limit)
- 🔒 Emergency stop command: "Jarvis stop all actions"

---

## 🐛 Bug Bounty Automation Security

### **Ethical Hacking Guidelines**

**CRITICAL**: Bug bounty automation is for **authorized testing only**.

### **Legal Requirements**
✅ **ALLOWED:**
- Targets with published bug bounty programs (HackerOne, Bugcrowd, etc.)
- Your own applications and infrastructure
- Targets with written authorization

❌ **PROHIBITED:**
- Scanning without authorization
- Testing production systems without permission
- Exceeding program scope
- Denial of Service (DoS) attacks
- Social engineering without consent

### **Built-in Safety Features**

```python
# Scan validation checks:
- Program verification (must be registered bounty program)
- Scope validation (domains/IPs must be in-scope)
- Rate limiting (respectful scanning speed)
- No automated exploitation (manual review required)
```

### **Burp Suite Integration Security**

**Requirements:**
- Burp Suite Professional license (REST API access)
- Localhost-only connections (`127.0.0.1:1337`)
- API key authentication

**Configuration:**
```python
# .env
BURP_API_URL=http://127.0.0.1:1337
BURP_API_KEY=your_secure_api_key_here
BURP_AUTO_SCAN=false  # Manual approval required
```

### **Report Security**
- Reports stored locally in `data/bugbounty/reports/`
- PoC code never automatically executed
- Sanitized output (no sensitive data leakage)
- Encrypted submission to platforms

---

## 🤖 Proactive AI Security

### **Action Execution Control**

Proactive suggestions categorized by risk:

| Category | Example | Auto-Execute |
|----------|---------|--------------|
| **Safe** | "Show daily plan" | Yes (informational) |
| **Moderate** | "Start Burp scan" | Prompt user |
| **Risky** | "Launch application" | Require explicit approval |
| **Dangerous** | "Delete files" | Blocked by default |

### **Context Awareness**

AI analyzes screen content with privacy controls:

```python
# Privacy filters:
REDACT_PASSWORDS = true
REDACT_API_KEYS = true
REDACT_CREDIT_CARDS = true
REDACT_EMAILS = false  # Optional
```

### **User Consent**

```javascript
// UI confirmation for moderate/risky actions
const confirmAction = async (suggestion) => {
  return await showDialog({
    title: `Execute: ${suggestion.title}?`,
    message: suggestion.description,
    warning: suggestion.risk_level,
    options: ["Execute", "Cancel", "Never suggest again"]
  });
};
```

---

## 🔑 API Security

### **Authentication**

```python
# API key authentication (optional but recommended)
API_KEY_ENABLED=true
API_KEY=your_secure_random_key_here

# Add to requests:
headers = {"X-API-Key": "your_secure_random_key_here"}
```

### **CORS Configuration**

```python
# Allowed origins (whitelist your frontend)
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Production:
ALLOWED_ORIGINS=https://yourdomain.com
```

### **Rate Limiting**

```python
# Per-endpoint limits
RATE_LIMIT_CHAT=60/minute
RATE_LIMIT_VOICE=30/minute
RATE_LIMIT_MONITORING=10/minute
RATE_LIMIT_CONTROL=5/minute
```

### **Encryption**

- HTTPS enforced in production
- TLS 1.3 minimum
- Environment variables for sensitive data
- Database encryption at rest (SQLCipher recommended)

---

## 💾 Data Storage Security

### **File Locations**

```
data/
├── screenshots/          # Screen captures (auto-cleanup)
├── conversations/        # Chat history (encrypted recommended)
├── bugbounty/           # Reports and findings
│   └── reports/         # Sensitive vulnerability data
├── control_audit.log    # PC action logs
├── memory.db            # User profile and memory (SQLite)
└── personality/         # Language patterns (non-sensitive)
```

### **Sensitive Data Protection**

1. **Never commit:**
   - `.env` files
   - `data/` directory
   - API keys, tokens, passwords
   - Screenshots or reports

2. **Encryption:**
   ```python
   # Enable database encryption
   pip install pysqlcipher3
   
   # In config:
   DATABASE_ENCRYPTION=true
   DATABASE_KEY=your_secure_key_here
   ```

3. **Backup Security:**
   - Encrypted backups only
   - Secure deletion of old data
   - No cloud sync without encryption

---

## 🚨 Incident Response

### **Emergency Actions**

If you suspect unauthorized access or malicious activity:

1. **Immediate:**
   ```bash
   # Stop all Aether services
   STOP_AETHER.bat
   
   # Or kill processes:
   taskkill /F /IM python.exe /FI "WINDOWTITLE eq Aether*"
   ```

2. **Revoke Access:**
   - Rotate all API keys immediately
   - Change `.env` API_KEY
   - Check `data/control_audit.log` for unauthorized actions

3. **Review Logs:**
   ```bash
   # Check API access logs
   type logs\api.log | findstr ERROR
   
   # Check control actions
   type data\control_audit.log
   
   # Check screenshot history
   dir data\screenshots /OD
   ```

4. **Clean Data:**
   ```bash
   # Delete sensitive data
   scripts\cleanup_sensitive_data.bat
   ```

### **Reporting Vulnerabilities**

Found a security issue in Aether AI?

**DO NOT** post publicly. Report privately:
- Email: security@aether-ai.dev (if available)
- GitHub: Private security advisory
- Include: PoC, impact, suggested fix

---

## ✅ Security Checklist

### **Before First Use:**
- [ ] Review `.env.example` and configure safely
- [ ] Set strong `API_KEY` (at least 32 random characters)
- [ ] Configure `ALLOWED_ORIGINS` for CORS
- [ ] Enable only needed features
- [ ] Review permission whitelist/blacklist
- [ ] Test in safe environment first

### **Regular Maintenance:**
- [ ] Review `control_audit.log` weekly
- [ ] Clean old screenshots (auto-cleanup enabled?)
- [ ] Update dependencies: `pip install -r requirements.txt --upgrade`
- [ ] Check for Aether AI updates
- [ ] Rotate API keys quarterly
- [ ] Backup encrypted data

### **Before Bug Bounty:**
- [ ] Verify target authorization
- [ ] Check program scope
- [ ] Test scanning on own infrastructure first
- [ ] Respect rate limits
- [ ] Never auto-exploit without review
- [ ] Follow responsible disclosure

---

## 🔗 Security Resources

### **Dependencies Security**
```bash
# Check for vulnerabilities
pip install safety
safety check -r requirements.txt

# Update dependencies
pip install --upgrade -r requirements.txt
```

### **Network Security**
- Use firewall to restrict API access (port 8000)
- VPN recommended for bug bounty work
- Monitor outbound connections

### **System Hardening**
- Run as non-admin user when possible
- Use Windows Defender / antivirus
- Enable Windows Security features
- Keep OS and dependencies updated

---

## 📝 Version History

| Version | Date | Security Changes |
|---------|------|------------------|
| v0.9.0 | Feb 2026 | Initial security doc for v0.9.0 features |
| v0.8.0 | Jan 2026 | Added PC control security |
| v0.7.0 | Dec 2025 | Screen monitoring privacy controls |

---

## 📞 Support

Security questions or concerns?
- Documentation: `README.md`, `FEATURES_v0.9.0.md`
- Configuration: `.env.example`
- Logs: `logs/` directory

**Remember**: Security is a shared responsibility. Use Aether AI's powerful features responsibly and ethically.

---

**Disclaimer**: Aether AI provides powerful automation capabilities. Users are solely responsible for ensuring their use complies with applicable laws, regulations, and ethical guidelines. Unauthorized access to computer systems is illegal.
