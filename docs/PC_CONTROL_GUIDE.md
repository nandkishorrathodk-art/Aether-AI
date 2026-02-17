# PC Control Guide - Safety & Usage

**Safe and responsible PC automation with Aether AI v0.9.0 🎮**

---

## ⚠️ Safety First

PC control is **POWERFUL** and potentially **DANGEROUS**. Always follow safety guidelines.

### Before You Enable PC Control

**Ask yourself:**
1. Do I understand the risks?
2. Do I trust Aether AI to control my PC?
3. Have I reviewed the audit logging system?
4. Am I prepared to use emergency stop if needed?

**If you answered NO to any question**: Keep PC control disabled.

---

## Quick Start

### Step 1: Enable PC Control

```env
# In .env file
ENABLE_PC_CONTROL=true
PC_CONTROL_REQUIRE_CONFIRMATION=true  # KEEP THIS TRUE!
PC_CONTROL_ALLOWED_ACTIONS=mouse_click,keyboard_type,app_launch
```

### Step 2: Test Safely

```bash
# Launch a safe app (Notepad)
curl -X POST http://localhost:8000/api/v1/control/app/launch \
  -H "Content-Type: application/json" \
  -d '{"app": "notepad"}'

# Type text
curl -X POST http://localhost:8000/api/v1/control/keyboard/type \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello from Aether AI!"}'
```

### Step 3: Review Audit Log

```bash
type data\control_audit.log
```

---

## Features

### Mouse Control

**Actions:**
- Click (left, right, middle)
- Move cursor
- Drag and drop
- Scroll

**Example:**
```bash
# Click at coordinates (100, 200)
curl -X POST http://localhost:8000/api/v1/control/mouse/click \
  -H "Content-Type: application/json" \
  -d '{"x": 100, "y": 200, "button": "left"}'
```

### Keyboard Control

**Actions:**
- Type text
- Press keys (Enter, Tab, Esc, etc.)
- Keyboard shortcuts (Ctrl+C, Alt+F4, etc.)

**Example:**
```bash
# Type text
curl -X POST http://localhost:8000/api/v1/control/keyboard/type \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello World"}'

# Press Ctrl+C
curl -X POST http://localhost:8000/api/v1/control/keyboard/press \
  -H "Content-Type: application/json" \
  -d '{"keys": ["ctrl", "c"]}'
```

### Application Launcher

**Supported Apps:**
- `notepad` - Notepad
- `chrome` - Google Chrome
- `firefox` - Firefox
- `burpsuite` - Burp Suite
- `vscode` - Visual Studio Code
- `powershell` - PowerShell
- `cmd` - Command Prompt

**Example:**
```bash
# Launch Chrome
curl -X POST http://localhost:8000/api/v1/control/app/launch \
  -H "Content-Type: application/json" \
  -d '{"app": "chrome", "args": ["--incognito"]}'

# Close Chrome
curl -X POST http://localhost:8000/api/v1/control/app/close \
  -H "Content-Type: application/json" \
  -d '{"app": "chrome"}'
```

---

## Permission System

### Permission Levels

**Level 0 (Blocked):** Action denied, no execution  
**Level 1 (Confirm):** Requires user confirmation (DEFAULT)  
**Level 2 (Auto-Allow):** Executes automatically (⚠️ USE WITH EXTREME CAUTION)

### Configuration

```env
# Allowed actions (comma-separated)
PC_CONTROL_ALLOWED_ACTIONS=mouse_click,keyboard_type,app_launch,app_close

# Blocked actions (comma-separated)
PC_CONTROL_BLOCKED_ACTIONS=system_shutdown,file_delete,registry_edit

# Require confirmation for all actions
PC_CONTROL_REQUIRE_CONFIRMATION=true  # RECOMMENDED!
```

### Viewing Permissions

```bash
curl http://localhost:8000/api/v1/control/permissions
```

---

## Safety Features

### 1. Audit Logging

**All actions logged to:** `data/control_audit.log`

**Log format:**
```
[2026-02-17 14:35:00] ACTION: mouse_click | USER: admin | PARAMS: {"x": 100, "y": 200} | RESULT: success
```

### 2. Coordinate Validation

- Mouse clicks validated within screen bounds
- Prevents clicks outside visible area

### 3. Rate Limiting

- Maximum 10 actions per second
- Prevents accidental spam or loops

### 4. Action Whitelisting

- Only approved actions can execute
- Dangerous actions blocked by default

### 5. Emergency Stop

**To stop all PC control:**
```bash
curl -X POST http://localhost:8000/api/v1/control/emergency-stop
```

**Or disable in .env:**
```env
ENABLE_PC_CONTROL=false
```

---

## Use Cases

### Use Case 1: Automated Testing

```bash
# Launch test app
curl -X POST http://localhost:8000/api/v1/control/app/launch \
  -d '{"app": "chrome", "args": ["http://localhost:3000"]}'

# Navigate and test
curl -X POST http://localhost:8000/api/v1/control/mouse/click \
  -d '{"x": 500, "y": 300}'  # Click login button

curl -X POST http://localhost:8000/api/v1/control/keyboard/type \
  -d '{"text": "testuser@example.com"}'  # Enter email

curl -X POST http://localhost:8000/api/v1/control/keyboard/press \
  -d '{"keys": ["tab"]}'  # Tab to password

curl -X POST http://localhost:8000/api/v1/control/keyboard/type \
  -d '{"text": "password123"}'  # Enter password

curl -X POST http://localhost:8000/api/v1/control/keyboard/press \
  -d '{"keys": ["enter"]}'  # Submit
```

### Use Case 2: Bug Bounty Workflow

```bash
# Launch Burp Suite
curl -X POST http://localhost:8000/api/v1/control/app/launch \
  -d '{"app": "burpsuite"}'

# Wait 5 seconds for Burp to start
timeout /t 5

# Launch Chrome with Burp proxy
curl -X POST http://localhost:8000/api/v1/control/app/launch \
  -d '{"app": "chrome", "args": ["--proxy-server=127.0.0.1:8080"]}'
```

---

## Best Practices

### DO ✅

1. **Keep confirmation prompts enabled** (`PC_CONTROL_REQUIRE_CONFIRMATION=true`)
2. **Review audit logs regularly**
3. **Test in safe environment first**
4. **Use whitelist approach** (only allow specific actions)
5. **Monitor resource usage** (CPU, memory)
6. **Have emergency stop ready**
7. **Backup important data** before enabling

### DON'T ❌

1. **Don't disable confirmation prompts** unless absolutely necessary
2. **Don't allow destructive actions** (file delete, system shutdown)
3. **Don't run unverified automation**
4. **Don't leave PC control enabled when not in use**
5. **Don't auto-execute user-generated scripts**
6. **Don't use on production systems** without thorough testing

---

## Troubleshooting

### Issue: Actions not executing

**Solutions:**
1. Check `ENABLE_PC_CONTROL=true` in `.env`
2. Verify action is in `PC_CONTROL_ALLOWED_ACTIONS`
3. Check audit log for errors
4. Restart Aether AI

### Issue: Confirmation prompts not showing

**Solutions:**
1. Check `PC_CONTROL_REQUIRE_CONFIRMATION=true`
2. Verify UI is connected
3. Check notification settings

### Issue: Mouse clicks missing target

**Solutions:**
1. Use absolute coordinates (not relative)
2. Account for screen resolution
3. Use screen monitoring to verify element positions
4. Add delays between actions

---

## Advanced Configuration

```env
# PC Control - Advanced
PC_CONTROL_ACTION_DELAY=100  # ms between actions
PC_CONTROL_MAX_ACTIONS_PER_MINUTE=100
PC_CONTROL_ENABLE_ROLLBACK=true
PC_CONTROL_SCREENSHOT_ON_ACTION=false  # For debugging
PC_CONTROL_DRY_RUN=false  # Test mode (no actual execution)
```

---

## Security Considerations

### Risks

1. **Unauthorized Access**: If API is compromised, attacker can control PC
2. **Accidental Damage**: Mis-configured actions can cause data loss
3. **Privacy**: Screen monitoring + PC control = full visibility
4. **Malicious Scripts**: User-provided scripts could be harmful

### Mitigations

1. **API Authentication**: Ensure strong API keys
2. **Network Security**: Use HTTPS, firewall rules
3. **Audit Logging**: Monitor all actions
4. **Permission System**: Whitelist approach
5. **Confirmation Prompts**: Human-in-the-loop
6. **Rate Limiting**: Prevent abuse
7. **Emergency Stop**: Quick disable mechanism

---

## Frequently Asked Questions

**Q: Is PC control safe?**  
A: With proper configuration (confirmation prompts, audit logging, whitelisting), it's reasonably safe. But it's never 100% risk-free.

**Q: Can I use it on production systems?**  
A: Not recommended. Test thoroughly on non-production systems first.

**Q: What if something goes wrong?**  
A: Use emergency stop, disable in `.env`, review audit logs, restore from backup if needed.

**Q: Can it bypass UAC prompts?**  
A: No. Aether runs with user-level permissions only.

**Q: Does it work on Mac/Linux?**  
A: v0.9.0 is Windows-only. Mac/Linux support planned for future releases.

---

## Emergency Procedures

### Emergency Stop

**Method 1:** API call
```bash
curl -X POST http://localhost:8000/api/v1/control/emergency-stop
```

**Method 2:** Disable in `.env`
```env
ENABLE_PC_CONTROL=false
```

**Method 3:** Stop Aether AI
```bash
STOP_AETHER.bat
# Or press Ctrl+C in terminal
```

### Recovery

1. **Review audit log**: `type data\control_audit.log`
2. **Check what actions were executed**
3. **Restore from backup if needed**
4. **Reconfigure permissions**
5. **Test in safe environment before re-enabling**

---

## Legal & Ethical Considerations

### Legal

- **Only control your own PC** or with explicit written authorization
- **Corporate environments**: Get IT approval before use
- **Liability**: You are responsible for all actions taken by Aether

### Ethical

- **Transparency**: Users should know their system can be controlled
- **Consent**: Always get consent before automating someone else's PC
- **Responsibility**: Use for good, not harm

---

**Use PC control responsibly and safely! 🛡️**

*With great power comes great responsibility - Uncle Ben (and Aether AI)*
