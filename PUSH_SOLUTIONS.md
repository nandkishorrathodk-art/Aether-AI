# GitHub Push Error - Connection Reset Solutions

## Error Details
```
fatal: unable to access 'https://github.com/nandkishorrathodk-art/Aether-AI.git/': 
Recv failure: Connection was reset
```

---

## Quick Fixes (Try in Order)

### ✅ Solution 1: Run Automated Fix Script
```powershell
fix_push.bat
```
This script automatically tries multiple fixes.

---

### ✅ Solution 2: Manual Network Fix (Windows)
```powershell
# Clear DNS cache
ipconfig /flushdns

# Reset network
netsh winsock reset
netsh int ip reset

# Restart (or just try pushing again)
```

---

### ✅ Solution 3: Increase Git Buffer
```powershell
git config --global http.postBuffer 524288000
git config --global http.version HTTP/1.1
git push -u origin main
```

---

### ✅ Solution 4: Disable SSL Temporarily (ONLY if other methods fail)
```powershell
# WARNING: Only use on trusted networks!
git config --global http.sslVerify false
git push -u origin main

# Re-enable SSL after push
git config --global http.sslVerify true
```

---

### ✅ Solution 5: Use SSH Instead of HTTPS

#### Step 1: Generate SSH Key
```powershell
ssh-keygen -t ed25519 -C "your_email@example.com"
# Press Enter 3 times (default location, no passphrase)
```

#### Step 2: Add Key to GitHub
```powershell
# Copy the key
type %USERPROFILE%\.ssh\id_ed25519.pub
```
1. Go to https://github.com/settings/keys
2. Click "New SSH key"
3. Paste the copied key
4. Click "Add SSH key"

#### Step 3: Change Remote to SSH
```powershell
git remote set-url origin git@github.com:nandkishorrathodk-art/Aether-AI.git
git push -u origin main
```

---

### ✅ Solution 6: GitHub Desktop (Easiest)
1. Download: https://desktop.github.com/
2. Sign in to GitHub
3. Add repository: C:\Users\nandk\.zenflow\worktrees\nitro-v-f99b
4. Click "Push origin" button

---

### ✅ Solution 7: Different Network
- Try mobile hotspot
- Try different WiFi
- Disable VPN (if using)
- Disable firewall temporarily

---

### ✅ Solution 8: Check Firewall/Antivirus
Windows Defender or antivirus may be blocking Git.

**Temporary disable**:
1. Windows Security → Firewall & network protection
2. Turn off temporarily
3. Try push
4. Turn back on

---

## ⚡ Fastest Solution (Recommended)

Run this in PowerShell:
```powershell
cd C:\Users\nandk\.zenflow\worktrees\nitro-v-f99b

# Fix network settings
git config --global http.postBuffer 524288000
git config --global http.version HTTP/1.1

# Wait 5 seconds
timeout /t 5

# Try push again
git push -u origin main --force
```

---

## Still Not Working?

### Try pushing smaller chunks:
```powershell
# Create a new branch with fewer files
git checkout -b small-push
git add src/
git commit -m "Aether core files"
git push -u origin small-push

# Then push rest
git checkout main
git push -u origin main
```

---

## Root Cause
This error is typically caused by:
- ❌ Network instability
- ❌ Firewall blocking Git
- ❌ Large repository size
- ❌ GitHub rate limiting
- ❌ Antivirus interference

## Your Repo Stats
- Size: 7.31 MB (after cleanup)
- Files: 633
- This should push easily once network is fixed!
