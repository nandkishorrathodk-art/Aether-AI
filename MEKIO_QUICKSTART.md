# 🎀 MEKIO-STYLE QUICK START

**Get your anime AI companion running in 5 minutes!**

---

## ⚡ FASTEST START (Anime Character Only)

### **1. Install Dependencies**

```bash
cd ui
npm install
```

### **2. Start UI**

```bash
npm start
```

### **3. Enable Character**

- Click the **pink face icon** (👤) in top-right corner
- Anime character appears!
- Click to get hearts, drag to move
- Right-click to change personality

**Done!** You now have a cute anime companion! 🎀

---

## 🤖 DISCORD BOT SETUP (Optional)

### **Step 1: Create Discord Application**

1. Go to https://discord.com/developers/applications
2. Click "New Application"
3. Name it "Aether AI" (or anything you like)
4. Click "Create"

### **Step 2: Create Bot**

1. Go to "Bot" tab in left menu
2. Click "Add Bot" → "Yes, do it!"
3. **Enable Intents** (Important!):
   - ✅ Presence Intent
   - ✅ Server Members Intent
   - ✅ Message Content Intent
4. Click "Reset Token" → Copy the token
5. **SAVE THIS TOKEN** - you'll need it!

### **Step 3: Invite Bot to Server**

1. Go to "OAuth2" → "URL Generator"
2. Select **Scopes**:
   - ✅ bot
   - ✅ applications.commands
3. Select **Bot Permissions**:
   - ✅ Send Messages
   - ✅ Read Message History
   - ✅ Use Slash Commands
   - ✅ Add Reactions
   - ✅ Embed Links
4. Copy the generated URL
5. Open URL in browser
6. Select your server
7. Click "Authorize"

**Bot is now in your server!** But not running yet...

### **Step 4: Start Aether Backend**

```bash
# Install Discord dependencies first
pip install discord.py==2.3.2 aiofiles==23.2.1

# Start backend
.\start-backend.bat
```

### **Step 5: Start Bot via API**

**Windows PowerShell**:
```powershell
$body = @{
    token = "YOUR_BOT_TOKEN_HERE"
    personality = "kawaii"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/v1/discord/start" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body
```

**Or use curl** (if installed):
```bash
curl -X POST http://localhost:8000/api/v1/discord/start \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"YOUR_BOT_TOKEN_HERE\", \"personality\": \"kawaii\"}"
```

**Bot should now be online in Discord!** 🎉

### **Step 6: Test Bot**

In your Discord server:

```
@Aether hello!
```

Bot should respond! Try:
```
!aether chat Tell me a joke
!aether personality tsundere
!aether status
```

---

## 🎭 PERSONALITY QUICK REFERENCE

Change personality anytime:

### **In Discord**:
```
!aether personality <type>
```

### **In UI (Character)**:
- Right-click character
- Select personality from menu

### **Personalities**:
- `friendly` - Warm and helpful 😊
- `playful` - Fun and energetic 😜
- `professional` - Business-like 💼
- `kawaii` - Super cute anime 🎀
- `tsundere` - Cold but caring 😤

---

## 🔧 COMMON ISSUES

### **Issue: "Invalid Token"**

**Solution**:
1. Go back to Discord Developer Portal
2. Bot tab → Reset Token
3. Copy NEW token
4. Use new token in API call

### **Issue: "Missing Permissions"**

**Solution**:
1. Reinvite bot with correct permissions
2. Check server roles
3. Ensure bot has "Send Messages" permission

### **Issue: "Bot Offline in Discord"**

**Solution**:
1. Check backend is running: http://localhost:8000/health
2. Check bot status: http://localhost:8000/api/v1/discord/status
3. Restart bot via API

### **Issue: "Character Not Appearing"**

**Solution**:
1. Check browser console for errors
2. Refresh page
3. Click face icon again
4. Clear cache and reload

### **Issue: "ModuleNotFoundError: discord"**

**Solution**:
```bash
pip install discord.py==2.3.2
```

---

## 📝 QUICK COMMANDS

### **Discord Bot Commands**:

```bash
# Chat
!aether chat <message>

# Personality
!aether personality <type>

# Clear history
!aether clear

# Status
!aether status

# Analyze text
!aether analyze <text>

# Translate
!aether translate <language> <text>

# Joke
!aether joke
```

### **API Commands**:

```bash
# Start bot
POST /api/v1/discord/start

# Stop bot
POST /api/v1/discord/stop

# Get status
GET /api/v1/discord/status

# Change personality
PUT /api/v1/discord/personality

# List servers
GET /api/v1/discord/guilds
```

---

## 🎯 WHAT'S NEXT?

### **Customize Character**:
Edit `ui/src/components/AnimeCharacter.css`:
- Change colors
- Modify animations
- Adjust size

### **Add Custom Commands**:
Edit `src/integrations/discord_bot.py`:
- Add new @bot.command decorators
- Create custom responses

### **Use Both Together**:
- Enable character in UI
- Run Discord bot
- Full Mekio experience!

---

## 💡 PRO TIPS

1. **Save your bot token** in `.env` file:
   ```env
   DISCORD_BOT_TOKEN=your_token_here
   ```

2. **Start bot automatically** on backend start:
   - Add to `src/main.py` startup

3. **Multiple personalities** per server:
   - Create multiple bot instances
   - Different tokens = different personalities

4. **Character follows voice**:
   - Enable voice in dashboard
   - Enable anime character
   - Character reacts to voice automatically!

5. **Stream with character**:
   - Enable character on stream
   - Position in corner
   - Chat via Discord bot
   - Viewers see anime AI companion!

---

## 🚀 ULTRA QUICK SUMMARY

### **Just want the anime character?**
```bash
cd ui && npm start
# Click face icon (👤)
# Done!
```

### **Want Discord bot too?**
```bash
# Backend
pip install discord.py
.\start-backend.bat

# Start bot (in new terminal)
curl -X POST http://localhost:8000/api/v1/discord/start \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"YOUR_TOKEN\", \"personality\": \"kawaii\"}"

# Test in Discord
@Aether hello!
```

---

## 📞 SUPPORT

**Documentation**: See `MEKIO_INTEGRATION_COMPLETE.md` for full details

**Discord Setup Issues**: https://discord.com/developers/docs

**UI Issues**: Check browser console (F12)

**API Issues**: Check backend logs

---

**That's it! Enjoy your anime AI companion!** 🎀✨

*Kawaii power activated!* (◕‿◕)✿
