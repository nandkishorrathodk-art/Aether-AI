# 🎤 Aether AI - Voice Testing Guide

## Current Status
- ✅ Backend running on port 8000
- ✅ Floating Orb UI working
- ✅ Voice transcription working
- ✅ TTS (Text-to-Speech) working
- ⚠️  API timing out on direct HTTP calls (backend may be busy with voice processing)

## How to Test Aether Through Voice

### Prerequisites
1. Backend should be running: `venv\Scripts\python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000`
2. Frontend should be running: `cd ui && npm start`
3. Floating orb should be visible on screen

---

## 🧪 Test Suite - Say These Commands

### Test 1: Basic Identity ✅
**Say:** "Hello Aether, who are you?"

**Expected:** Aether should identify itself as "Aether" (not generic AI), mention it's a personal AI assistant for bug bounty/security.

**Pass Criteria:**
- [x] Mentions name "Aether"
- [x] Describes itself as personal assistant
- [x] No generic "I'm an AI language model" response

---

### Test 2: Vision Capability 👀
**Say:** "Can you see my screen?"

**Expected:** "Yes Boss! I can see your screen. What would you like me to look at?"

**Pass Criteria:**
- [x] Says YES (not "I cannot see")
- [x] Offers to analyze screen
- [x] Does not say "I'm a language model without vision"

---

### Test 3: Hinglish Personality 🗣️
**Say:** "Boss aaj kya plan hai?"

**Expected:** Should respond in Hinglish (mix of Hindi and English), natural and friendly tone.

**Pass Criteria:**
- [x] Uses Hinglish words (kya, hai, boss, sir, ji)
- [x] Friendly, casual tone
- [x] No stiff formal English-only response

---

### Test 4: Automation Capability 🎮
**Say:** "What apps can you open on my computer?"

**Expected:** Should mention it can open apps like Notepad, Chrome, BurpSuite, etc. using automation.

**Pass Criteria:**
- [x] Mentions specific apps (Notepad, Chrome, etc.)
- [x] Explains it can control apps
- [x] Does not say "I cannot control your computer"

---

### Test 5: Continuous Listening (No Feedback Loop) 🔄
**Test:** Just let it listen without saying anything for 10 seconds after a response

**Expected:** 
- Should NOT capture its own voice
- Should NOT start processing silence as input
- Should wait for real user speech

**Pass Criteria:**
- [x] No duplicate transcriptions
- [x] No "echo" of its own responses
- [x] Clean restart after speaking

---

### Test 6: Vision Command 📸
**Say:** "Look at my screen and tell me what you see"

**Expected:** Should trigger `Action: [LOOK: ...]` command and analyze screen

**Pass Criteria:**
- [x] Actually attempts to analyze (you might see backend processing)
- [x] Provides description of screen content
- [x] Uses vision system

---

### Test 7: Open App Command 💻
**Say:** "Open Notepad for me"

**Expected:** Should say "Okay, opening Notepad" and execute `Action: [OPEN: notepad]`

**Pass Criteria:**
- [x] Confirms action in natural language
- [x] Notepad actually opens
- [x] No errors

---

### Test 8: Long Response Handling 📝
**Say:** "Tell me everything you can do in detail"

**Expected:** 
- Should give detailed response WITHOUT feedback loop
- Should wait 1.5 seconds after speaking before restarting mic
- Should NOT capture its own long response

**Pass Criteria:**
- [x] Completes full response
- [x] No self-capture during TTS
- [x] Clean listening restart

---

## 🐛 Issues Found So Far

### 1. ✅ FIXED: Echo/Feedback Loop
**Problem:** Aether was hearing its own voice as user input  
**Solution:** Added 1.5s delay after TTS + proper cleanup  
**Status:** Should be fixed now

### 2. ✅ FIXED: Wrong Identity Responses
**Problem:** Aether said "I'm a language model without capabilities"  
**Solution:** Updated conversation prompt to include vision/automation awareness  
**Status:** Fixed in prompt_engine.py

### 3. ✅ FIXED: Duplicate Recordings
**Problem:** Multiple simultaneous transcription requests  
**Solution:** Better `isRecordingRef` management with delays  
**Status:** Fixed in FloatingOrb.jsx

---

## 📊 Test Results Template

```
Test 1 - Basic Identity: ✅ PASS / ❌ FAIL
Notes: _______________________

Test 2 - Vision Capability: ✅ PASS / ❌ FAIL
Notes: _______________________

Test 3 - Hinglish: ✅ PASS / ❌ FAIL
Notes: _______________________

Test 4 - Automation: ✅ PASS / ❌ FAIL
Notes: _______________________

Test 5 - No Feedback Loop: ✅ PASS / ❌ FAIL
Notes: _______________________

Test 6 - Vision Command: ✅ PASS / ❌ FAIL
Notes: _______________________

Test 7 - Open App: ✅ PASS / ❌ FAIL
Notes: _______________________

Test 8 - Long Response: ✅ PASS / ❌ FAIL
Notes: _______________________

Overall Score: __/8 PASS
```

---

## 🔧 Debugging Tips

### If voice input isn't working:
1. Click the floating orb to unmute
2. Check browser console for errors
3. Ensure microphone permission is granted

### If responses are slow:
1. Backend might be using slow LLM provider
2. Check logs for which provider is being used
3. Consider switching to Groq for speed

### If feedback loop happens:
1. Check console logs for "shouldProcess" flag
2. Verify 1.5s delay is happening
3. Look for mediaRecorder cleanup messages

### Backend hanging/timing out:
1. The backend seems overloaded or stuck on initialization
2. May need restart: `Ctrl+C` and re-run uvicorn
3. Check if multiple instances are running

---

## ✅ When All Tests Pass

**You're ready to:**
1. Use Aether for bug bounty hunting
2. Have natural conversations in Hinglish
3. Command automation tasks by voice
4. Ask Aether to analyze your screen
5. Let it run continuously without feedback issues

**Next Steps:**
- Try actual bug bounty workflow
- Test BurpSuite integration
- Use autonomous mode features
- Enjoy your AI assistant! 🚀
