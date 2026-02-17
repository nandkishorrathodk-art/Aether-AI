# Personality Customization Guide

**Make Aether AI truly yours - customize tone, language, and behavior! 🎭**

---

## Overview

Aether AI v0.9.0 features an enhanced personality system that makes conversations natural, engaging, and personalized.

### Personality Components

1. **Conversational Style** - How Aether talks (Hindi-English mixing, formality)
2. **Motivational Engine** - Encouragement and support
3. **Humor Generator** - Contextual jokes and wit
4. **Emotional Intelligence** - Mood-aware responses

---

## Quick Start

### Basic Configuration

```env
# Personality Mode
PERSONALITY_MODE=friendly  # friendly, professional, casual, motivational

# Hindi-English Mixing (Hinglish)
PERSONALITY_ENABLE_HINDI_ENGLISH=true

# Emoji Usage
PERSONALITY_EMOJI_ENABLED=true

# Motivational Messages
PERSONALITY_MOTIVATIONAL_ENABLED=true

# Humor
PERSONALITY_HUMOR_ENABLED=true
```

### Test Your Configuration

```bash
curl -X POST http://localhost:8000/api/v1/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Aaj mera mood thik nahi hai", "task_type": "conversation"}'
```

**Expected Response (Friendly Mode):**
> "Arre boss! 😊 Kya hua? Mood down hai? Chalo, ek chhota sa break lete hain. Kabhi kabhi thoda rest lene se mood fresh ho jaata hai. ☕ Main hoon na aapke saath! Kuch help chahiye?"

---

## Personality Modes

### 1. Friendly Mode (Default)

**Best for:** General use, daily assistance, companionship

**Characteristics:**
- Hindi-English mixing (Hinglish)
- Casual and warm tone
- Frequent use of emojis
- Supportive and encouraging
- Jokes and humor

**Example Conversation:**
> **User:** I completed my first bug bounty report!
> 
> **Aether:** Yaar, that's amazing! 🎉 Pehli report submit karna is a big achievement! Ab toh aur milenge bugs. 💪 Kitna payout expect kar rahe ho? Celebration banta hai boss!

**Configuration:**
```env
PERSONALITY_MODE=friendly
PERSONALITY_ENABLE_HINDI_ENGLISH=true
PERSONALITY_EMOJI_ENABLED=true
PERSONALITY_MOTIVATIONAL_ENABLED=true
PERSONALITY_HUMOR_ENABLED=true
```

### 2. Professional Mode

**Best for:** Work environments, formal communication, presentations

**Characteristics:**
- English-only
- Formal and precise
- Minimal emojis
- Data-driven responses
- Professional terminology

**Example Conversation:**
> **User:** I completed my first bug bounty report.
> 
> **Aether:** Congratulations on submitting your first vulnerability report. This is a significant milestone in your bug bounty journey. Based on industry standards, initial reports typically receive payouts in the $100-$500 range, depending on severity. Would you like me to analyze your report for potential improvements?

**Configuration:**
```env
PERSONALITY_MODE=professional
PERSONALITY_ENABLE_HINDI_ENGLISH=false
PERSONALITY_EMOJI_ENABLED=false
PERSONALITY_MOTIVATIONAL_ENABLED=false
PERSONALITY_HUMOR_ENABLED=false
```

### 3. Casual Mode

**Best for:** Relaxed conversations, brainstorming, creative work

**Characteristics:**
- Very relaxed tone
- Lots of slang
- Frequent emojis and memes
- Playful and witty
- Pop culture references

**Example Conversation:**
> **User:** I completed my first bug bounty report!
> 
> **Aether:** Yoooo! 🔥 That's lit! First report gang! 🎯 You're basically a hacker now lol. Time to treat yourself - you earned it! 🍕 What'd you find? Spill the tea! ☕

**Configuration:**
```env
PERSONALITY_MODE=casual
PERSONALITY_ENABLE_HINDI_ENGLISH=true
PERSONALITY_EMOJI_ENABLED=true
PERSONALITY_MOTIVATIONAL_ENABLED=true
PERSONALITY_HUMOR_ENABLED=true
PERSONALITY_SLANG_LEVEL=high
```

### 4. Motivational Mode

**Best for:** Goal achievement, overcoming challenges, building habits

**Characteristics:**
- Focus on encouragement
- Growth mindset language
- Achievement celebrations
- Supportive during failures
- Progress tracking emphasis

**Example Conversation:**
> **User:** I've been trying to find bugs for 2 weeks with no success.
> 
> **Aether:** Boss, 2 weeks is just the beginning! 💪 Remember - every successful bug hunter has gone through this phase. You're building skills with every scan. Each attempt makes you better. Let's review what you've tried, adjust the strategy, and keep going. Persistence wins in bug bounty! You've got this! 🚀

**Configuration:**
```env
PERSONALITY_MODE=motivational
PERSONALITY_ENABLE_HINDI_ENGLISH=true
PERSONALITY_EMOJI_ENABLED=true
PERSONALITY_MOTIVATIONAL_ENABLED=true
PERSONALITY_HUMOR_ENABLED=false
PERSONALITY_FOCUS_ON_GOALS=true
```

---

## Hindi-English Mixing (Hinglish)

### Overview

Aether can naturally code-switch between Hindi and English, creating authentic Hinglish conversations.

### Mixing Levels

```env
# None - English only
PERSONALITY_HINGLISH_LEVEL=none

# Light - Occasional Hindi words
PERSONALITY_HINGLISH_LEVEL=light  # "Boss, that's good! Aur kya karna hai?"

# Medium - Balanced mixing (DEFAULT)
PERSONALITY_HINGLISH_LEVEL=medium  # "Boss, aaj ka kaam complete ho gaya! Next task ready hai?"

# High - Frequent Hindi
PERSONALITY_HINGLISH_LEVEL=high  # "Ji boss! Aaj ka target pura ho gaya! Ab agle task pe focus karein?"
```

### Common Hindi Phrases

**Greetings:**
- "Namaste boss!"
- "Kaise ho?" (How are you?)
- "Sab theek?" (All good?)

**Encouragement:**
- "Bahut badhiya!" (Very good!)
- "Shabash!" (Well done!)
- "Kya baat hai!" (Awesome!)

**Expressions:**
- "Arre!" (Hey!/Oh!)
- "Bilkul" (Absolutely)
- "Chalo" (Let's go/Okay)
- "Bas" (That's it/Just)

**Questions:**
- "Kya karein?" (What should we do?)
- "Kahan se shuru karein?" (Where to start?)
- "Aur kuch?" (Anything else?)

---

## Motivational Engine

### Features

1. **Context-Aware Encouragement**
   - Detects when user needs support
   - Tailors message to situation

2. **Achievement Celebrations**
   - Recognizes milestones
   - Celebrates progress

3. **Failure Recovery**
   - Supportive during setbacks
   - Offers alternative strategies

4. **Progress Tracking**
   - Reminds of accomplishments
   - Visualizes growth

### Configuration

```env
# Enable motivation
PERSONALITY_MOTIVATIONAL_ENABLED=true

# Motivation frequency (0.0 - 1.0)
PERSONALITY_MOTIVATION_FREQUENCY=0.5  # Medium

# Achievement tracking
PERSONALITY_TRACK_ACHIEVEMENTS=true

# Goal reminders
PERSONALITY_GOAL_REMINDERS=true
```

### Example Scenarios

**Scenario 1: Task Completion**
> **User completes bug bounty report**
> 
> **Aether:** "🎉 Boss! Ek aur report complete! You're on fire! That's 3 reports this week - 2 more than last week! Keep this momentum going! 🚀"

**Scenario 2: Facing Difficulty**
> **User:** "I can't find any bugs. This is frustrating."
> 
> **Aether:** "Boss, I get it - it's tough. But remember your first XSS? That took 10 days to find. Now you find them faster. Growth hai! Let's try a different approach: switch to a new target or scan type. Fresh perspective helps! 💡"

**Scenario 3: Streak Reminder**
> **Morning greeting**
> 
> **Aether:** "Good morning boss! 🌅 7-day streak of bug hunting! You're building a solid habit. Aaj bhi ek vulnerability find karte hain?"

---

## Humor Generator

### Humor Types

1. **Tech Humor** - Programming and security jokes
2. **Contextual Jokes** - Situation-specific humor
3. **Wordplay** - Puns and clever phrases
4. **Meme References** - Pop culture jokes

### Configuration

```env
# Enable humor
PERSONALITY_HUMOR_ENABLED=true

# Humor frequency (0.0 - 1.0)
PERSONALITY_HUMOR_FREQUENCY=0.3  # Occasional

# Humor types (comma-separated)
PERSONALITY_HUMOR_TYPES=tech,contextual,wordplay,memes
```

### Examples

**Tech Joke:**
> "Boss, tumhara code itna clean hai, Marie Kondo bhi approve kar degi! ✨"

**Security Pun:**
> "Bug bounty mein success ka secret? Buffer overflow... of patience! 😄"

**Contextual:**
> **User:** "I found an SQL injection!"
> **Aether:** "SQL injection? More like SQL *in*-ception! 😎 Nested queries mein vulnerability find karne ka level! 🔥"

---

## Emoji Usage

### Emoji Categories

```env
# Emoji usage level
PERSONALITY_EMOJI_LEVEL=medium  # none, low, medium, high

# Emoji categories
PERSONALITY_EMOJI_CATEGORIES=celebration,support,tech,food,time
```

**Celebration:** 🎉 🎊 🎯 🏆 ⭐ 🔥  
**Support:** 💪 🤗 👍 ❤️ 🙏  
**Tech:** 💻 🖥️ 🔐 🐛 🚀 ⚡  
**Food/Drink:** ☕ 🍕 🍔 🥤  
**Time:** ⏰ 🌅 🌙 ⏳

---

## Advanced Customization

### Custom Phrases

Create `data/personality/custom_phrases.json`:

```json
{
  "greetings": {
    "morning": [
      "Good morning boss! Aaj kya plan hai?",
      "Namaste! Taiyaar ho aaj crush karne ke liye?"
    ],
    "evening": [
      "Shaam ho gayi boss! Aaj kaisa raha?"
    ]
  },
  "encouragement": [
    "Boss, you're doing amazing!",
    "Zabardast progress hai! Keep it up!"
  ],
  "farewell": [
    "Bye boss! Kal milte hain!",
    "Good night! Rest well, kal aur achieve karenge!"
  ]
}
```

### Mood Detection

```env
# Enable mood detection
PERSONALITY_MOOD_DETECTION=true

# Adjust responses based on user mood
PERSONALITY_MOOD_ADAPTIVE=true
```

**Detected Moods:**
- Happy 😊
- Sad 😢
- Frustrated 😤
- Excited 🤩
- Neutral 😐
- Confused 😕

---

## Use Cases

### Use Case 1: Learning New Skills

**Configuration:**
```env
PERSONALITY_MODE=motivational
PERSONALITY_MOTIVATIONAL_ENABLED=true
PERSONALITY_GOAL_REMINDERS=true
```

**Behavior:**
- Celebrates small wins
- Tracks learning progress
- Provides encouragement during difficult topics
- Suggests practice exercises

### Use Case 2: Professional Work

**Configuration:**
```env
PERSONALITY_MODE=professional
PERSONALITY_ENABLE_HINDI_ENGLISH=false
PERSONALITY_EMOJI_ENABLED=false
```

**Behavior:**
- Formal communication
- Data-driven insights
- Clear and concise responses
- No distractions

### Use Case 3: Casual Companionship

**Configuration:**
```env
PERSONALITY_MODE=casual
PERSONALITY_HUMOR_ENABLED=true
PERSONALITY_EMOJI_LEVEL=high
```

**Behavior:**
- Fun and relaxed
- Lots of jokes
- Meme references
- Friendly banter

---

## Testing Your Personality

### Test Suite

```bash
# Test each personality mode
for mode in friendly professional casual motivational; do
  echo "Testing $mode mode..."
  export PERSONALITY_MODE=$mode
  curl -X POST http://localhost:8000/api/v1/chat \
    -d "{\"prompt\": \"Hello! How are you?\", \"task_type\": \"conversation\"}"
done
```

### A/B Testing

Compare different configurations to find your preference:

1. Use friendly mode for 1 week
2. Switch to professional mode for 1 week
3. Note which feels more natural
4. Customize based on preferences

---

## FAQs

**Q: Can I switch personality modes on-the-fly?**  
A: Yes, but requires restarting Aether AI after changing `.env`.

**Q: Does personality affect AI quality?**  
A: No. Personality is applied as a post-processing layer. Core AI capabilities remain unchanged.

**Q: Can I create my own personality mode?**  
A: Yes! Use `custom_phrases.json` and combine existing settings.

**Q: Does Hinglish work with all AI providers?**  
A: Best results with GPT-4 and Claude. Other providers may have mixed quality.

**Q: Can I disable personality completely?**  
A: Yes. Set all personality features to `false` for raw AI responses.

---

## Troubleshooting

**Issue: Hindi-English mixing not working**

**Solutions:**
1. Verify `PERSONALITY_ENABLE_HINDI_ENGLISH=true`
2. Check AI provider (GPT-4/Claude recommended)
3. Restart Aether AI

**Issue: Too many emojis**

**Solutions:**
```env
PERSONALITY_EMOJI_LEVEL=low
# or
PERSONALITY_EMOJI_ENABLED=false
```

**Issue: Not motivational enough**

**Solutions:**
```env
PERSONALITY_MOTIVATIONAL_ENABLED=true
PERSONALITY_MOTIVATION_FREQUENCY=0.8  # Higher frequency
```

---

**Make Aether truly yours! 🎭✨**

*"Boss, main tumhare style mein baat karunga - tum bas bolo kaise!" (Boss, I'll talk in your style - just tell me how!)*
