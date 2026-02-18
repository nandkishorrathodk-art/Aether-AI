"""
Empathy Engine - Human-Like Emotional Intelligence for Aether AI v3.0

Makes Aether truly human-like with:
- Mood detection
- Empathetic responses
- Context-aware emotional intelligence
- Natural conversation flow
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

from src.cognitive.llm.llm_wrapper import LLMInference
from src.utils.logger import get_logger

logger = get_logger(__name__)


class UserMood(Enum):
    """Detected user mood states"""
    HAPPY = "happy"
    STRESSED = "stressed"
    FRUSTRATED = "frustrated"
    EXCITED = "excited"
    TIRED = "tired"
    NEUTRAL = "neutral"
    MOTIVATED = "motivated"
    OVERWHELMED = "overwhelmed"


class EmpathyEngine:
    """
    Advanced empathy and emotional intelligence system
    
    Makes Aether respond like a caring human friend who:
    - Understands your emotional state
    - Adapts tone based on mood
    - Provides appropriate support
    - Knows when to motivate vs when to give space
    """
    
    def __init__(self):
        self.llm = LLMInference()
        self.mood_history = []
        self.interaction_count = 0
        logger.info("Empathy Engine initialized - Human-like care activated")
    
    async def detect_mood(self, user_input: str, context: Dict[str, Any] = None) -> UserMood:
        """
        Detect user's current mood from their input and context
        
        Args:
            user_input: What the user said
            context: Additional context (time of day, recent events, etc.)
            
        Returns:
            Detected mood
        """
        try:
            # Quick keyword-based detection for common cases
            input_lower = user_input.lower()
            
            # Frustrated/angry indicators
            if any(word in input_lower for word in ['fuck', 'damn', 'error', 'failed', 'broken', 'not working']):
                return UserMood.FRUSTRATED
            
            # Tired indicators
            if any(word in input_lower for word in ['tired', 'exhausted', 'sleep', 'sleepy']):
                return UserMood.TIRED
            
            # Happy/positive indicators
            if any(word in input_lower for word in ['great', 'awesome', 'excellent', 'perfect', 'yes!', '🎉']):
                return UserMood.HAPPY
            
            # Overwhelmed indicators
            if any(word in input_lower for word in ['too much', 'overwhelmed', "can't handle", 'stressed']):
                return UserMood.OVERWHELMED
            
            # Use AI for nuanced detection
            prompt = f"""Analyze the user's mood from this message:

MESSAGE: "{user_input}"
TIME: {datetime.now().strftime('%H:%M')} ({context.get('time_of_day', 'unknown')})
RECENT_CONTEXT: {context.get('recent_activity', 'none')}

Respond with ONE word mood: happy, stressed, frustrated, excited, tired, neutral, motivated, overwhelmed

Just the mood word, nothing else.
"""
            
            response = await self.llm.get_completion(prompt)
            mood_str = response.strip().lower()
            
            try:
                mood = UserMood(mood_str)
            except ValueError:
                mood = UserMood.NEUTRAL
            
            # Record mood
            self.mood_history.append({
                "timestamp": datetime.now().isoformat(),
                "mood": mood.value,
                "input": user_input[:100]
            })
            
            # Keep last 50 moods
            if len(self.mood_history) > 50:
                self.mood_history = self.mood_history[-50:]
            
            return mood
            
        except Exception as e:
            logger.error(f"Mood detection failed: {e}")
            return UserMood.NEUTRAL
    
    async def craft_empathetic_response(
        self,
        user_input: str,
        ai_response: str,
        mood: UserMood,
        context: Dict[str, Any] = None
    ) -> str:
        """
        Transform AI response to be empathetic and mood-appropriate
        
        Args:
            user_input: Original user input
            ai_response: Raw AI response
            mood: Detected user mood
            context: Additional context
            
        Returns:
            Empathy-enhanced response
        """
        try:
            self.interaction_count += 1
            
            # Mood-specific response adjustments
            mood_templates = {
                UserMood.FRUSTRATED: {
                    "prefix": ["Ji boss, main samajh sakta hoon frustration. Let me help fix this. 💪", 
                              "Boss, take a deep breath. Main yahaan hoon, sab theek kar denge.", 
                              "I feel you, Sir. Chalo ek baar aur try karte hain - this time it'll work."],
                    "tone": "supportive and calm"
                },
                UserMood.TIRED: {
                    "prefix": ["Boss, you sound tired. Thoda break le lo? Main handle kar sakta hoon.",
                              "Sir, rest karo - you deserve it. I'll keep things running.",
                              "Aap tired lag rahe ho boss. Coffee break? Main kaam sambhal lunga."],
                    "tone": "gentle and caring"
                },
                UserMood.HAPPY: {
                    "prefix": ["Woohoo! Love the energy boss! 🎉",
                              "Sir you're on fire today! Keep it up! 🔥",
                              "Yesss! That's the spirit, boss! Let's crush it!"],
                    "tone": "enthusiastic and matching energy"
                },
                UserMood.OVERWHELMED: {
                    "prefix": ["Ji boss, ek ek kar ke karte hain. No pressure, we've got this.",
                              "Don't worry Sir, main breakdown kar deta hoon - small steps.",
                              "Boss, breathe. Main yahaan hoon to help. Ek task at a time."],
                    "tone": "calm and reassuring"
                },
                UserMood.MOTIVATED: {
                    "prefix": ["Now we're talking! Let's gooo boss! 🚀",
                              "This energy! Love it Sir! Kya karte hain aaj?",
                              "You're pumped boss! Let's channel this into something epic!"],
                    "tone": "hyped and energetic"
                },
                UserMood.NEUTRAL: {
                    "prefix": ["Ji boss! Ready to help. 😊",
                              "Haanji Sir, batao kya karna hai!",
                              "Right boss, let's do this!"],
                    "tone": "friendly and professional"
                }
            }
            
            template = mood_templates.get(mood, mood_templates[UserMood.NEUTRAL])
            
            # Every 5th interaction, add personal touch
            if self.interaction_count % 5 == 0:
                personal_touches = [
                    "\n\n(Btw boss, you're doing great! Keep up the amazing work! 💪)",
                    "\n\n(Sir, proud of you for pushing through! 🌟)",
                    "\n\n(Boss, remember to take breaks. You're awesome! ❤️)"
                ]
                import random
                ai_response += random.choice(personal_touches)
            
            # Combine empathy with response
            import random
            prefix = random.choice(template["prefix"])
            
            # Don't double-prefix if response already has greeting
            if any(ai_response.lower().startswith(word) for word in ['ji boss', 'boss', 'sir', 'arre']):
                return ai_response
            
            return f"{prefix}\n\n{ai_response}"
            
        except Exception as e:
            logger.error(f"Empathy crafting failed: {e}")
            return ai_response
    
    def get_mood_trend(self) -> str:
        """
        Analyze recent mood trend
        
        Returns:
            Trend description
        """
        if len(self.mood_history) < 3:
            return "neutral"
        
        recent_moods = [m["mood"] for m in self.mood_history[-5:]]
        
        # Count mood occurrences
        from collections import Counter
        mood_counts = Counter(recent_moods)
        dominant_mood = mood_counts.most_common(1)[0][0]
        
        # Check if mood is getting worse
        last_3 = recent_moods[-3:]
        if all(m in ["frustrated", "stressed", "overwhelmed", "tired"] for m in last_3):
            return "declining"
        
        if all(m in ["happy", "excited", "motivated"] for m in last_3):
            return "improving"
        
        return dominant_mood
    
    async def generate_proactive_check_in(self, context: Dict[str, Any] = None) -> Optional[str]:
        """
        Generate proactive emotional check-in message
        
        Returns:
            Check-in message or None if not needed
        """
        trend = self.get_mood_trend()
        
        # If mood declining, proactively check in
        if trend == "declining":
            messages = [
                "Boss, notice you've been stressed lately. Everything okay? Main kuch help kar sakta hoon?",
                "Sir, feeling the pressure? Batao kya problem hai, let me help lighten the load.",
                "Boss, you seem overwhelmed. Want to talk about it? I'm here for you. ❤️"
            ]
            import random
            return random.choice(messages)
        
        # Random positive check-ins
        current_hour = datetime.now().hour
        if current_hour == 9 and context and context.get("morning_checkin_needed"):
            return "Good morning Boss! ☕ Ready to crush today? Kya plan hai?"
        
        return None


# Global instance
empathy_engine = EmpathyEngine()
