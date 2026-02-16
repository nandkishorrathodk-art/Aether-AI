"""
Emotional Intelligence & Empathy Engine
Understands and responds to human emotions
"""
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

class Emotion(Enum):
    HAPPY = "happy"
    SAD = "sad"
    ANGRY = "angry"
    ANXIOUS = "anxious"
    EXCITED = "excited"
    FRUSTRATED = "frustrated"
    CALM = "calm"
    CONFUSED = "confused"
    STRESSED = "stressed"
    CONTENT = "content"

@dataclass
class EmotionalState:
    primary_emotion: Emotion
    intensity: float
    confidence: float
    detected_triggers: List[str]
    timestamp: datetime

class EmotionDetector:
    def __init__(self):
        self.emotion_keywords = {
            Emotion.HAPPY: ['happy', 'joy', 'great', 'awesome', 'love', 'excellent', 'wonderful', 'glad', 'pleased', 'delighted'],
            Emotion.SAD: ['sad', 'unhappy', 'depressed', 'miserable', 'down', 'gloomy', 'disappointed', 'heartbroken'],
            Emotion.ANGRY: ['angry', 'furious', 'mad', 'rage', 'irritated', 'annoyed', 'pissed', 'outraged'],
            Emotion.ANXIOUS: ['anxious', 'worried', 'nervous', 'scared', 'fearful', 'concerned', 'uneasy', 'tense'],
            Emotion.EXCITED: ['excited', 'thrilled', 'pumped', 'energized', 'enthusiastic', 'eager'],
            Emotion.FRUSTRATED: ['frustrated', 'annoyed', 'stuck', 'blocked', 'can\'t', 'won\'t work', 'problem'],
            Emotion.STRESSED: ['stressed', 'overwhelmed', 'pressure', 'too much', 'deadline', 'rushed', 'busy'],
            Emotion.CONFUSED: ['confused', 'don\'t understand', 'unclear', 'lost', 'puzzled', 'what'],
            Emotion.CALM: ['calm', 'peaceful', 'relaxed', 'serene', 'tranquil'],
            Emotion.CONTENT: ['content', 'satisfied', 'okay', 'fine', 'good']
        }
        
        self.sentiment_patterns = {
            'negative': [r'not\s+\w+', r'never', r'hate', r'worst', r'terrible', r'awful'],
            'positive': [r'love', r'best', r'amazing', r'perfect', r'fantastic'],
            'question': [r'\?', r'how', r'what', r'why', r'when', r'where']
        }
    
    def detect_from_text(self, text: str) -> EmotionalState:
        text_lower = text.lower()
        
        emotion_scores = {}
        detected_triggers = []
        
        for emotion, keywords in self.emotion_keywords.items():
            score = 0
            for keyword in keywords:
                if keyword in text_lower:
                    score += 1
                    detected_triggers.append(keyword)
            emotion_scores[emotion] = score
        
        if not emotion_scores or max(emotion_scores.values()) == 0:
            return EmotionalState(
                primary_emotion=Emotion.CALM,
                intensity=0.3,
                confidence=0.5,
                detected_triggers=[],
                timestamp=datetime.now()
            )
        
        primary_emotion = max(emotion_scores, key=emotion_scores.get)
        max_score = emotion_scores[primary_emotion]
        
        intensity = min(max_score / 3.0, 1.0)
        
        total_triggers = sum(emotion_scores.values())
        confidence = max_score / total_triggers if total_triggers > 0 else 0.5
        
        return EmotionalState(
            primary_emotion=primary_emotion,
            intensity=intensity,
            confidence=confidence,
            detected_triggers=detected_triggers,
            timestamp=datetime.now()
        )
    
    def detect_from_voice_tone(self, pitch: float, volume: float, speed: float) -> Emotion:
        if volume > 0.8 and pitch > 0.7:
            return Emotion.EXCITED if speed > 0.6 else Emotion.ANGRY
        elif volume < 0.3 and pitch < 0.4:
            return Emotion.SAD
        elif speed > 0.8:
            return Emotion.ANXIOUS
        elif volume < 0.4 and speed < 0.4:
            return Emotion.CALM
        else:
            return Emotion.CONTENT

class EmpathyGenerator:
    def __init__(self):
        self.empathetic_responses = {
            Emotion.HAPPY: [
                "That's wonderful to hear! I'm so glad you're feeling happy!",
                "Your happiness is contagious! How can I help make your day even better?",
                "I love seeing you in such a great mood!"
            ],
            Emotion.SAD: [
                "I'm sorry you're feeling down. I'm here for you.",
                "It's okay to feel sad sometimes. Would you like to talk about it?",
                "I understand this is difficult. How can I support you?"
            ],
            Emotion.ANGRY: [
                "I can sense your frustration. Take a deep breath, and let's work through this together.",
                "I understand you're upset. Let's find a solution to what's bothering you.",
                "Your feelings are valid. How can I help resolve this?"
            ],
            Emotion.ANXIOUS: [
                "I know you're feeling anxious. Let's take this one step at a time.",
                "It's okay to feel worried. Would some breathing exercises help?",
                "I'm here to help you through this. What's on your mind?"
            ],
            Emotion.EXCITED: [
                "Your energy is amazing! Let's channel this excitement into something productive!",
                "I love your enthusiasm! What are you excited about?",
                "This is great! How can I help with your exciting plans?"
            ],
            Emotion.FRUSTRATED: [
                "I can tell you're frustrated. Let's break this down into smaller steps.",
                "Frustration is normal. Let's find a different approach together.",
                "I understand this is challenging. Want me to help you tackle it?"
            ],
            Emotion.STRESSED: [
                "You seem overwhelmed. Let's prioritize and tackle one thing at a time.",
                "Stress is tough. How about a quick break to recharge?",
                "I'm here to help lighten your load. What's the most urgent task?"
            ],
            Emotion.CONFUSED: [
                "No problem! Let me explain that more clearly.",
                "I'll break it down step-by-step so it's easier to understand.",
                "Confusion is just the first step to clarity. What part is unclear?"
            ],
            Emotion.CALM: [
                "I'm glad you're feeling peaceful. How can I assist you today?",
                "You seem relaxed. What would you like to work on?",
                "Great to see you're in a calm state. Let's be productive!"
            ],
            Emotion.CONTENT: [
                "You seem satisfied. That's great! Anything I can help with?",
                "I'm glad things are going well for you!",
                "Contentment is wonderful. Let's keep this positive momentum!"
            ]
        }
    
    def generate_response(self, emotional_state: EmotionalState) -> str:
        import random
        responses = self.empathetic_responses.get(emotional_state.primary_emotion, [])
        
        if not responses:
            return "I'm here to help you. What can I do for you?"
        
        response = random.choice(responses)
        
        if emotional_state.intensity > 0.7:
            response += " I can tell this is really important to you."
        
        return response

class MoodTracker:
    def __init__(self):
        self.mood_history = []
    
    def track_mood(self, emotional_state: EmotionalState):
        self.mood_history.append({
            'emotion': emotional_state.primary_emotion.value,
            'intensity': emotional_state.intensity,
            'timestamp': emotional_state.timestamp.isoformat()
        })
        
        if len(self.mood_history) > 100:
            self.mood_history = self.mood_history[-100:]
    
    def get_mood_trend(self, hours: int = 24) -> Dict[str, float]:
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        
        recent_moods = [
            m for m in self.mood_history 
            if datetime.fromisoformat(m['timestamp']) > cutoff
        ]
        
        if not recent_moods:
            return {}
        
        emotion_counts = {}
        for mood in recent_moods:
            emotion = mood['emotion']
            emotion_counts[emotion] = emotion_counts.get(emotion, 0) + 1
        
        total = len(recent_moods)
        return {emotion: count / total for emotion, count in emotion_counts.items()}
    
    def get_average_mood_intensity(self) -> float:
        if not self.mood_history:
            return 0.5
        
        return sum(m['intensity'] for m in self.mood_history) / len(self.mood_history)

class EmotionalSupportMode:
    def __init__(self):
        self.active = False
        self.support_strategies = {
            'breathing': {
                'name': 'Breathing Exercise',
                'instructions': [
                    "Breathe in slowly for 4 seconds",
                    "Hold for 4 seconds",
                    "Breathe out for 4 seconds",
                    "Repeat 3 times"
                ]
            },
            'grounding': {
                'name': '5-4-3-2-1 Grounding',
                'instructions': [
                    "Name 5 things you can see",
                    "Name 4 things you can touch",
                    "Name 3 things you can hear",
                    "Name 2 things you can smell",
                    "Name 1 thing you can taste"
                ]
            },
            'positive_affirmations': {
                'name': 'Positive Affirmations',
                'affirmations': [
                    "I am capable and strong",
                    "This feeling will pass",
                    "I can handle whatever comes my way",
                    "I am doing my best, and that's enough"
                ]
            }
        }
    
    def activate(self, emotion: Emotion):
        self.active = True
        
        if emotion in [Emotion.ANXIOUS, Emotion.STRESSED]:
            return self.support_strategies['breathing']
        elif emotion in [Emotion.SAD, Emotion.FRUSTRATED]:
            return self.support_strategies['positive_affirmations']
        else:
            return self.support_strategies['grounding']
    
    def deactivate(self):
        self.active = False

class EmpathyEngine:
    def __init__(self):
        self.emotion_detector = EmotionDetector()
        self.empathy_generator = EmpathyGenerator()
        self.mood_tracker = MoodTracker()
        self.support_mode = EmotionalSupportMode()
    
    def process_text(self, text: str) -> Dict[str, any]:
        emotional_state = self.emotion_detector.detect_from_text(text)
        
        self.mood_tracker.track_mood(emotional_state)
        
        empathetic_response = self.empathy_generator.generate_response(emotional_state)
        
        support_needed = emotional_state.intensity > 0.7 and emotional_state.primary_emotion in [
            Emotion.SAD, Emotion.ANXIOUS, Emotion.STRESSED, Emotion.ANGRY
        ]
        
        result = {
            'detected_emotion': emotional_state.primary_emotion.value,
            'intensity': emotional_state.intensity,
            'confidence': emotional_state.confidence,
            'empathetic_response': empathetic_response,
            'support_needed': support_needed
        }
        
        if support_needed:
            result['support_strategy'] = self.support_mode.activate(emotional_state.primary_emotion)
        
        return result
    
    def get_mood_report(self) -> Dict[str, any]:
        return {
            'recent_trend': self.mood_tracker.get_mood_trend(24),
            'average_intensity': self.mood_tracker.get_average_mood_intensity(),
            'total_interactions': len(self.mood_tracker.mood_history)
        }

empathy_engine = EmpathyEngine()

def detect_emotion(text: str) -> Dict[str, any]:
    return empathy_engine.process_text(text)

def get_mood_report() -> Dict[str, any]:
    return empathy_engine.get_mood_report()
