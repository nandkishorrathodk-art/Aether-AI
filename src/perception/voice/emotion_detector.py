"""
Emotion Detector (Upgrade #5: Emotion Detection)

Detects user mood from voice tone and text patterns.
Aether responds differently based on detected emotion:
- Stressed → calm, reassuring
- Excited → match energy
- Frustrated → apologetic, focused
- Neutral → normal Jarvis mode

Works on text alone (no audio ML needed), with optional
audio energy analysis for more accuracy.
"""

import re
import logging
from typing import Dict, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class Emotion(Enum):
    EXCITED = "excited"
    STRESSED = "stressed"
    FRUSTRATED = "frustrated"
    HAPPY = "happy"
    NEUTRAL = "neutral"
    CONFUSED = "confused"
    URGENT = "urgent"


# ── Keyword maps ──────────────────────────────────────────────────────────────
EMOTION_KEYWORDS: Dict[Emotion, list] = {
    Emotion.EXCITED: [
        "amazing", "awesome", "!!", "yess", "bhai", "bro", "wow", "nice",
        "excellent", "perfect", "great", "let's go", "chahiye", "chahta"
    ],
    Emotion.STRESSED: [
        "stuck", "not working", "kaam nahi", "dikkat", "problem", "issue",
        "help", "please", "urgent", "jaldi", "asap", "broke", "fail"
    ],
    Emotion.FRUSTRATED: [
        "ugh", "argh", "yaar", "kyu", "kyun nahi", "still", "again", "phir",
        "bakwaas", "useless", "why", "baar baar", "same error"
    ],
    Emotion.CONFUSED: [
        "?", "kya", "samajh nahi", "explain", "matlab", "what", "how",
        "why", "confused", "don't understand", "nahi pata"
    ],
    Emotion.URGENT: [
        "abhi", "right now", "immediately", "turat", "jaldi", "fast",
        "quick", "hurry", "now", "asap"
    ],
    Emotion.HAPPY: [
        "thanks", "shukriya", "perfect", "love it", "mast", "sahi hai",
        "accha", "great job", "bahut accha", "shabash"
    ],
}

# ── Per-emotion response style adjustments ────────────────────────────────────
EMOTION_RESPONSE_STYLE: Dict[Emotion, Dict] = {
    Emotion.EXCITED: {
        "prefix": "Haan boss! ",
        "energy": "high",
        "speed_modifier": 1.1,
    },
    Emotion.STRESSED: {
        "prefix": "Relax sir, main hoon. ",
        "energy": "calm",
        "speed_modifier": 0.9,
    },
    Emotion.FRUSTRATED: {
        "prefix": "Sorry sir, seedha fix karte hain. ",
        "energy": "focused",
        "speed_modifier": 0.95,
    },
    Emotion.CONFUSED: {
        "prefix": "Main explain karta hoon, sir. ",
        "energy": "calm",
        "speed_modifier": 0.9,
    },
    Emotion.URGENT: {
        "prefix": "Immediately, sir! ",
        "energy": "fast",
        "speed_modifier": 1.15,
    },
    Emotion.HAPPY: {
        "prefix": "Bahut accha sir! ",
        "energy": "warm",
        "speed_modifier": 1.0,
    },
    Emotion.NEUTRAL: {
        "prefix": "",
        "energy": "normal",
        "speed_modifier": 1.0,
    },
}


class EmotionDetector:
    """
    Detects emotion from user text and optionally audio energy.
    """

    def detect(self, text: str, audio_energy: float = 0.0) -> Tuple[Emotion, float]:
        """
        Detect emotion from text input.
        
        Args:
            text: User message
            audio_energy: Optional RMS audio energy (0-1)
            
        Returns:
            (Emotion, confidence 0-1)
        """
        text_lower = text.lower()
        scores: Dict[Emotion, int] = {e: 0 for e in Emotion}

        for emotion, keywords in EMOTION_KEYWORDS.items():
            for kw in keywords:
                if kw in text_lower:
                    scores[emotion] += 1

        # Boost URGENT if audio energy is very high (loud/fast speech)
        if audio_energy > 0.7:
            scores[Emotion.URGENT] += 2
        elif audio_energy > 0.5:
            scores[Emotion.EXCITED] += 1

        # Count exclamation marks → excitement
        excl_count = text.count("!")
        if excl_count >= 2:
            scores[Emotion.EXCITED] += excl_count

        best_emotion = max(scores, key=lambda e: scores[e])
        best_score = scores[best_emotion]

        if best_score == 0:
            return Emotion.NEUTRAL, 0.5

        total = sum(scores.values()) or 1
        confidence = min(best_score / total, 0.95)
        logger.debug(f"Emotion detected: {best_emotion.value} (conf={confidence:.2f})")
        return best_emotion, confidence

    def get_response_style(self, emotion: Emotion) -> Dict:
        """Get TTS/response style adjustments for this emotion"""
        return EMOTION_RESPONSE_STYLE.get(emotion, EMOTION_RESPONSE_STYLE[Emotion.NEUTRAL])

    def adapt_response(self, text: str, emotion: Emotion) -> str:
        """Prepend an emotion-appropriate starter to a response"""
        style = self.get_response_style(emotion)
        prefix = style.get("prefix", "")
        if prefix and not text.startswith(prefix):
            return prefix + text
        return text


# ── Global singleton ──────────────────────────────────────────────────────────
_emotion_detector = None


def get_emotion_detector() -> EmotionDetector:
    global _emotion_detector
    if _emotion_detector is None:
        _emotion_detector = EmotionDetector()
    return _emotion_detector


logger.info("🎭 Emotion Detector module loaded")
