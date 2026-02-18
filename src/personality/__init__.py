"""
Personality System for Aether AI

Human-like conversational personality with empathy and emotion.
"""

from src.personality.conversational_style import ConversationalStyle
from src.personality.motivational_engine import MotivationalEngine
from src.personality.humor_generator import HumorGenerator

# v3.0 components
from src.personality.empathy_engine import EmpathyEngine

# Initialize singleton
empathy_engine = EmpathyEngine()

__all__ = [
    "ConversationalStyle",
    "MotivationalEngine",
    "HumorGenerator",
    "EmpathyEngine",
    "empathy_engine"
]
