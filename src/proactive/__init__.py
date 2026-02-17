"""
Proactive AI Brain & Daily Planning Module
Provides context-aware suggestions and proactive task planning
"""

from src.proactive.proactive_brain import ProactiveBrain, get_proactive_brain
from src.proactive.suggestion_generator import (
    SuggestionGenerator, ProactiveSuggestion, get_suggestion_generator
)
from src.proactive.daily_planner import DailyPlanner, DailyPlan, get_daily_planner
from src.proactive.auto_executor import AutoExecutor, get_auto_executor

__all__ = [
    "ProactiveBrain",
    "get_proactive_brain",
    "SuggestionGenerator",
    "get_suggestion_generator",
    "ProactiveSuggestion",
    "DailyPlanner",
    "get_daily_planner",
    "DailyPlan",
    "AutoExecutor",
    "get_auto_executor"
]
