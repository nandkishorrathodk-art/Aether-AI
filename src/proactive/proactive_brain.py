"""
Proactive Brain - Core proactive intelligence system
Orchestrates suggestions, planning, and proactive interactions
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import asyncio

from src.proactive.suggestion_generator import SuggestionGenerator, ProactiveSuggestion, get_suggestion_generator
from src.proactive.daily_planner import DailyPlanner, get_daily_planner
from src.cognitive.memory.user_profile import UserProfile
from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)


class ProactiveBrain:
    def __init__(
        self,
        user_profile: Optional[UserProfile] = None,
        suggestion_generator: Optional[SuggestionGenerator] = None,
        daily_planner: Optional[DailyPlanner] = None
    ):
        self.user_profile = user_profile or UserProfile()
        self.suggestion_generator = suggestion_generator or get_suggestion_generator()
        self.daily_planner = daily_planner or get_daily_planner()
        
        self.last_check_time: Optional[datetime] = None
        self.last_greeting_date: Optional[str] = None
        self.context_cache: Dict[str, Any] = {}
        
        logger.info("ProactiveBrain initialized")

    async def check_and_suggest(
        self,
        current_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        current_time = datetime.now()
        
        if self.last_check_time:
            time_since_check = (current_time - self.last_check_time).seconds
            if time_since_check < 60:
                logger.debug("Skipping check - too soon since last check")
                return {
                    "status": "skipped",
                    "reason": "too_soon",
                    "suggestions": []
                }
        
        self.last_check_time = current_time
        
        try:
            context = await self._build_context(current_context)
            
            suggestions = await self.suggestion_generator.generate_contextual_suggestions(
                user_context=context
            )
            
            greeting = await self._check_morning_greeting()
            
            result = {
                "status": "success",
                "timestamp": current_time.isoformat(),
                "suggestions": [s.to_dict() for s in suggestions],
                "greeting": greeting,
                "context": context
            }
            
            logger.info(f"Proactive check completed: {len(suggestions)} suggestions")
            return result
            
        except Exception as e:
            logger.error(f"Proactive check failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "suggestions": []
            }

    async def _build_context(self, external_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        context = external_context or {}
        
        try:
            from src.monitoring import get_monitoring_bridge
            bridge = get_monitoring_bridge()
            detection = await bridge.detect_apps()
            
            if "error" not in detection:
                context["detected_apps"] = detection.get("target_apps_detected", [])
                context["active_window"] = detection.get("active_window", {}).get("name", "Unknown")
        except Exception as e:
            logger.debug(f"Could not fetch monitoring context: {e}")
            context["detected_apps"] = []
            context["active_window"] = "Unknown"
        
        user_prefs = self.user_profile.get_personalization_context()
        context["user_interests"] = user_prefs.get("interests", [])
        context["communication_style"] = user_prefs.get("communication_style", "friendly")
        
        stats = self.user_profile.get("statistics", {})
        last_active = stats.get("last_active")
        if last_active:
            context["last_break_time"] = last_active
        
        plan = self.daily_planner.load_plan()
        if plan:
            context["daily_goals"] = plan.goals
            current_task = self.daily_planner.get_current_task()
            if current_task:
                context["current_task"] = current_task.to_dict()
        
        self.context_cache = context
        return context

    async def _check_morning_greeting(self) -> Optional[str]:
        if not settings.proactive_morning_greeting:
            return None
        
        today = datetime.now().date().isoformat()
        
        if self.last_greeting_date == today:
            return None
        
        current_hour = datetime.now().hour
        if 6 <= current_hour < 11:
            self.last_greeting_date = today
            greeting = await self.daily_planner.generate_morning_greeting()
            logger.info("Morning greeting generated")
            return greeting
        
        return None

    async def proactive_greeting(self) -> str:
        return await self.daily_planner.generate_morning_greeting()

    async def generate_daily_plan(
        self,
        user_goals: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        try:
            plan = await self.daily_planner.generate_daily_plan(user_goals)
            return {
                "status": "success",
                "plan": plan.to_dict()
            }
        except Exception as e:
            logger.error(f"Failed to generate daily plan: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    def get_suggestion_by_id(self, suggestion_id: str) -> Optional[ProactiveSuggestion]:
        for suggestion in self.suggestion_generator.suggestion_history:
            if suggestion.id == suggestion_id:
                return suggestion
        return None

    async def periodic_check(self):
        interval_seconds = settings.proactive_check_interval
        logger.info(f"Starting periodic proactive checks every {interval_seconds}s")
        
        while True:
            try:
                await asyncio.sleep(interval_seconds)
                result = await self.check_and_suggest()
                
                if result.get("suggestions"):
                    logger.info(f"Periodic check: {len(result['suggestions'])} new suggestions")
                
                if result.get("greeting"):
                    logger.info(f"Morning greeting: {result['greeting'][:50]}...")
                    
            except asyncio.CancelledError:
                logger.info("Periodic check cancelled")
                break
            except Exception as e:
                logger.error(f"Error in periodic check: {e}")
                await asyncio.sleep(60)

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_suggestions": len(self.suggestion_generator.suggestion_history),
            "last_check_time": self.last_check_time.isoformat() if self.last_check_time else None,
            "last_greeting_date": self.last_greeting_date,
            "enabled_suggestion_types": self.suggestion_generator.suggestion_types,
            "proactive_mode_enabled": settings.enable_proactive_mode,
            "morning_greeting_enabled": settings.proactive_morning_greeting
        }


_proactive_brain: Optional[ProactiveBrain] = None


def get_proactive_brain() -> ProactiveBrain:
    global _proactive_brain
    if _proactive_brain is None:
        _proactive_brain = ProactiveBrain()
    return _proactive_brain
