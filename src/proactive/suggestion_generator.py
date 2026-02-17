"""
Suggestion Generator - Creates contextual proactive suggestions
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, time as datetime_time
import uuid
import json
from pathlib import Path

from src.cognitive.llm.model_loader import model_loader
from src.cognitive.llm.providers.base import TaskType
from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)


@dataclass
class ProactiveSuggestion:
    id: str
    timestamp: str
    context: str
    suggestion_type: str
    title: str
    description: str
    action_command: Optional[str]
    confidence: float
    requires_approval: bool
    priority: int = 5
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SuggestionGenerator:
    def __init__(self):
        self.suggestion_types = settings.get_proactive_suggestion_types()
        self.history_file = settings.screen_monitor_data_path / "suggestion_history.json"
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        self.suggestion_history: List[ProactiveSuggestion] = self._load_history()
        logger.info(f"SuggestionGenerator initialized with types: {self.suggestion_types}")

    def _load_history(self) -> List[ProactiveSuggestion]:
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return [ProactiveSuggestion(**item) for item in data[-100:]]
            except Exception as e:
                logger.error(f"Failed to load suggestion history: {e}")
                return []
        return []

    def _save_history(self):
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(
                    [s.to_dict() for s in self.suggestion_history[-100:]],
                    f,
                    indent=2
                )
        except Exception as e:
            logger.error(f"Failed to save suggestion history: {e}")

    async def generate_contextual_suggestions(
        self,
        user_context: Dict[str, Any],
        time_of_day: Optional[str] = None
    ) -> List[ProactiveSuggestion]:
        current_time = datetime.now()
        time_of_day = time_of_day or self._get_time_of_day(current_time)
        
        suggestions = []
        
        for suggestion_type in self.suggestion_types:
            try:
                suggestion = await self._generate_suggestion(
                    suggestion_type,
                    user_context,
                    time_of_day,
                    current_time
                )
                if suggestion:
                    suggestions.append(suggestion)
            except Exception as e:
                logger.error(f"Failed to generate {suggestion_type} suggestion: {e}")
        
        self.suggestion_history.extend(suggestions)
        self._save_history()
        
        return sorted(suggestions, key=lambda s: (-s.priority, -s.confidence))

    async def _generate_suggestion(
        self,
        suggestion_type: str,
        context: Dict[str, Any],
        time_of_day: str,
        current_time: datetime
    ) -> Optional[ProactiveSuggestion]:
        
        if suggestion_type == "bug_bounty":
            return await self._generate_bug_bounty_suggestion(context, time_of_day)
        elif suggestion_type == "youtube":
            return await self._generate_youtube_suggestion(context, time_of_day)
        elif suggestion_type == "breaks":
            return self._generate_break_suggestion(context, current_time)
        elif suggestion_type == "learning":
            return await self._generate_learning_suggestion(context, time_of_day)
        else:
            return None

    async def _generate_bug_bounty_suggestion(
        self,
        context: Dict[str, Any],
        time_of_day: str
    ) -> Optional[ProactiveSuggestion]:
        
        detected_apps = context.get("detected_apps", [])
        activity_type = context.get("activity_type", "unknown")
        
        if "Burp Suite" in detected_apps or activity_type == "security_testing":
            title = "Boss! Burp Suite detected - Continue bug hunting?"
            description = "Burp Suite active hai. Apple Security Bounty pe focus karein? $2M tak ka potential hai advanced chains mein."
            action = "start_bugbounty_autopilot"
            priority = 10
            confidence = 0.9
        elif time_of_day == "morning":
            title = "Good morning Boss! Bug bounty shuru karein?"
            description = "Aaj ka focus: Apple/Google high-paying programs. Fresh vulnerabilities ka best time hai!"
            action = "open_bugbounty_dashboard"
            priority = 8
            confidence = 0.7
        elif time_of_day == "evening":
            title = "Evening productive session?"
            description = "Bug bounty automation run karein? Burp Suite auto-scan se quick wins mil sakte hain."
            action = None
            priority = 6
            confidence = 0.6
        else:
            return None
        
        return ProactiveSuggestion(
            id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            context=f"Time: {time_of_day}, Apps: {', '.join(detected_apps)}",
            suggestion_type="bug_bounty",
            title=title,
            description=description,
            action_command=action,
            confidence=confidence,
            requires_approval=True,
            priority=priority,
            metadata={"detected_apps": detected_apps}
        )

    async def _generate_youtube_suggestion(
        self,
        context: Dict[str, Any],
        time_of_day: str
    ) -> Optional[ProactiveSuggestion]:
        
        if time_of_day == "afternoon":
            prompt = """Suggest ONE trending YouTube niche for Feb 2026 that has high CPM ($10-25).
Format: {"title": "...", "description": "...", "confidence": 0.8}"""
            
            try:
                response = await model_loader.generate(
                    prompt=prompt,
                    task_type=TaskType.FAST,
                    system_prompt="You are a YouTube trends expert. Respond with valid JSON only.",
                    temperature=0.7,
                    max_tokens=150
                )
                
                import re
                match = re.search(r'\{.*\}', response.content, re.DOTALL)
                if match:
                    result = json.loads(match.group(0))
                    return ProactiveSuggestion(
                        id=str(uuid.uuid4()),
                        timestamp=datetime.now().isoformat(),
                        context=f"Time: {time_of_day}",
                        suggestion_type="youtube",
                        title=result.get("title", "YouTube content idea"),
                        description=result.get("description", "High CPM niche trending hai"),
                        action_command="open_youtube_studio",
                        confidence=result.get("confidence", 0.7),
                        requires_approval=False,
                        priority=7,
                        metadata={"niche": "trending"}
                    )
            except Exception as e:
                logger.error(f"Failed to generate YouTube suggestion: {e}")
        
        return None

    def _generate_break_suggestion(
        self,
        context: Dict[str, Any],
        current_time: datetime
    ) -> Optional[ProactiveSuggestion]:
        
        last_break = context.get("last_break_time")
        if last_break:
            hours_since_break = (current_time - datetime.fromisoformat(last_break)).seconds / 3600
            if hours_since_break >= 2:
                return ProactiveSuggestion(
                    id=str(uuid.uuid4()),
                    timestamp=current_time.isoformat(),
                    context=f"Last break: {hours_since_break:.1f} hours ago",
                    suggestion_type="breaks",
                    title="Boss, break time! 🌟",
                    description=f"{hours_since_break:.1f} hours se continuous kaam. 10-minute break lein - eyes rest, water piyo, stretch karo.",
                    action_command=None,
                    confidence=0.95,
                    requires_approval=False,
                    priority=9,
                    metadata={"hours_since_break": hours_since_break}
                )
        
        return None

    async def _generate_learning_suggestion(
        self,
        context: Dict[str, Any],
        time_of_day: str
    ) -> Optional[ProactiveSuggestion]:
        
        if time_of_day == "night":
            return ProactiveSuggestion(
                id=str(uuid.uuid4()),
                timestamp=datetime.now().isoformat(),
                context=f"Time: {time_of_day}",
                suggestion_type="learning",
                title="Night learning session?",
                description="Latest security research padhein ya new exploit techniques practice karein. Calm environment hai learning ke liye.",
                action_command=None,
                confidence=0.65,
                requires_approval=False,
                priority=5,
                metadata={"topic": "security_research"}
            )
        
        return None

    def _get_time_of_day(self, dt: datetime) -> str:
        hour = dt.hour
        if 5 <= hour < 12:
            return "morning"
        elif 12 <= hour < 17:
            return "afternoon"
        elif 17 <= hour < 21:
            return "evening"
        else:
            return "night"

    def get_recent_suggestions(self, limit: int = 10) -> List[ProactiveSuggestion]:
        return self.suggestion_history[-limit:]

    def clear_history(self):
        self.suggestion_history = []
        self._save_history()
        logger.info("Suggestion history cleared")


_generator: Optional[SuggestionGenerator] = None


def get_suggestion_generator() -> SuggestionGenerator:
    global _generator
    if _generator is None:
        _generator = SuggestionGenerator()
    return _generator
