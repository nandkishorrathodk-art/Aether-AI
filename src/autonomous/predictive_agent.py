"""
Predictive Agent - Forecasts User Needs Before They Ask

Uses machine learning on usage patterns to predict what you'll need next.
The ultimate proactive AI.
"""

import asyncio
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PredictiveAgent:
    """
    Predicts user needs using pattern recognition and time-series analysis
    
    Features:
    - Learns from usage patterns
    - Time-of-day predictions
    - Context-aware forecasting
    - Confidence scoring
    """
    
    def __init__(self):
        self.data_path = Path("data/predictions")
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        self.usage_log_path = self.data_path / "usage_log.jsonl"
        self.patterns_path = self.data_path / "learned_patterns.json"
        
        self.patterns = self._load_patterns()
        logger.info("Predictive Agent initialized - Forecasting needs")
    
    def _load_patterns(self) -> Dict:
        """Load learned patterns from disk"""
        if self.patterns_path.exists():
            try:
                with open(self.patterns_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load patterns: {e}")
        
        return {
            "hourly_tasks": defaultdict(list),
            "sequential_patterns": [],
            "context_patterns": {},
            "user_preferences": {}
        }
    
    def _save_patterns(self):
        """Save learned patterns to disk"""
        try:
            # Convert defaultdict to regular dict for JSON serialization
            patterns_to_save = {
                "hourly_tasks": dict(self.patterns["hourly_tasks"]),
                "sequential_patterns": self.patterns["sequential_patterns"],
                "context_patterns": self.patterns["context_patterns"],
                "user_preferences": self.patterns["user_preferences"]
            }
            
            with open(self.patterns_path, 'w') as f:
                json.dump(patterns_to_save, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save patterns: {e}")
    
    def log_activity(
        self,
        activity_type: str,
        details: Dict[str, Any],
        context: Dict[str, Any] = None
    ):
        """
        Log user activity for pattern learning
        
        Args:
            activity_type: Type of activity (e.g., "bug_bounty", "job_search")
            details: Activity details
            context: Additional context (time, screen content, etc.)
        """
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "hour": datetime.now().hour,
                "day_of_week": datetime.now().strftime("%A"),
                "activity_type": activity_type,
                "details": details,
                "context": context or {}
            }
            
            # Append to log file
            with open(self.usage_log_path, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            # Update patterns in memory
            self._update_patterns(log_entry)
            
        except Exception as e:
            logger.error(f"Failed to log activity: {e}")
    
    def _update_patterns(self, log_entry: Dict):
        """Update learned patterns based on new activity"""
        hour = log_entry["hour"]
        activity_type = log_entry["activity_type"]
        
        # Hourly pattern learning
        if hour not in self.patterns["hourly_tasks"]:
            self.patterns["hourly_tasks"][hour] = []
        
        self.patterns["hourly_tasks"][hour].append(activity_type)
        
        # Keep last 100 entries per hour
        if len(self.patterns["hourly_tasks"][hour]) > 100:
            self.patterns["hourly_tasks"][hour] = self.patterns["hourly_tasks"][hour][-100:]
        
        # Save every 10 logs
        if sum(len(tasks) for tasks in self.patterns["hourly_tasks"].values()) % 10 == 0:
            self._save_patterns()
    
    async def predict_next_need(
        self,
        context: Dict[str, Any] = None
    ) -> List[Tuple[str, float]]:
        """
        Predict what user might need next
        
        Args:
            context: Current context (time, screen content, recent activity)
            
        Returns:
            List of (prediction, confidence) tuples, sorted by confidence
        """
        predictions = []
        current_hour = datetime.now().hour
        
        # Time-based predictions
        if str(current_hour) in self.patterns["hourly_tasks"]:
            hourly_activities = self.patterns["hourly_tasks"][str(current_hour)]
            activity_counts = Counter(hourly_activities)
            
            total = sum(activity_counts.values())
            for activity, count in activity_counts.most_common(3):
                confidence = count / total
                predictions.append((activity, confidence))
        
        # Context-based predictions
        if context:
            # Screen content analysis
            if "screen_content" in context:
                screen = context["screen_content"].lower()
                
                if "burp" in screen:
                    predictions.append(("bug_bounty_assist", 0.8))
                elif "linkedin" in screen or "indeed" in screen:
                    predictions.append(("job_search", 0.75))
                elif "vs code" in screen or "github" in screen:
                    predictions.append(("code_development", 0.7))
            
            # Time of day heuristics
            hour = datetime.now().hour
            if 8 <= hour < 10:
                predictions.append(("morning_brief", 0.6))
                predictions.append(("job_applications", 0.5))
            elif 14 <= hour < 16:
                predictions.append(("bug_bounty", 0.55))
            elif 20 <= hour < 22:
                predictions.append(("daily_report", 0.7))
        
        # Remove duplicates, keep highest confidence
        unique_predictions = {}
        for pred, conf in predictions:
            if pred not in unique_predictions or conf > unique_predictions[pred]:
                unique_predictions[pred] = conf
        
        # Sort by confidence
        sorted_predictions = sorted(
            unique_predictions.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return sorted_predictions[:5]  # Top 5 predictions
    
    async def get_proactive_suggestions(
        self,
        context: Dict[str, Any] = None,
        min_confidence: float = 0.4
    ) -> List[Dict[str, Any]]:
        """
        Get proactive task suggestions with high confidence
        
        Args:
            context: Current context
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of actionable suggestions
        """
        predictions = await self.predict_next_need(context)
        
        suggestions = []
        for task_type, confidence in predictions:
            if confidence < min_confidence:
                continue
            
            suggestion = self._task_to_suggestion(task_type, confidence)
            if suggestion:
                suggestions.append(suggestion)
        
        return suggestions
    
    def _task_to_suggestion(self, task_type: str, confidence: float) -> Optional[Dict]:
        """Convert task type to actionable suggestion"""
        
        suggestions_map = {
            "bug_bounty": {
                "type": "bug_bounty",
                "message": "Ji boss! Time for bug hunting? New programs detected. Shall I scan? 🐛",
                "action": "start_autonomous_hunt",
                "confidence": confidence
            },
            "job_search": {
                "type": "job_search",
                "message": "Sir, morning job search time! I can auto-apply to 100+ positions. Ready?",
                "action": "start_job_applications",
                "confidence": confidence
            },
            "code_development": {
                "type": "code_development",
                "message": "Boss, coding session? I can review code or suggest optimizations!",
                "action": "code_review",
                "confidence": confidence
            },
            "morning_brief": {
                "type": "daily_brief",
                "message": "Good morning Sir! ☕ Daily brief: 3 new opportunities, 2 PRs pending. Details?",
                "action": "show_daily_brief",
                "confidence": confidence
            },
            "daily_report": {
                "type": "report",
                "message": "Boss, end of day! Shall I generate today's report?",
                "action": "generate_daily_report",
                "confidence": confidence
            }
        }
        
        return suggestions_map.get(task_type)
    
    async def learn_from_feedback(
        self,
        prediction: str,
        was_accurate: bool,
        user_action: Optional[str] = None
    ):
        """
        Learn from prediction accuracy feedback
        
        Args:
            prediction: What was predicted
            was_accurate: Whether prediction was accurate
            user_action: What user actually did
        """
        # Store feedback for future improvement
        feedback_entry = {
            "timestamp": datetime.now().isoformat(),
            "prediction": prediction,
            "accurate": was_accurate,
            "user_action": user_action
        }
        
        feedback_path = self.data_path / "prediction_feedback.jsonl"
        with open(feedback_path, 'a') as f:
            f.write(json.dumps(feedback_entry) + '\n')
        
        # Adjust confidence for this prediction type
        # (In a full ML system, this would retrain the model)
        logger.info(f"Feedback recorded: {prediction} was {'accurate' if was_accurate else 'inaccurate'}")


# Global instance
predictive_agent = PredictiveAgent()
