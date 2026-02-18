"""
User Learning System - Learn from User Interactions

Tracks user preferences, learns from corrections, adapts suggestions,
and personalizes workflows to improve over time.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
from collections import defaultdict

from src.utils.logger import get_logger

logger = get_logger(__name__)


class UserLearningSystem:
    """
    Learns from user interactions to provide better suggestions over time
    """
    
    def __init__(self, user_id: str = "default"):
        self.user_id = user_id
        self.data_dir = Path(f"data/user_learning/{user_id}")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.preferences_file = self.data_dir / "preferences.json"
        self.interaction_log_file = self.data_dir / "interactions.json"
        self.feedback_file = self.data_dir / "feedback.json"
        
        self.preferences = self._load_preferences()
        logger.info(f"User Learning System initialized for user {user_id}")
    
    def record_suggestion_feedback(
        self,
        suggestion_id: str,
        suggestion_type: str,
        accepted: bool,
        feedback_rating: Optional[int] = None,
        context: Optional[Dict] = None
    ):
        """Record user feedback on a suggestion"""
        try:
            feedback_entry = {
                "suggestion_id": suggestion_id,
                "suggestion_type": suggestion_type,
                "accepted": accepted,
                "rating": feedback_rating,  # 1-5
                "context": context or {},
                "timestamp": datetime.now().isoformat()
            }
            
            # Load existing feedback
            feedback_log = []
            if self.feedback_file.exists():
                feedback_log = json.loads(self.feedback_file.read_text())
            
            feedback_log.append(feedback_entry)
            
            # Keep last 1000 entries
            if len(feedback_log) > 1000:
                feedback_log = feedback_log[-1000:]
            
            self.feedback_file.write_text(json.dumps(feedback_log, indent=2))
            
            # Update preferences based on feedback
            self._update_preferences_from_feedback(feedback_entry)
            
            logger.info(f"Recorded feedback: {suggestion_type} - {'accepted' if accepted else 'rejected'}")
            
        except Exception as e:
            logger.error(f"Failed to record feedback: {e}")
    
    def record_interaction(
        self,
        action: str,
        details: Dict,
        success: bool = True
    ):
        """Record a user interaction"""
        try:
            interaction = {
                "action": action,
                "details": details,
                "success": success,
                "timestamp": datetime.now().isoformat()
            }
            
            # Load existing interactions
            interactions = []
            if self.interaction_log_file.exists():
                interactions = json.loads(self.interaction_log_file.read_text())
            
            interactions.append(interaction)
            
            # Keep last 30 days
            cutoff_date = datetime.now() - timedelta(days=30)
            interactions = [
                i for i in interactions
                if datetime.fromisoformat(i["timestamp"]) > cutoff_date
            ]
            
            self.interaction_log_file.write_text(json.dumps(interactions, indent=2))
            
        except Exception as e:
            logger.error(f"Failed to record interaction: {e}")
    
    def get_time_of_day_preferences(self) -> Dict[str, List[str]]:
        """Get preferred activities by time of day"""
        return self.preferences.get("time_of_day", {
            "morning": ["bug_bounty", "daily_planning"],
            "afternoon": ["youtube_content", "learning"],
            "evening": ["reports", "analytics"],
            "night": ["research", "breaks"]
        })
    
    def get_task_success_rates(self) -> Dict[str, float]:
        """Get success rates for different task types"""
        try:
            if not self.interaction_log_file.exists():
                return {}
            
            interactions = json.loads(self.interaction_log_file.read_text())
            
            # Calculate success rates
            task_stats = defaultdict(lambda: {"total": 0, "success": 0})
            
            for interaction in interactions:
                action = interaction["action"]
                task_stats[action]["total"] += 1
                if interaction.get("success", False):
                    task_stats[action]["success"] += 1
            
            success_rates = {
                task: stats["success"] / stats["total"]
                for task, stats in task_stats.items()
                if stats["total"] > 0
            }
            
            return success_rates
            
        except Exception as e:
            logger.error(f"Failed to calculate success rates: {e}")
            return {}
    
    def get_suggestion_acceptance_rate(self, suggestion_type: str) -> float:
        """Get acceptance rate for a specific suggestion type"""
        try:
            if not self.feedback_file.exists():
                return 0.5  # Default 50%
            
            feedback_log = json.loads(self.feedback_file.read_text())
            
            # Filter for this suggestion type
            relevant_feedback = [
                f for f in feedback_log
                if f["suggestion_type"] == suggestion_type
            ]
            
            if not relevant_feedback:
                return 0.5
            
            accepted_count = sum(1 for f in relevant_feedback if f["accepted"])
            return accepted_count / len(relevant_feedback)
            
        except Exception as e:
            logger.error(f"Failed to get acceptance rate: {e}")
            return 0.5
    
    def get_preferred_suggestion_types(self, top_n: int = 5) -> List[str]:
        """Get most preferred suggestion types"""
        try:
            if not self.feedback_file.exists():
                return ["bug_bounty", "daily_planning", "learning"]
            
            feedback_log = json.loads(self.feedback_file.read_text())
            
            # Count accepted suggestions by type
            type_counts = defaultdict(lambda: {"accepted": 0, "total": 0})
            
            for feedback in feedback_log:
                stype = feedback["suggestion_type"]
                type_counts[stype]["total"] += 1
                if feedback["accepted"]:
                    type_counts[stype]["accepted"] += 1
            
            # Calculate acceptance rates and sort
            type_scores = [
                (stype, stats["accepted"] / stats["total"])
                for stype, stats in type_counts.items()
                if stats["total"] >= 3  # At least 3 samples
            ]
            
            type_scores.sort(key=lambda x: x[1], reverse=True)
            
            return [stype for stype, score in type_scores[:top_n]]
            
        except Exception as e:
            logger.error(f"Failed to get preferred types: {e}")
            return []
    
    def should_suggest(self, suggestion_type: str, context: Dict) -> bool:
        """Decide if a suggestion should be shown based on learned preferences"""
        # Get acceptance rate for this type
        acceptance_rate = self.get_suggestion_acceptance_rate(suggestion_type)
        
        # Don't suggest if historically low acceptance
        if acceptance_rate < 0.2:  # Less than 20% acceptance
            return False
        
        # Check time of day preferences
        current_hour = datetime.now().hour
        if current_hour < 12:
            time_of_day = "morning"
        elif current_hour < 17:
            time_of_day = "afternoon"
        elif current_hour < 21:
            time_of_day = "evening"
        else:
            time_of_day = "night"
        
        preferred_activities = self.get_time_of_day_preferences().get(time_of_day, [])
        
        # Boost if it's a preferred activity for this time
        if suggestion_type in preferred_activities:
            return acceptance_rate > 0.3  # Lower threshold
        
        return acceptance_rate > 0.5  # Default threshold
    
    def _load_preferences(self) -> Dict:
        """Load user preferences"""
        if self.preferences_file.exists():
            try:
                return json.loads(self.preferences_file.read_text())
            except Exception as e:
                logger.error(f"Failed to load preferences: {e}")
        return self._get_default_preferences()
    
    def _save_preferences(self):
        """Save user preferences"""
        try:
            self.preferences_file.write_text(json.dumps(self.preferences, indent=2))
        except Exception as e:
            logger.error(f"Failed to save preferences: {e}")
    
    def _update_preferences_from_feedback(self, feedback: Dict):
        """Update preferences based on feedback"""
        try:
            suggestion_type = feedback["suggestion_type"]
            accepted = feedback["accepted"]
            
            # Update time of day preferences
            current_hour = datetime.now().hour
            if current_hour < 12:
                time_of_day = "morning"
            elif current_hour < 17:
                time_of_day = "afternoon"
            elif current_hour < 21:
                time_of_day = "evening"
            else:
                time_of_day = "night"
            
            if "time_of_day" not in self.preferences:
                self.preferences["time_of_day"] = {}
            
            if accepted:
                # Add to preferred activities for this time
                if time_of_day not in self.preferences["time_of_day"]:
                    self.preferences["time_of_day"][time_of_day] = []
                
                if suggestion_type not in self.preferences["time_of_day"][time_of_day]:
                    self.preferences["time_of_day"][time_of_day].append(suggestion_type)
            
            self._save_preferences()
            
        except Exception as e:
            logger.error(f"Failed to update preferences: {e}")
    
    def _get_default_preferences(self) -> Dict:
        """Get default preferences"""
        return {
            "time_of_day": {
                "morning": ["bug_bounty", "daily_planning"],
                "afternoon": ["youtube_content", "learning"],
                "evening": ["reports", "analytics"],
                "night": ["research", "breaks"]
            },
            "notification_frequency": "medium",  # low, medium, high
            "personality_mode": "friendly"
        }
    
    def get_learning_insights(self) -> Dict:
        """Get insights about learned user preferences"""
        return {
            "preferred_suggestion_types": self.get_preferred_suggestion_types(),
            "task_success_rates": self.get_task_success_rates(),
            "time_of_day_preferences": self.get_time_of_day_preferences(),
            "total_interactions": len(json.loads(self.interaction_log_file.read_text())) if self.interaction_log_file.exists() else 0,
            "total_feedback": len(json.loads(self.feedback_file.read_text())) if self.feedback_file.exists() else 0
        }
