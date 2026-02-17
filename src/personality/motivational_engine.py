from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import json
import random

from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class MoodLevel(Enum):
    VERY_LOW = "very_low"
    LOW = "low"
    NEUTRAL = "neutral"
    HIGH = "high"
    VERY_HIGH = "very_high"


class AchievementType(Enum):
    BUG_FOUND = "bug_found"
    TASK_COMPLETED = "task_completed"
    GOAL_REACHED = "goal_reached"
    STREAK_MAINTAINED = "streak_maintained"
    MILESTONE_REACHED = "milestone_reached"
    SKILL_IMPROVED = "skill_improved"


class MotivationalEngine:
    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or Path("./data/personality")
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        self.progress_file = self.data_path / "user_progress.json"
        self.achievements_file = self.data_path / "achievements.json"
        
        self.user_progress = self._load_user_progress()
        self.achievements = self._load_achievements()
        
        self.encouragement_messages = self._load_encouragement_messages()
        self.celebration_messages = self._load_celebration_messages()
        self.support_messages = self._load_support_messages()
        
        logger.info("MotivationalEngine initialized")
    
    def _load_user_progress(self) -> Dict[str, Any]:
        if self.progress_file.exists():
            try:
                with open(self.progress_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load user progress: {e}")
        
        return {
            "total_tasks": 0,
            "completed_tasks": 0,
            "bugs_found": 0,
            "streak_days": 0,
            "last_active": datetime.now().isoformat(),
            "mood_history": [],
            "failures": 0,
            "successes": 0,
        }
    
    def _save_user_progress(self):
        try:
            with open(self.progress_file, 'w', encoding='utf-8') as f:
                json.dump(self.user_progress, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save user progress: {e}")
    
    def _load_achievements(self) -> List[Dict[str, Any]]:
        if self.achievements_file.exists():
            try:
                with open(self.achievements_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load achievements: {e}")
        
        return []
    
    def _save_achievements(self):
        try:
            with open(self.achievements_file, 'w', encoding='utf-8') as f:
                json.dump(self.achievements, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save achievements: {e}")
    
    def _load_encouragement_messages(self) -> Dict[str, List[str]]:
        messages_file = self.data_path / "encouragement_messages.json"
        
        default_messages = {
            "general": [
                "Boss, tum bohot acha kar rahe ho! Keep pushing! 💪",
                "Ji boss, har kadam important hai. You're doing great!",
                "Boss, remember - consistency beats perfection! Keep going ji! 🔥",
                "Arre boss, thoda patience rakho. Success zaroor milegi! ✨",
                "Ji boss, progress slow lag raha but you're moving forward! Proud of you! 🌟",
            ],
            "task_progress": [
                "Boss, {completed}/{total} tasks ho gaye! Mast pace hai ji! 📊",
                "Dekho boss, {completed} tasks done already! You're crushing it! 💯",
                "Ji boss, {tasks_remaining} aur bachhe hain - almost there! 🎯",
                "Boss halfway ho gaye! Second half mein aur tez chalenge ji! ⚡",
            ],
            "before_break": [
                "Boss, break lelo ji. Fresh mind se better results aayenge! ☕",
                "Ji boss, thoda stretch karo. Eyes rest chahiye! 👀",
                "Boss, 5-minute walk karo ji. Circulation improve hoga! 🚶",
                "Arre boss, paani piyo aur thoda relax. You deserve it ji! 💧",
            ],
            "morning": [
                "Good morning boss! Aaj ka din ekdum zabardast jayega ji! 🌅",
                "Namaskar boss! Ready ho? Let's make today awesome! 🔥",
                "Morning boss ji! Coffee leke shuru karte hain? ☕",
                "Boss aaj ka plan hai - let's crush it together ji! 💪",
            ],
            "evening": [
                "Boss aaj ka kaam bohot acha tha! Rest karo ji. 🌙",
                "Ji boss, productive day raha! Kal aur better hoga! ✨",
                "Boss, well done today! Recharge karo for tomorrow ji! 🔋",
                "Aaj ke achievements note kar liye boss? Celebrate karo! 🎉",
            ],
        }
        
        if messages_file.exists():
            try:
                with open(messages_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    default_messages.update(loaded)
            except Exception as e:
                logger.warning(f"Failed to load encouragement messages: {e}")
        else:
            with open(messages_file, 'w', encoding='utf-8') as f:
                json.dump(default_messages, f, ensure_ascii=False, indent=2)
        
        return default_messages
    
    def _load_celebration_messages(self) -> Dict[str, List[str]]:
        return {
            "bug_found": [
                "Arre waah boss! {severity} bug mila - this is huge ji! 🐛💰",
                "Boss zabardast! ${estimated_bounty} ka bug hai ye! Celebrate karo ji! 🎉",
                "Ji boss, legend move! {vulnerability_type} vulnerability - bohot rare hai! 🏆",
                "Boss you're on fire! Ye bug kaafi valuable hai ji! 🔥💯",
            ],
            "task_complete": [
                "Boom boss! {task_name} done and dusted ji! ✅",
                "Ji boss, excellent! {task_name} completed perfectly! 🌟",
                "Boss mast kaam kiya! {task_name} ekdum top level ji! 💪",
                "Arre boss fabulous! {task_name} finished - next level hai ye! 🚀",
            ],
            "goal_reached": [
                "Boss GOAL ACHIEVED! {goal_name} complete ho gaya ji! 🎯🎉",
                "Ji boss CONGRATULATIONS! {goal_name} - you made it! 🏆",
                "BOSS LEGENDARY! {goal_name} done - bohot hard hai ye ji! 💯🔥",
                "Arre WAAH BOSS! {goal_name} conquered! You're unstoppable ji! ⚡",
            ],
            "streak": [
                "Boss {days} days streak chal raha! Consistency ekdum mast hai ji! 📈",
                "Ji boss, {days} days straight! You're building momentum! 🔥",
                "Boss {days}-day streak - this is discipline level 1000 ji! 💪",
            ],
            "milestone": [
                "BOSS MILESTONE ALERT! {milestone_name} reached! 🎊🎉",
                "Ji boss HUGE! {milestone_name} complete - proud moment hai ye! 🏅",
                "BOSS {milestone_name} achieved! This deserves a celebration ji! 🥇",
            ],
        }
    
    def _load_support_messages(self) -> Dict[str, List[str]]:
        return {
            "failure": [
                "Boss it's okay ji! Failures se hi learning aati hai. Try again! 💪",
                "Ji boss, har expert pehle beginner tha. Keep trying! 🌟",
                "Boss galti normal hai ji. Next time better strategy try karte hain! 🎯",
                "Arre boss, failure = First Attempt In Learning ji! You got this! 🔥",
                "Ji boss, Edison 1000 times fail hue light bulb banane mein. You're doing great! 💡",
            ],
            "stuck": [
                "Boss stuck lag raha? Chalo break lete hain aur fresh perspective laate hain ji! ☕",
                "Ji boss, sometimes stepping back helps. Kya main kuch suggest karun? 🤔",
                "Boss different approach try karte hain? Main help kar sakta hoon ji! 🔧",
                "Arre boss, har problem ka solution hota hai. Together dhundhte hain! 🔍",
            ],
            "low_mood": [
                "Boss sab theek hai? Remember why you started ji. You're amazing! ✨",
                "Ji boss, tough times temporary hain. Your strength is permanent! 💪",
                "Boss, take a deep breath. Ek step at a time chalte hain ji! 🌈",
                "Arre boss, bad days make good days better. Tomorrow pakka better hoga ji! 🌅",
            ],
            "error": [
                "Boss error aa gayi but no worries! Main fix karta hoon ji! 🔧",
                "Ji boss, technical glitch hai - happens to everyone. Resolving! ⚙️",
                "Boss sorry ji! Let me handle this error. You focus on the big picture! 🛠️",
            ],
        }
    
    def get_encouragement(
        self,
        context: str = "general",
        variables: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        if not settings.personality_motivational_enabled:
            return None
        
        messages = self.encouragement_messages.get(context, self.encouragement_messages["general"])
        message = random.choice(messages)
        
        if variables:
            try:
                return message.format(**variables)
            except KeyError:
                return message
        
        return message
    
    def celebrate_achievement(
        self,
        achievement_type: AchievementType,
        details: Dict[str, Any]
    ) -> str:
        if not settings.personality_motivational_enabled:
            return "Congratulations!"
        
        achievement = {
            "type": achievement_type.value,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        }
        self.achievements.append(achievement)
        self._save_achievements()
        
        if achievement_type == AchievementType.BUG_FOUND:
            self.user_progress["bugs_found"] += 1
            self.user_progress["successes"] += 1
            messages = self.celebration_messages["bug_found"]
        elif achievement_type == AchievementType.TASK_COMPLETED:
            self.user_progress["completed_tasks"] += 1
            self.user_progress["successes"] += 1
            messages = self.celebration_messages["task_complete"]
        elif achievement_type == AchievementType.GOAL_REACHED:
            self.user_progress["successes"] += 1
            messages = self.celebration_messages["goal_reached"]
        elif achievement_type == AchievementType.STREAK_MAINTAINED:
            messages = self.celebration_messages["streak"]
        elif achievement_type == AchievementType.MILESTONE_REACHED:
            messages = self.celebration_messages["milestone"]
        else:
            messages = ["Great work boss! 🎉"]
        
        self._save_user_progress()
        
        message = random.choice(messages)
        try:
            return message.format(**details)
        except KeyError:
            return message
    
    def provide_support(
        self,
        situation: str = "failure",
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        if not settings.personality_motivational_enabled:
            return "Keep trying!"
        
        self.user_progress["failures"] += 1
        self._save_user_progress()
        
        messages = self.support_messages.get(situation, self.support_messages["failure"])
        message = random.choice(messages)
        
        if details:
            try:
                return message.format(**details)
            except KeyError:
                return message
        
        return message
    
    def update_streak(self) -> int:
        last_active = datetime.fromisoformat(self.user_progress.get("last_active", datetime.now().isoformat()))
        now = datetime.now()
        
        days_diff = (now.date() - last_active.date()).days
        
        if days_diff == 0:
            pass
        elif days_diff == 1:
            self.user_progress["streak_days"] += 1
        else:
            self.user_progress["streak_days"] = 1
        
        self.user_progress["last_active"] = now.isoformat()
        self._save_user_progress()
        
        return self.user_progress["streak_days"]
    
    def track_mood(self, mood: MoodLevel) -> None:
        mood_entry = {
            "level": mood.value,
            "timestamp": datetime.now().isoformat(),
        }
        
        self.user_progress.setdefault("mood_history", []).append(mood_entry)
        
        if len(self.user_progress["mood_history"]) > 100:
            self.user_progress["mood_history"] = self.user_progress["mood_history"][-100:]
        
        self._save_user_progress()
    
    def get_mood_based_message(self, mood: MoodLevel) -> Optional[str]:
        if not settings.personality_motivational_enabled:
            return None
        
        if mood in [MoodLevel.VERY_LOW, MoodLevel.LOW]:
            return self.provide_support("low_mood")
        elif mood == MoodLevel.VERY_HIGH:
            return random.choice([
                "Boss aaj ekdum energetic ho! Let's make the most of it ji! 🔥",
                "Ji boss, high energy dekh ke maza aa gaya! Let's go! 💪",
                "Boss mood ekdum top pe hai! Perfect time for tough tasks ji! ⚡",
            ])
        
        return None
    
    def get_progress_summary(self) -> Dict[str, Any]:
        success_rate = 0
        total_attempts = self.user_progress["successes"] + self.user_progress["failures"]
        if total_attempts > 0:
            success_rate = (self.user_progress["successes"] / total_attempts) * 100
        
        return {
            "total_tasks": self.user_progress["total_tasks"],
            "completed_tasks": self.user_progress["completed_tasks"],
            "bugs_found": self.user_progress["bugs_found"],
            "streak_days": self.user_progress["streak_days"],
            "success_rate": round(success_rate, 2),
            "total_achievements": len(self.achievements),
            "recent_achievements": self.achievements[-5:] if self.achievements else [],
        }


motivational_engine = MotivationalEngine()
