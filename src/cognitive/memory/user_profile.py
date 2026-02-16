import json
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
import logging

from src.config import settings

logger = logging.getLogger(__name__)


class UserProfile:
    def __init__(self, profile_dir: Optional[Path] = None, user_id: str = "default"):
        self.profile_dir = profile_dir or (settings.chromadb_path.parent / "profiles")
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        
        self.user_id = user_id
        self.profile_file = self.profile_dir / f"{user_id}.json"
        
        self.profile_data = self._load_profile()
        logger.info(f"UserProfile loaded for user '{user_id}'")
    
    def _load_profile(self) -> Dict:
        if self.profile_file.exists():
            try:
                with open(self.profile_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    logger.debug(f"Loaded profile for '{self.user_id}'")
                    return data
            except Exception as e:
                logger.error(f"Failed to load profile: {e}")
                return self._create_default_profile()
        else:
            return self._create_default_profile()
    
    def _create_default_profile(self) -> Dict:
        return {
            "user_id": self.user_id,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "preferences": {
                "language": "en",
                "voice_gender": settings.voice_gender,
                "response_style": "balanced",
                "verbosity": "normal",
                "timezone": "UTC",
                "theme": "dark"
            },
            "personal_info": {
                "name": None,
                "occupation": None,
                "interests": [],
                "skills": []
            },
            "habits": {
                "active_hours": [],
                "frequent_tasks": [],
                "communication_style": "professional"
            },
            "learned_patterns": {
                "favorite_topics": [],
                "disliked_topics": [],
                "common_queries": [],
                "shortcuts": {}
            },
            "settings": {
                "enable_proactive_suggestions": True,
                "enable_memory_recall": True,
                "privacy_mode": False,
                "data_retention_days": 365
            },
            "statistics": {
                "total_conversations": 0,
                "total_messages": 0,
                "favorite_features": [],
                "last_active": None
            }
        }
    
    def _save_profile(self) -> bool:
        try:
            self.profile_data["updated_at"] = datetime.utcnow().isoformat()
            
            with open(self.profile_file, 'w', encoding='utf-8') as f:
                json.dump(self.profile_data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"Saved profile for '{self.user_id}'")
            return True
        except Exception as e:
            logger.error(f"Failed to save profile: {e}")
            return False
    
    def get(self, key_path: str, default: Any = None) -> Any:
        keys = key_path.split('.')
        value = self.profile_data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any) -> bool:
        keys = key_path.split('.')
        data = self.profile_data
        
        for key in keys[:-1]:
            if key not in data:
                data[key] = {}
            data = data[key]
        
        data[keys[-1]] = value
        return self._save_profile()
    
    def update(self, updates: Dict) -> bool:
        def deep_update(base: Dict, updates: Dict):
            for key, value in updates.items():
                if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                    deep_update(base[key], value)
                else:
                    base[key] = value
        
        deep_update(self.profile_data, updates)
        return self._save_profile()
    
    def get_preference(self, key: str, default: Any = None) -> Any:
        return self.get(f"preferences.{key}", default)
    
    def set_preference(self, key: str, value: Any) -> bool:
        return self.set(f"preferences.{key}", value)
    
    def add_interest(self, interest: str) -> bool:
        interests = self.get("personal_info.interests", [])
        if interest not in interests:
            interests.append(interest)
            return self.set("personal_info.interests", interests)
        return True
    
    def remove_interest(self, interest: str) -> bool:
        interests = self.get("personal_info.interests", [])
        if interest in interests:
            interests.remove(interest)
            return self.set("personal_info.interests", interests)
        return True
    
    def add_skill(self, skill: str) -> bool:
        skills = self.get("personal_info.skills", [])
        if skill not in skills:
            skills.append(skill)
            return self.set("personal_info.skills", skills)
        return True
    
    def learn_pattern(self, pattern_type: str, pattern_value: str, increment: bool = True) -> bool:
        patterns = self.get(f"learned_patterns.{pattern_type}", [])
        
        if isinstance(patterns, list):
            if pattern_value not in patterns:
                patterns.append(pattern_value)
                return self.set(f"learned_patterns.{pattern_type}", patterns)
        elif isinstance(patterns, dict):
            if pattern_value in patterns:
                if increment:
                    patterns[pattern_value] += 1
            else:
                patterns[pattern_value] = 1
            return self.set(f"learned_patterns.{pattern_type}", patterns)
        
        return True
    
    def record_activity(self, activity_type: str, metadata: Optional[Dict] = None) -> bool:
        stats = self.profile_data.get("statistics", {})
        
        if activity_type == "conversation":
            stats["total_conversations"] = stats.get("total_conversations", 0) + 1
        elif activity_type == "message":
            stats["total_messages"] = stats.get("total_messages", 0) + 1
        
        stats["last_active"] = datetime.utcnow().isoformat()
        
        self.profile_data["statistics"] = stats
        return self._save_profile()
    
    def get_personalization_context(self) -> Dict:
        return {
            "name": self.get("personal_info.name"),
            "preferences": self.get("preferences", {}),
            "interests": self.get("personal_info.interests", []),
            "communication_style": self.get("habits.communication_style", "professional"),
            "response_style": self.get("preferences.response_style", "balanced"),
            "verbosity": self.get("preferences.verbosity", "normal")
        }
    
    def export_profile(self) -> Dict:
        return self.profile_data.copy()
    
    def import_profile(self, profile_data: Dict) -> bool:
        try:
            profile_data["user_id"] = self.user_id
            profile_data["updated_at"] = datetime.utcnow().isoformat()
            
            self.profile_data = profile_data
            return self._save_profile()
        except Exception as e:
            logger.error(f"Failed to import profile: {e}")
            return False
    
    def reset_profile(self) -> bool:
        self.profile_data = self._create_default_profile()
        return self._save_profile()
    
    def delete_profile(self) -> bool:
        try:
            if self.profile_file.exists():
                self.profile_file.unlink()
                logger.info(f"Deleted profile for '{self.user_id}'")
            return True
        except Exception as e:
            logger.error(f"Failed to delete profile: {e}")
            return False


class ProfileManager:
    def __init__(self, profile_dir: Optional[Path] = None):
        self.profile_dir = profile_dir or (settings.chromadb_path.parent / "profiles")
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        
        self.profiles = {}
        logger.info("ProfileManager initialized")
    
    def get_profile(self, user_id: str = "default") -> UserProfile:
        if user_id not in self.profiles:
            self.profiles[user_id] = UserProfile(self.profile_dir, user_id)
        return self.profiles[user_id]
    
    def list_profiles(self) -> List[str]:
        profile_files = self.profile_dir.glob("*.json")
        return [f.stem for f in profile_files]
    
    def delete_profile(self, user_id: str) -> bool:
        profile = UserProfile(self.profile_dir, user_id)
        success = profile.delete_profile()
        
        if user_id in self.profiles:
            del self.profiles[user_id]
        
        return success
    
    def export_all_profiles(self) -> Dict[str, Dict]:
        exports = {}
        for user_id in self.list_profiles():
            profile = self.get_profile(user_id)
            exports[user_id] = profile.export_profile()
        return exports
    
    def import_profile(self, user_id: str, profile_data: Dict) -> bool:
        profile = self.get_profile(user_id)
        return profile.import_profile(profile_data)
