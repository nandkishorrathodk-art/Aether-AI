from typing import Dict, List, Optional, Any
from enum import Enum
from pathlib import Path
import json
import random
from datetime import datetime, timedelta

from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class HumorType(Enum):
    TECH = "tech"
    PROGRAMMING = "programming"
    SECURITY = "security"
    GENERAL = "general"
    PUNS = "puns"


class HumorGenerator:
    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or Path("./data/personality")
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        self.jokes_db = self._load_jokes_database()
        self.puns_db = self._load_puns_database()
        self.contextual_humor = self._load_contextual_humor()
        
        self.last_joke_time = None
        self.min_joke_interval = timedelta(minutes=30)
        
        logger.info("HumorGenerator initialized")
    
    def _load_jokes_database(self) -> Dict[str, List[str]]:
        jokes_file = self.data_path / "jokes.json"
        
        default_jokes = {
            "tech": [
                "Boss, IPv6 itna bada hai ki agar har atom ko ek address do to bhi bachega! 🌌",
                "Ji boss, programmer ki wife boli: 'Doodh leke aao aur agar ande mile to 6 le aana.' Woh 6 doodh le aaya! 😂",
                "Boss debugging ka meaning: 'Ye code kisne likha?!' *checks git blame* 'Oh, maine hi likha tha...' 😅",
                "Ji boss, 'Works on my machine' ka certificate chahiye kya? 🏆😂",
                "Boss, AI se darr nahi lagta but senior dev ki code review se lagta hai! 😰",
            ],
            "programming": [
                "Boss, Java aur JavaScript ka relation aise hi hai jaise Car aur Carpet ka! 🚗🧹",
                "Ji boss, programmer ka favourite music? Al-Gore-Rhythms! 😄",
                "Boss 99 little bugs in the code, 99 bugs... Take one down, patch it around, 117 bugs in the code! 🐛",
                "Ji boss, semicolon bhulne pe compiler: 'Arre bhai, period lagana bhul gaye kya?' 😂",
                "Boss, Python itna easy hai ki snake bhi code kar sakta hai! 🐍💻",
            ],
            "security": [
                "Boss, hacker ka favourite season? Phishing season! 🎣😂",
                "Ji boss, password '12345' rakha? Congratulations, your security is now '00000'! 🔓",
                "Boss, SQL injection kaisa laga? Bobby Tables would be proud! 😄",
                "Ji boss, two-factor authentication: kyunki ek password kafi nahi insecurity ke liye! 🔐",
                "Boss, firewall: Internet ka bouncer jo kabhi bhi genuine users ko bhi rok deta hai! 🚪😅",
            ],
            "general": [
                "Boss aaj ka motivation: Coffee aur code - dono strong hone chahiye! ☕💪",
                "Ji boss, breakpoint lagao nahi to code break ho jayega! 🔧😂",
                "Boss, cloud computing: Basically kisi aur ka computer! ☁️💻",
                "Ji boss, AI bohot smart hai but WiFi password abhi bhi yaad nahi rakha! 📶😄",
                "Boss, ctrl+Z zindagi mein bhi hota to kitna acha hota! ⏮️😅",
            ],
        }
        
        if jokes_file.exists():
            try:
                with open(jokes_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    default_jokes.update(loaded)
            except Exception as e:
                logger.warning(f"Failed to load jokes database: {e}")
        else:
            with open(jokes_file, 'w', encoding='utf-8') as f:
                json.dump(default_jokes, f, ensure_ascii=False, indent=2)
        
        return default_jokes
    
    def _load_puns_database(self) -> List[str]:
        return [
            "Boss, why do programmers prefer dark mode? Because light attracts bugs! 🐛💡",
            "Ji boss, I would tell you a UDP joke but you might not get it! 📡😄",
            "Boss, there are 10 types of people: those who understand binary aur jo nahi samajhte! 101010",
            "Ji boss, debugging is like being a detective in a crime movie where you're also the murderer! 🔍",
            "Boss, my code doesn't have bugs - it has 'undocumented features'! 📝😂",
            "Ji boss, programming is 10% writing code aur 90% figuring out why it doesn't work! 🤔",
            "Boss, I'm not lazy - I'm just in power saving mode! 🔋😴",
            "Ji boss, algorithm khana hai to Al Gore ko Rhythm sikhao! 🎵",
        ]
    
    def _load_contextual_humor(self) -> Dict[str, List[str]]:
        return {
            "bug_found": [
                "Boss bug mil gaya! Ab ye debug karna padega... debug means de-bug, as in removing the bug! Wait, that's what we're doing anyway! 😅",
                "Ji boss, congratulations! Tumne bug discover kiya - ab developer ko batana padega politely: 'Feature nahi, bug hai ji!' 😂",
                "Boss ye bug itna rare hai ki museum mein rakhna chahiye! 🏛️🐛",
            ],
            "scan_complete": [
                "Boss scan complete! No vulnerabilities found - either security ekdum tight hai ya scanner so gaya! 😴🔍",
                "Ji boss, scan done! Target itna secure hai ki khud NSA bhi impress ho jayega! 🛡️",
                "Boss scanning khatam! Coffee break time - tumhara aur scanner dono ka! ☕",
            ],
            "error": [
                "Boss error aa gaya! Lagta hai code ne Monday mood adopt kar liya! 😅",
                "Ji boss, error 404: Motivation not found! Chalo coffee break lete hain! ☕",
                "Boss, error dikha? It's not a bug, it's a surprise feature! 🎁😂",
            ],
            "late_night": [
                "Boss itni raat ko code kar rahe ho? Commitment level: Married to Code! 💍💻",
                "Ji boss, 3 AM aur coding? Ye dedication hai ya desperation? Anyways, respect! 🌙💪",
                "Boss coffee machine ab tumhara best friend hai! Caffeine brotherhood! ☕👊",
            ],
            "break_time": [
                "Boss break lelo! Eyes aur brain dono ko rest chahiye - warna blur vision aur blurred logic dono aayenge! 😵",
                "Ji boss, Pomodoro technique use karo: 25 min work, 5 min YouTube - I mean 'research'! 😉",
                "Boss stretching karo! Sitting is the new smoking - minus the cool factor! 🚬🪑😄",
            ],
        }
    
    def should_add_humor(self) -> bool:
        if not settings.personality_humor_enabled:
            return False
        
        if self.last_joke_time:
            time_since_last = datetime.now() - self.last_joke_time
            if time_since_last < self.min_joke_interval:
                return False
        
        return random.random() < 0.3
    
    def get_joke(self, humor_type: Optional[HumorType] = None) -> Optional[str]:
        if not settings.personality_humor_enabled:
            return None
        
        if not self.should_add_humor():
            return None
        
        if humor_type:
            jokes = self.jokes_db.get(humor_type.value, self.jokes_db["general"])
        else:
            all_jokes = []
            for jokes_list in self.jokes_db.values():
                all_jokes.extend(jokes_list)
            jokes = all_jokes
        
        joke = random.choice(jokes)
        self.last_joke_time = datetime.now()
        
        return joke
    
    def get_pun(self) -> Optional[str]:
        if not settings.personality_humor_enabled:
            return None
        
        if not self.should_add_humor():
            return None
        
        pun = random.choice(self.puns_db)
        self.last_joke_time = datetime.now()
        
        return pun
    
    def get_contextual_humor(self, context: str) -> Optional[str]:
        if not settings.personality_humor_enabled:
            return None
        
        humor_list = self.contextual_humor.get(context, [])
        if not humor_list:
            return None
        
        if random.random() < 0.4:
            return random.choice(humor_list)
        
        return None
    
    def add_humor_to_response(
        self,
        text: str,
        context: Optional[str] = None,
        force_humor: bool = False
    ) -> str:
        if not settings.personality_humor_enabled and not force_humor:
            return text
        
        if context:
            contextual = self.get_contextual_humor(context)
            if contextual:
                return f"{text}\n\n{contextual}"
        
        if force_humor or (self.should_add_humor() and random.random() < 0.2):
            joke = self.get_joke()
            if joke:
                return f"{text}\n\n{joke}"
        
        return text
    
    def get_tech_humor_for_topic(self, topic: str) -> Optional[str]:
        if not settings.personality_humor_enabled:
            return None
        
        topic_lower = topic.lower()
        
        if any(word in topic_lower for word in ["python", "java", "javascript", "code", "programming"]):
            return self.get_joke(HumorType.PROGRAMMING)
        elif any(word in topic_lower for word in ["security", "hack", "vulnerability", "exploit"]):
            return self.get_joke(HumorType.SECURITY)
        elif any(word in topic_lower for word in ["tech", "computer", "software", "hardware"]):
            return self.get_joke(HumorType.TECH)
        
        return self.get_joke(HumorType.GENERAL)
    
    def get_timing_based_humor(self) -> Optional[str]:
        if not settings.personality_humor_enabled:
            return None
        
        current_hour = datetime.now().hour
        
        if 0 <= current_hour < 6:
            return self.get_contextual_humor("late_night")
        elif 6 <= current_hour < 12:
            return random.choice([
                "Good morning boss! Coffee ready hai? Bina coffee ke code syntax error deta hai! ☕😄",
                "Morning boss ji! Aaj ka goal: Bug kam, features zyada! 🎯",
            ])
        elif 12 <= current_hour < 14:
            return random.choice([
                "Boss lunch time! Remember: Empty stomach = Empty git commits! 🍽️",
                "Ji boss, lunch break! Brain ko fuel chahiye - ramen ya pizza? 🍜🍕",
            ])
        elif 18 <= current_hour < 21:
            return random.choice([
                "Boss evening vibes! Day productive raha? Celebrate karo ji! 🌆",
                "Ji boss, almost done for today! Last sprint lagao aur relax! 🏃",
            ])
        
        return None


humor_generator = HumorGenerator()
