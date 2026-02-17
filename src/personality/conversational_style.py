from typing import Dict, List, Optional, Any
from enum import Enum
import random
import re
from pathlib import Path
import json

from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ToneType(Enum):
    FRIENDLY = "friendly"
    PROFESSIONAL = "professional"
    CASUAL = "casual"
    MOTIVATIONAL = "motivational"
    HUMOROUS = "humorous"


class ConversationalStyle:
    def __init__(self, data_path: Optional[Path] = None):
        self.data_path = data_path or Path("./data/personality")
        self.data_path.mkdir(parents=True, exist_ok=True)
        
        self.hindi_english_phrases = self._load_hindi_english_phrases()
        self.contextual_responses = self._load_contextual_responses()
        self.emoji_map = self._load_emoji_map()
        
        logger.info("ConversationalStyle initialized")
    
    def _load_hindi_english_phrases(self) -> Dict[str, List[str]]:
        phrases_file = self.data_path / "hindi_english_phrases.json"
        
        default_phrases = {
            "greetings": [
                "Ji boss!",
                "Haan ji, bolo!",
                "Ji, kya kaam hai?",
                "Yes boss, ready hoon!",
                "Bilkul ji, batao!",
                "Haan boss, sunao!",
                "Ji, all set!",
                "Ready hoon ji!",
            ],
            "confirmations": [
                "Bilkul!",
                "Haan ji!",
                "Sure boss!",
                "Pakka!",
                "Done ji!",
                "Perfect!",
                "Theek hai ji!",
                "Got it boss!",
                "Samajh gaya!",
                "Roger that ji!",
            ],
            "questions": [
                "Boss aaj kya plan hai?",
                "Kya chahiye ji?",
                "Kuch aur help chahiye?",
                "Aur kya karna hai boss?",
                "Next kya boss?",
                "Sab theek hai na ji?",
                "Kaise lag raha hai boss?",
                "Koi problem to nahi?",
            ],
            "encouragements": [
                "Tum best ho boss!",
                "Ek dum zabardast!",
                "Bohot badhiya ji!",
                "You're doing great boss!",
                "Mast kaam kar rahe ho!",
                "Keep it up ji!",
                "Ekdum top level!",
                "Outstanding boss!",
            ],
            "transitions": [
                "Chalo ji",
                "Theek hai boss",
                "Acha",
                "Okay ji",
                "Sahi hai",
                "Cool boss",
                "Nice",
                "Perfect ji",
            ],
            "errors": [
                "Sorry boss, thoda issue aa gaya",
                "Oops ji, problem hai",
                "Ek minute boss, fix karta hoon",
                "My bad ji!",
                "Galti ho gayi boss",
                "Let me fix this ji",
                "Thoda rukna boss",
            ],
            "excitement": [
                "Arre waah boss!",
                "Zabardast ji!",
                "Ekdum mast!",
                "Wow boss, superb!",
                "Bohot hard ji!",
                "Fire hai ye to!",
                "Dhamaal boss!",
                "Top-notch ji!",
            ],
        }
        
        if phrases_file.exists():
            try:
                with open(phrases_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    default_phrases.update(loaded)
            except Exception as e:
                logger.warning(f"Failed to load Hindi-English phrases: {e}")
        else:
            with open(phrases_file, 'w', encoding='utf-8') as f:
                json.dump(default_phrases, f, ensure_ascii=False, indent=2)
        
        return default_phrases
    
    def _load_contextual_responses(self) -> Dict[str, List[str]]:
        responses_file = self.data_path / "contextual_responses.json"
        
        default_responses = {
            "bug_found": [
                "Arre boss, bug mil gaya! {severity} level ka hai ji. Kya karna hai?",
                "Boss dekho! {severity} vulnerability detect hui hai! Report banau?",
                "Ji boss, jackpot! {severity} bug hai ye - ${estimate} tak mil sakta hai!",
            ],
            "task_complete": [
                "Ho gaya boss! {task_name} complete hai ji. Next kya karein?",
                "Done ji! {task_name} finish ho gaya. Kaisa laga boss?",
                "Boss {task_name} ready hai! Aur kuch chahiye?",
            ],
            "scan_start": [
                "Boss scanning shuru kar diya! {target} pe focus hai ji.",
                "Ji, scan chal raha hai {target} ka. Updates deta rahunga!",
                "Chalo boss, {target} ko scan karte hain. Kuch milega zaroor!",
            ],
            "daily_plan": [
                "Boss aaj ka plan ready hai! {tasks_count} tasks hai ji. Start karein?",
                "Ji boss, aaj ye karein: {highlights}. Kya lagta hai?",
                "Good morning boss! Aaj ka schedule: {highlights}. Ready ho?",
            ],
            "motivation_low": [
                "Boss thoda break lo ji. Fresh mind se kaafi better results aate hain!",
                "Arre boss, pressure mat lo. Tum bohot acha kar rahe ho!",
                "Ji boss, step by step chalo. Success zaroor milegi!",
            ],
            "achievement": [
                "Boss congratulations! {achievement} complete kiya - ekdum mast!",
                "Arre waah boss! {achievement} ho gaya ji. Celebrate karo!",
                "Zabardast boss! {achievement} - tum legend ho ji!",
            ],
        }
        
        if responses_file.exists():
            try:
                with open(responses_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    default_responses.update(loaded)
            except Exception as e:
                logger.warning(f"Failed to load contextual responses: {e}")
        else:
            with open(responses_file, 'w', encoding='utf-8') as f:
                json.dump(default_responses, f, ensure_ascii=False, indent=2)
        
        return default_responses
    
    def _load_emoji_map(self) -> Dict[str, List[str]]:
        return {
            "positive": ["🔥", "💪", "🎯", "✨", "🚀", "⚡", "💯", "🎉", "🌟", "👊"],
            "thinking": ["🤔", "💭", "🧠", "🔍", "📊", "🎓"],
            "working": ["⚙️", "🔧", "💻", "📝", "🛠️", "⏳"],
            "success": ["✅", "🎊", "🏆", "🥇", "🎁", "💰"],
            "warning": ["⚠️", "🚨", "⏰", "🔔"],
            "error": ["❌", "😅", "🙏", "😬"],
            "security": ["🛡️", "🔒", "🔐", "🕵️", "🐛", "💣"],
            "money": ["💰", "💵", "💸", "🤑", "📈"],
            "time": ["⏰", "⏳", "📅", "🕐"],
        }
    
    def get_greeting(self) -> str:
        if not settings.personality_enable_hindi_english:
            return "Hello!"
        return random.choice(self.hindi_english_phrases.get("greetings", ["Hello!"]))
    
    def get_confirmation(self) -> str:
        if not settings.personality_enable_hindi_english:
            return "Sure!"
        return random.choice(self.hindi_english_phrases.get("confirmations", ["Sure!"]))
    
    def get_contextual_response(self, context_type: str, variables: Optional[Dict[str, Any]] = None) -> str:
        if not settings.personality_enable_hindi_english:
            return ""
        
        templates = self.contextual_responses.get(context_type, [])
        if not templates:
            return ""
        
        template = random.choice(templates)
        
        if variables:
            try:
                return template.format(**variables)
            except KeyError as e:
                logger.warning(f"Missing variable in template: {e}")
                return template
        
        return template
    
    def add_emoji(self, text: str, context: str = "positive") -> str:
        if not settings.personality_emoji_enabled:
            return text
        
        emojis = self.emoji_map.get(context, self.emoji_map["positive"])
        emoji = random.choice(emojis)
        
        if random.random() < 0.3:
            return f"{emoji} {text}"
        elif random.random() < 0.6:
            return f"{text} {emoji}"
        else:
            return text


class ResponseEnhancer:
    def __init__(self):
        self.style = ConversationalStyle()
        self.tone_patterns = self._load_tone_patterns()
        logger.info("ResponseEnhancer initialized")
    
    def _load_tone_patterns(self) -> Dict[ToneType, Dict[str, Any]]:
        return {
            ToneType.FRIENDLY: {
                "prefixes": ["", "So ", "Well, "],
                "suffixes": ["!", ".", " 😊"],
                "transitions": ["Also,", "Plus,", "And hey,", "Oh and,"],
            },
            ToneType.PROFESSIONAL: {
                "prefixes": ["", "I would suggest ", "My recommendation is "],
                "suffixes": [".", "."],
                "transitions": ["Additionally,", "Furthermore,", "Moreover,", "Also,"],
            },
            ToneType.CASUAL: {
                "prefixes": ["Hey, ", "Yo, ", "So ", ""],
                "suffixes": ["!", ".", " lol", " 😄"],
                "transitions": ["Btw,", "Also,", "Oh and,", "Plus,"],
            },
            ToneType.MOTIVATIONAL: {
                "prefixes": ["You got this! ", "Great job! ", "Keep it up! ", ""],
                "suffixes": ["!", " 💪", " 🔥"],
                "transitions": ["And remember,", "Keep in mind,", "Also,", "Plus,"],
            },
            ToneType.HUMOROUS: {
                "prefixes": ["Haha, ", "Lol, ", "Funny thing - ", ""],
                "suffixes": ["!", " 😂", " 😄", " 🤣"],
                "transitions": ["Also funny -", "Oh and,", "Plus,", "Btw,"],
            },
        }
    
    def enhance_response(
        self,
        text: str,
        tone: Optional[ToneType] = None,
        add_personality: bool = True,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        if not add_personality:
            return text
        
        tone = tone or ToneType(settings.personality_mode)
        
        enhanced = text
        
        if settings.personality_enable_hindi_english:
            enhanced = self._mix_hindi_english(enhanced, tone)
        
        if settings.personality_emoji_enabled:
            emoji_context = self._detect_emoji_context(enhanced, context)
            enhanced = self.style.add_emoji(enhanced, emoji_context)
        
        enhanced = self._apply_tone(enhanced, tone)
        
        return enhanced
    
    def _mix_hindi_english(self, text: str, tone: ToneType) -> str:
        mixing_probability = {
            ToneType.FRIENDLY: 0.4,
            ToneType.CASUAL: 0.6,
            ToneType.PROFESSIONAL: 0.1,
            ToneType.MOTIVATIONAL: 0.3,
            ToneType.HUMOROUS: 0.5,
        }
        
        prob = mixing_probability.get(tone, 0.3)
        
        if random.random() > prob:
            return text
        
        replacements = {
            r'\byes\b': 'haan ji',
            r'\bno\b': 'nahi ji',
            r'\bokay\b': 'theek hai',
            r'\bok\b': 'okay ji',
            r'\bsure\b': 'bilkul',
            r'\bgreat\b': 'zabardast',
            r'\bgood\b': 'acha',
            r'\bbad\b': 'bura',
            r'\bsorry\b': 'sorry ji',
            r'\bthanks\b': 'shukriya',
            r'\bwait\b': 'ruko',
            r'\blet\'s start\b': 'chalo shuru karte hain',
            r'\blet\'s go\b': 'chalo',
        }
        
        for pattern, replacement in replacements.items():
            if random.random() < 0.3:
                text = re.sub(pattern, replacement, text, flags=re.IGNORECASE, count=1)
        
        return text
    
    def _detect_emoji_context(self, text: str, context: Optional[Dict[str, Any]]) -> str:
        text_lower = text.lower()
        
        if context:
            if context.get("bug_found"):
                return "security"
            if context.get("money_related"):
                return "money"
            if context.get("success"):
                return "success"
            if context.get("error"):
                return "error"
        
        if any(word in text_lower for word in ["bug", "vulnerability", "exploit", "security"]):
            return "security"
        if any(word in text_lower for word in ["success", "done", "complete", "finished"]):
            return "success"
        if any(word in text_lower for word in ["error", "failed", "problem", "issue"]):
            return "error"
        if any(word in text_lower for word in ["money", "payment", "bounty", "reward", "earnings"]):
            return "money"
        if any(word in text_lower for word in ["working", "processing", "scanning", "analyzing"]):
            return "working"
        if any(word in text_lower for word in ["think", "analyze", "consider", "evaluate"]):
            return "thinking"
        if any(word in text_lower for word in ["warning", "caution", "careful", "alert"]):
            return "warning"
        
        return "positive"
    
    def _apply_tone(self, text: str, tone: ToneType) -> str:
        patterns = self.tone_patterns.get(tone)
        if not patterns or not settings.personality_enable_hindi_english:
            return text
        
        if random.random() < 0.2 and patterns["prefixes"]:
            prefix = random.choice([p for p in patterns["prefixes"] if p])
            if prefix and not text.startswith(prefix):
                text = prefix + text
        
        return text
    
    def enhance_with_context(
        self,
        text: str,
        context_type: str,
        variables: Optional[Dict[str, Any]] = None
    ) -> str:
        contextual = self.style.get_contextual_response(context_type, variables)
        
        if contextual:
            return f"{contextual}\n\n{text}"
        
        return text


response_enhancer = ResponseEnhancer()
