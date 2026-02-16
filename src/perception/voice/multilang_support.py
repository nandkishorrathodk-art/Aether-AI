"""Multi-language support for global voice interaction."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum


class LanguageCode(Enum):
    """Supported language codes (ISO 639-1)."""
    ENGLISH = "en"
    SPANISH = "es"
    FRENCH = "fr"
    GERMAN = "de"
    ITALIAN = "it"
    PORTUGUESE = "pt"
    RUSSIAN = "ru"
    CHINESE = "zh"
    JAPANESE = "ja"
    KOREAN = "ko"
    ARABIC = "ar"
    HINDI = "hi"
    BENGALI = "bn"
    PUNJABI = "pa"
    TELUGU = "te"
    MARATHI = "mr"
    TAMIL = "ta"
    URDU = "ur"
    GUJARATI = "gu"
    KANNADA = "kn"
    DUTCH = "nl"
    TURKISH = "tr"
    POLISH = "pl"
    UKRAINIAN = "uk"
    VIETNAMESE = "vi"
    THAI = "th"
    INDONESIAN = "id"
    MALAY = "ms"
    FILIPINO = "fil"
    SWAHILI = "sw"


@dataclass
class LanguageProfile:
    """Language profile with STT/TTS configuration."""
    code: str
    name: str
    native_name: str
    whisper_code: str
    tts_voice_male: Optional[str]
    tts_voice_female: Optional[str]
    rtl: bool = False
    dialect_variants: List[str] = None


class MultiLanguageManager:
    """
    Manages multi-language support for voice and text interaction.
    
    Supports 30+ languages for STT, TTS, and LLM processing.
    """
    
    def __init__(self):
        """Initialize multi-language manager."""
        self.current_language = "en"
        self.languages = self._initialize_language_profiles()
        self.auto_detect_enabled = True
        
    def _initialize_language_profiles(self) -> Dict[str, LanguageProfile]:
        """Initialize language profiles."""
        return {
            "en": LanguageProfile(
                code="en", name="English", native_name="English",
                whisper_code="en", tts_voice_male="en-US-GuyNeural",
                tts_voice_female="en-US-JennyNeural"
            ),
            "es": LanguageProfile(
                code="es", name="Spanish", native_name="Español",
                whisper_code="es", tts_voice_male="es-ES-AlvaroNeural",
                tts_voice_female="es-ES-ElviraNeural"
            ),
            "fr": LanguageProfile(
                code="fr", name="French", native_name="Français",
                whisper_code="fr", tts_voice_male="fr-FR-HenriNeural",
                tts_voice_female="fr-FR-DeniseNeural"
            ),
            "de": LanguageProfile(
                code="de", name="German", native_name="Deutsch",
                whisper_code="de", tts_voice_male="de-DE-ConradNeural",
                tts_voice_female="de-DE-KatjaNeural"
            ),
            "it": LanguageProfile(
                code="it", name="Italian", native_name="Italiano",
                whisper_code="it", tts_voice_male="it-IT-DiegoNeural",
                tts_voice_female="it-IT-ElsaNeural"
            ),
            "pt": LanguageProfile(
                code="pt", name="Portuguese", native_name="Português",
                whisper_code="pt", tts_voice_male="pt-BR-AntonioNeural",
                tts_voice_female="pt-BR-FranciscaNeural"
            ),
            "ru": LanguageProfile(
                code="ru", name="Russian", native_name="Русский",
                whisper_code="ru", tts_voice_male="ru-RU-DmitryNeural",
                tts_voice_female="ru-RU-SvetlanaNeural"
            ),
            "zh": LanguageProfile(
                code="zh", name="Chinese", native_name="中文",
                whisper_code="zh", tts_voice_male="zh-CN-YunxiNeural",
                tts_voice_female="zh-CN-XiaoxiaoNeural"
            ),
            "ja": LanguageProfile(
                code="ja", name="Japanese", native_name="日本語",
                whisper_code="ja", tts_voice_male="ja-JP-KeitaNeural",
                tts_voice_female="ja-JP-NanamiNeural"
            ),
            "ko": LanguageProfile(
                code="ko", name="Korean", native_name="한국어",
                whisper_code="ko", tts_voice_male="ko-KR-InJoonNeural",
                tts_voice_female="ko-KR-SunHiNeural"
            ),
            "ar": LanguageProfile(
                code="ar", name="Arabic", native_name="العربية",
                whisper_code="ar", tts_voice_male="ar-SA-HamedNeural",
                tts_voice_female="ar-SA-ZariyahNeural", rtl=True
            ),
            "hi": LanguageProfile(
                code="hi", name="Hindi", native_name="हिन्दी",
                whisper_code="hi", tts_voice_male="hi-IN-MadhurNeural",
                tts_voice_female="hi-IN-SwaraNeural"
            ),
            "bn": LanguageProfile(
                code="bn", name="Bengali", native_name="বাংলা",
                whisper_code="bn", tts_voice_male="bn-IN-BashkarNeural",
                tts_voice_female="bn-IN-TanishaaNeural"
            ),
            "pa": LanguageProfile(
                code="pa", name="Punjabi", native_name="ਪੰਜਾਬੀ",
                whisper_code="pa", tts_voice_male="pa-IN-GianNeural",
                tts_voice_female="pa-IN-AmritaNeural"
            ),
            "te": LanguageProfile(
                code="te", name="Telugu", native_name="తెలుగు",
                whisper_code="te", tts_voice_male="te-IN-MohanNeural",
                tts_voice_female="te-IN-ShrutiNeural"
            ),
            "mr": LanguageProfile(
                code="mr", name="Marathi", native_name="मराठी",
                whisper_code="mr", tts_voice_male="mr-IN-ManoharNeural",
                tts_voice_female="mr-IN-AarohiNeural"
            ),
            "ta": LanguageProfile(
                code="ta", name="Tamil", native_name="தமிழ்",
                whisper_code="ta", tts_voice_male="ta-IN-ValluvarNeural",
                tts_voice_female="ta-IN-PallaviNeural"
            ),
            "ur": LanguageProfile(
                code="ur", name="Urdu", native_name="اردو",
                whisper_code="ur", tts_voice_male="ur-PK-AsadNeural",
                tts_voice_female="ur-PK-UzmaNeural", rtl=True
            ),
            "gu": LanguageProfile(
                code="gu", name="Gujarati", native_name="ગુજરાતી",
                whisper_code="gu", tts_voice_male="gu-IN-NiranjanNeural",
                tts_voice_female="gu-IN-DhwaniNeural"
            ),
            "kn": LanguageProfile(
                code="kn", name="Kannada", native_name="ಕನ್ನಡ",
                whisper_code="kn", tts_voice_male="kn-IN-GaganNeural",
                tts_voice_female="kn-IN-SapnaNeural"
            ),
            "nl": LanguageProfile(
                code="nl", name="Dutch", native_name="Nederlands",
                whisper_code="nl", tts_voice_male="nl-NL-MaartenNeural",
                tts_voice_female="nl-NL-ColetteNeural"
            ),
            "tr": LanguageProfile(
                code="tr", name="Turkish", native_name="Türkçe",
                whisper_code="tr", tts_voice_male="tr-TR-AhmetNeural",
                tts_voice_female="tr-TR-EmelNeural"
            ),
            "pl": LanguageProfile(
                code="pl", name="Polish", native_name="Polski",
                whisper_code="pl", tts_voice_male="pl-PL-MarekNeural",
                tts_voice_female="pl-PL-ZofiaNeural"
            ),
            "uk": LanguageProfile(
                code="uk", name="Ukrainian", native_name="Українська",
                whisper_code="uk", tts_voice_male="uk-UA-OstapNeural",
                tts_voice_female="uk-UA-PolinaNeural"
            ),
            "vi": LanguageProfile(
                code="vi", name="Vietnamese", native_name="Tiếng Việt",
                whisper_code="vi", tts_voice_male="vi-VN-NamMinhNeural",
                tts_voice_female="vi-VN-HoaiMyNeural"
            ),
            "th": LanguageProfile(
                code="th", name="Thai", native_name="ไทย",
                whisper_code="th", tts_voice_male="th-TH-NiwatNeural",
                tts_voice_female="th-TH-PremwadeeNeural"
            ),
            "id": LanguageProfile(
                code="id", name="Indonesian", native_name="Bahasa Indonesia",
                whisper_code="id", tts_voice_male="id-ID-ArdiNeural",
                tts_voice_female="id-ID-GadisNeural"
            ),
            "ms": LanguageProfile(
                code="ms", name="Malay", native_name="Bahasa Melayu",
                whisper_code="ms", tts_voice_male="ms-MY-OsmanNeural",
                tts_voice_female="ms-MY-YasminNeural"
            ),
            "fil": LanguageProfile(
                code="fil", name="Filipino", native_name="Filipino",
                whisper_code="fil", tts_voice_male="fil-PH-AngeloNeural",
                tts_voice_female="fil-PH-BlessicaNeural"
            ),
            "sw": LanguageProfile(
                code="sw", name="Swahili", native_name="Kiswahili",
                whisper_code="sw", tts_voice_male="sw-KE-RafikiNeural",
                tts_voice_female="sw-KE-ZuriNeural"
            ),
        }
    
    def set_language(self, language_code: str) -> bool:
        """
        Set current language.
        
        Args:
            language_code: ISO 639-1 language code
            
        Returns:
            True if successful
        """
        if language_code in self.languages:
            self.current_language = language_code
            return True
        return False
    
    def get_language(self) -> LanguageProfile:
        """Get current language profile."""
        return self.languages.get(self.current_language, self.languages["en"])
    
    def detect_language(self, text: str) -> str:
        """
        Detect language from text.
        
        Args:
            text: Input text
            
        Returns:
            Detected language code
        """
        try:
            from langdetect import detect
            detected = detect(text)
            if detected in self.languages:
                return detected
        except Exception:
            pass
        
        return self.current_language
    
    def get_tts_voice(self, gender: str = "female") -> Optional[str]:
        """Get TTS voice for current language."""
        profile = self.get_language()
        if gender == "male":
            return profile.tts_voice_male
        else:
            return profile.tts_voice_female
    
    def get_whisper_language(self) -> str:
        """Get Whisper language code for current language."""
        profile = self.get_language()
        return profile.whisper_code
    
    def get_supported_languages(self) -> List[Dict[str, Any]]:
        """Get list of all supported languages."""
        return [
            {
                'code': lang.code,
                'name': lang.name,
                'native_name': lang.native_name,
                'rtl': lang.rtl
            }
            for lang in self.languages.values()
        ]
    
    def translate_system_messages(self, message_key: str) -> str:
        """Get translated system messages."""
        translations = {
            "en": {
                "greeting": "Hello! How can I help you today?",
                "goodbye": "Goodbye! Have a great day!",
                "error": "I'm sorry, I encountered an error.",
                "thinking": "Let me think about that...",
                "processing": "Processing your request...",
                "completed": "Task completed successfully!",
                "failed": "Task failed. Please try again."
            },
            "es": {
                "greeting": "¡Hola! ¿Cómo puedo ayudarte hoy?",
                "goodbye": "¡Adiós! ¡Que tengas un gran día!",
                "error": "Lo siento, encontré un error.",
                "thinking": "Déjame pensar en eso...",
                "processing": "Procesando tu solicitud...",
                "completed": "¡Tarea completada con éxito!",
                "failed": "La tarea falló. Por favor, inténtalo de nuevo."
            },
            "fr": {
                "greeting": "Bonjour! Comment puis-je vous aider aujourd'hui?",
                "goodbye": "Au revoir! Passez une excellente journée!",
                "error": "Désolé, j'ai rencontré une erreur.",
                "thinking": "Laissez-moi réfléchir à cela...",
                "processing": "Traitement de votre demande...",
                "completed": "Tâche terminée avec succès!",
                "failed": "La tâche a échoué. Veuillez réessayer."
            },
            "hi": {
                "greeting": "नमस्ते! मैं आज आपकी कैसे मदद कर सकता हूं?",
                "goodbye": "अलविदा! आपका दिन शुभ हो!",
                "error": "मुझे खेद है, मुझे एक त्रुटि का सामना करना पड़ा।",
                "thinking": "मुझे इसके बारे में सोचने दो...",
                "processing": "आपके अनुरोध को संसाधित कर रहा हूं...",
                "completed": "कार्य सफलतापूर्वक पूर्ण हुआ!",
                "failed": "कार्य विफल रहा। कृपया पुन: प्रयास करें।"
            },
            "zh": {
                "greeting": "你好！今天我能如何帮助你？",
                "goodbye": "再见！祝你有美好的一天！",
                "error": "对不起，我遇到了一个错误。",
                "thinking": "让我想想...",
                "processing": "正在处理您的请求...",
                "completed": "任务成功完成！",
                "failed": "任务失败。请重试。"
            },
            "ar": {
                "greeting": "مرحبا! كيف يمكنني مساعدتك اليوم؟",
                "goodbye": "وداعا! أتمنى لك يوما سعيدا!",
                "error": "أنا آسف، واجهت خطأ.",
                "thinking": "دعني أفكر في ذلك...",
                "processing": "معالجة طلبك...",
                "completed": "تمت المهمة بنجاح!",
                "failed": "فشلت المهمة. يرجى المحاولة مرة أخرى."
            },
            "ja": {
                "greeting": "こんにちは！今日は何をお手伝いしましょうか？",
                "goodbye": "さようなら！良い一日を！",
                "error": "申し訳ございません。エラーが発生しました。",
                "thinking": "考えさせてください...",
                "processing": "リクエストを処理しています...",
                "completed": "タスクが正常に完了しました！",
                "failed": "タスクが失敗しました。もう一度お試しください。"
            }
        }
        
        lang_messages = translations.get(self.current_language, translations["en"])
        return lang_messages.get(message_key, translations["en"].get(message_key, ""))
