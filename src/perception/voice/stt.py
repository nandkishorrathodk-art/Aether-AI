import logging
import numpy as np
import whisper
import tempfile
import os
from typing import Optional, Union
from pathlib import Path
from openai import OpenAI
from .audio_utils import AudioInputHandler, AudioConfig

logger = logging.getLogger(__name__)


class SpeechToText:
    def __init__(
        self,
        model_name: str = "base",
        use_cloud: bool = False,
        api_key: Optional[str] = None,
        language: Optional[str] = None,
        device: str = "cpu"
    ):
        self.model_name = model_name
        self.use_cloud = use_cloud
        self.language = language
        self.device = device
        
        self.model: Optional[whisper.Whisper] = None
        self.client: Optional[OpenAI] = None
        
        if use_cloud:
            if not api_key:
                raise ValueError("API key required for cloud-based STT")
            self.client = OpenAI(api_key=api_key)
            logger.info("Using cloud-based OpenAI Whisper API")
        else:
            self._load_local_model()
    
    def _load_local_model(self):
        try:
            logger.info(f"Loading Whisper model: {self.model_name}")
            self.model = whisper.load_model(self.model_name, device=self.device)
            logger.info(f"Whisper model loaded successfully on {self.device}")
        except Exception as e:
            logger.error(f"Failed to load Whisper model: {e}")
            raise

    def transcribe_audio(
        self,
        audio_data: Union[np.ndarray, str, Path],
        language: Optional[str] = None,
        task: str = "transcribe",
        temperature: float = 0.0,
        best_of: int = 5,
        beam_size: int = 5
    ) -> dict:
        language = language or self.language
        prompt = "This is a casual conversation in Hinglish (Hindi + English). Accurately transcribe English and Hindi words."
        
        if isinstance(audio_data, (str, Path)):
            audio_path = str(audio_data)
            return self._transcribe_from_file(audio_path, language, task, temperature, best_of, beam_size)
        elif isinstance(audio_data, np.ndarray):
            return self._transcribe_from_array(audio_data, language, task, temperature, best_of, beam_size)
        else:
            raise ValueError("audio_data must be numpy array, file path, or Path object")

    def _transcribe_from_array(
        self,
        audio_array: np.ndarray,
        language: Optional[str],
        task: str,
        temperature: float,
        best_of: int,
        beam_size: int
    ) -> dict:
        if len(audio_array) == 0:
            logger.warning("Empty audio array provided")
            return self._empty_result()
        
        audio_float = audio_array.astype(np.float32) / 32768.0
        
        if self.use_cloud:
            return self._transcribe_cloud_from_array(audio_float, language)
        else:
            return self._transcribe_local(audio_float, language, task, temperature, best_of, beam_size)

    def _transcribe_from_file(
        self,
        audio_path: str,
        language: Optional[str],
        task: str,
        temperature: float,
        best_of: int,
        beam_size: int
    ) -> dict:
        if not os.path.exists(audio_path):
            raise FileNotFoundError(f"Audio file not found: {audio_path}")
        
        if self.use_cloud:
            return self._transcribe_cloud_from_file(audio_path, language)
        else:
            audio = whisper.load_audio(audio_path)
            return self._transcribe_local(audio, language, task, temperature, best_of, beam_size)

    def _transcribe_local(
        self,
        audio: np.ndarray,
        language: Optional[str],
        task: str,
        temperature: float,
        best_of: int,
        beam_size: int
    ) -> dict:
        if self.model is None:
            raise RuntimeError("Whisper model not loaded")
        
        try:
            options = {
                "task": task,
                "temperature": temperature,
                "best_of": best_of,
                "beam_size": beam_size,
                "fp16": False if self.device == "cpu" else True,
                "initial_prompt": "This is a casual conversation in Hinglish (Hindi + English). Accurately transcribe English and Hindi words."
            }
            
            if language:
                options["language"] = language
            
            result = self.model.transcribe(audio, **options)
            
            confidence = self._calculate_confidence(result)
            
            return {
                "text": result["text"].strip(),
                "language": result.get("language", language),
                "segments": result.get("segments", []),
                "confidence": confidence,
                "source": "local"
            }
        except Exception as e:
            logger.error(f"Local transcription error: {e}")
            return self._empty_result(error=str(e))

    def _transcribe_cloud_from_array(
        self,
        audio_array: np.ndarray,
        language: Optional[str]
    ) -> dict:
        try:
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_file:
                temp_path = temp_file.name
            
            audio_handler = AudioInputHandler()
            audio_int16 = (audio_array * 32768.0).astype(np.int16)
            audio_handler.save_to_wav(audio_int16, temp_path)
            
            result = self._transcribe_cloud_from_file(temp_path, language)
            
            os.unlink(temp_path)
            
            return result
        except Exception as e:
            logger.error(f"Cloud transcription error: {e}")
            return self._empty_result(error=str(e))

    def _transcribe_cloud_from_file(
        self,
        audio_path: str,
        language: Optional[str]
    ) -> dict:
        if self.client is None:
            raise RuntimeError("OpenAI client not initialized")
        
        try:
            with open(audio_path, "rb") as audio_file:
                params = {"file": audio_file, "model": "whisper-1"}
                if language:
                    params["language"] = language
                
                response = self.client.audio.transcriptions.create(**params)
            
            return {
                "text": response.text.strip(),
                "language": language or "auto",
                "segments": [],
                "confidence": 0.9,
                "source": "cloud"
            }
        except Exception as e:
            logger.error(f"Cloud API transcription error: {e}")
            return self._empty_result(error=str(e))

    def _calculate_confidence(self, result: dict) -> float:
        segments = result.get("segments", [])
        if not segments:
            return 0.5
        
        probabilities = []
        for segment in segments:
            if "avg_logprob" in segment:
                prob = np.exp(segment["avg_logprob"])
                probabilities.append(prob)
            elif "no_speech_prob" in segment:
                prob = 1.0 - segment["no_speech_prob"]
                probabilities.append(prob)
        
        if not probabilities:
            return 0.7
        
        return float(np.mean(probabilities))

    def _empty_result(self, error: Optional[str] = None) -> dict:
        result = {
            "text": "",
            "language": None,
            "segments": [],
            "confidence": 0.0,
            "source": "cloud" if self.use_cloud else "local"
        }
        if error:
            result["error"] = error
        return result

    def transcribe_realtime(
        self,
        audio_handler: AudioInputHandler,
        duration_seconds: float = 5.0,
        language: Optional[str] = None
    ) -> dict:
        logger.info(f"Recording for {duration_seconds} seconds...")
        audio_data = audio_handler.read_audio(duration_seconds)
        
        if len(audio_data) == 0:
            logger.warning("No audio data captured")
            return self._empty_result()
        
        return self.transcribe_audio(audio_data, language=language)

    def transcribe_until_silence(
        self,
        audio_handler: AudioInputHandler,
        max_duration_seconds: float = 30,
        silence_duration_ms: int = 1500,
        language: Optional[str] = None
    ) -> dict:
        logger.info("Recording until silence...")
        audio_data = audio_handler.record_until_silence(
            max_duration_seconds=max_duration_seconds,
            silence_duration_ms=silence_duration_ms
        )
        
        if len(audio_data) == 0:
            logger.warning("No audio data captured")
            return self._empty_result()
        
        return self.transcribe_audio(audio_data, language=language)

    def get_available_models(self) -> list[str]:
        return ["tiny", "base", "small", "medium", "large", "large-v2", "large-v3"]

    def get_supported_languages(self) -> list[str]:
        return [
            "en", "zh", "de", "es", "ru", "ko", "fr", "ja", "pt", "tr", "pl", "ca", "nl",
            "ar", "sv", "it", "id", "hi", "fi", "vi", "he", "uk", "el", "ms", "cs", "ro",
            "da", "hu", "ta", "no", "th", "ur", "hr", "bg", "lt", "la", "mi", "ml", "cy",
            "sk", "te", "fa", "lv", "bn", "sr", "az", "sl", "kn", "et", "mk", "br", "eu",
            "is", "hy", "ne", "mn", "bs", "kk", "sq", "sw", "gl", "mr", "pa", "si", "km",
            "sn", "yo", "so", "af", "oc", "ka", "be", "tg", "sd", "gu", "am", "yi", "lo",
            "uz", "fo", "ht", "ps", "tk", "nn", "mt", "sa", "lb", "my", "bo", "tl", "mg",
            "as", "tt", "haw", "ln", "ha", "ba", "jw", "su"
        ]

    def cleanup(self):
        if self.model is not None:
            del self.model
            self.model = None
        logger.info("SpeechToText cleaned up")


class STTConfig:
    WHISPER_MODELS = {
        "tiny": {"size_mb": 39, "speed": "very_fast", "accuracy": "low"},
        "base": {"size_mb": 74, "speed": "fast", "accuracy": "medium"},
        "small": {"size_mb": 244, "speed": "medium", "accuracy": "good"},
        "medium": {"size_mb": 769, "speed": "slow", "accuracy": "very_good"},
        "large": {"size_mb": 1550, "speed": "very_slow", "accuracy": "excellent"},
        "large-v2": {"size_mb": 1550, "speed": "very_slow", "accuracy": "excellent"},
        "large-v3": {"size_mb": 1550, "speed": "very_slow", "accuracy": "best"}
    }

    @classmethod
    def get_recommended_model(cls, ram_gb: int, has_gpu: bool) -> str:
        if ram_gb < 4:
            return "tiny"
        elif ram_gb < 8:
            return "base"
        elif ram_gb < 16:
            return "small"
        elif has_gpu:
            return "large-v3"
        else:
            return "medium"
