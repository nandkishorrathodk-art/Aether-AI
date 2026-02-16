import logging
import numpy as np
from typing import Optional, Callable
from pathlib import Path
import pvporcupine
from .audio_utils import AudioInputHandler, AudioConfig

logger = logging.getLogger(__name__)


class WakeWordDetector:
    def __init__(
        self,
        wake_word: str = "hey aether",
        sensitivity: float = 0.5,
        access_key: Optional[str] = None,
        use_porcupine: bool = False,
        audio_handler: Optional[AudioInputHandler] = None
    ):
        self.wake_word = wake_word.lower()
        self.sensitivity = sensitivity
        self.use_porcupine = use_porcupine
        self.audio_handler = audio_handler or AudioInputHandler()
        
        self.porcupine: Optional[pvporcupine.Porcupine] = None
        self.is_listening = False
        
        if use_porcupine and access_key:
            try:
                self._init_porcupine(access_key)
            except Exception as e:
                logger.warning(f"Failed to initialize Porcupine: {e}. Falling back to energy-based detection.")
                self.use_porcupine = False
        else:
            logger.info("Using energy-based wake word detection")

    def _init_porcupine(self, access_key: str):
        keywords = self._get_available_porcupine_keywords()
        
        target_keyword = None
        if "jarvis" in self.wake_word:
            target_keyword = "jarvis"
        elif "alexa" in self.wake_word:
            target_keyword = "alexa"
        elif "computer" in self.wake_word:
            target_keyword = "computer"
        elif "hey google" in self.wake_word or "ok google" in self.wake_word:
            target_keyword = "ok google"
        elif "hey siri" in self.wake_word:
            target_keyword = "hey siri"
        else:
            target_keyword = "porcupine"
        
        if target_keyword not in keywords:
            target_keyword = "porcupine"
        
        try:
            self.porcupine = pvporcupine.create(
                access_key=access_key,
                keywords=[target_keyword],
                sensitivities=[self.sensitivity]
            )
            logger.info(f"Porcupine initialized with keyword: {target_keyword}")
        except Exception as e:
            logger.error(f"Failed to create Porcupine instance: {e}")
            raise

    def _get_available_porcupine_keywords(self) -> list[str]:
        return [
            "alexa", "americano", "blueberry", "bumblebee", "computer",
            "grapefruit", "grasshopper", "hey google", "hey siri", "jarvis",
            "ok google", "picovoice", "porcupine", "terminator"
        ]

    def detect_from_audio(self, audio_data: np.ndarray) -> bool:
        if self.use_porcupine and self.porcupine is not None:
            return self._detect_porcupine(audio_data)
        else:
            return self._detect_energy_based(audio_data)

    def _detect_porcupine(self, audio_data: np.ndarray) -> bool:
        if self.porcupine is None:
            return False
        
        try:
            frame_length = self.porcupine.frame_length
            
            for i in range(0, len(audio_data) - frame_length, frame_length):
                frame = audio_data[i:i + frame_length]
                keyword_index = self.porcupine.process(frame)
                
                if keyword_index >= 0:
                    logger.info("Wake word detected (Porcupine)")
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Porcupine detection error: {e}")
            return False

    def _detect_energy_based(self, audio_data: np.ndarray) -> bool:
        energy = AudioInputHandler.calculate_energy(audio_data)
        
        energy_threshold = AudioConfig.ENERGY_THRESHOLD * 2
        
        if energy > energy_threshold:
            logger.debug(f"High energy detected: {energy:.2f}")
            return True
        
        return False

    def listen_for_wake_word(
        self,
        callback: Optional[Callable[[], None]] = None,
        timeout_seconds: Optional[float] = None
    ) -> bool:
        self.is_listening = True
        logger.info(f"Listening for wake word: '{self.wake_word}'")
        
        if not self.audio_handler.stream:
            self.audio_handler.start_stream()
        
        chunks_processed = 0
        max_chunks = None
        if timeout_seconds:
            max_chunks = int(timeout_seconds * AudioConfig.SAMPLE_RATE / AudioConfig.CHUNK_SIZE)
        
        try:
            while self.is_listening:
                chunk = self.audio_handler.read_chunk()
                if chunk is None:
                    continue
                
                chunks_processed += 1
                if max_chunks and chunks_processed >= max_chunks:
                    logger.info("Wake word detection timeout")
                    return False
                
                if self.detect_from_audio(chunk):
                    logger.info("Wake word detected!")
                    if callback:
                        callback()
                    return True
            
            return False
        except KeyboardInterrupt:
            logger.info("Wake word detection interrupted")
            return False
        except Exception as e:
            logger.error(f"Wake word detection error: {e}")
            return False

    def listen_continuous(
        self,
        on_wake_word: Callable[[], None],
        on_error: Optional[Callable[[Exception], None]] = None
    ):
        self.is_listening = True
        logger.info("Starting continuous wake word detection...")
        
        if not self.audio_handler.stream:
            self.audio_handler.start_stream()
        
        try:
            while self.is_listening:
                chunk = self.audio_handler.read_chunk()
                if chunk is None:
                    continue
                
                try:
                    if self.detect_from_audio(chunk):
                        logger.info("Wake word detected!")
                        on_wake_word()
                except Exception as e:
                    logger.error(f"Error in wake word callback: {e}")
                    if on_error:
                        on_error(e)
        except KeyboardInterrupt:
            logger.info("Continuous detection interrupted")
        except Exception as e:
            logger.error(f"Continuous detection error: {e}")
            if on_error:
                on_error(e)

    def stop_listening(self):
        self.is_listening = False
        logger.info("Wake word detection stopped")

    def cleanup(self):
        self.stop_listening()
        if self.porcupine is not None:
            self.porcupine.delete()
            self.porcupine = None
        logger.info("WakeWordDetector cleaned up")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


class SimpleWakeWordDetector:
    def __init__(
        self,
        wake_word: str = "hey aether",
        energy_multiplier: float = 2.0,
        min_duration_ms: int = 300
    ):
        self.wake_word = wake_word.lower()
        self.energy_multiplier = energy_multiplier
        self.min_duration_ms = min_duration_ms
        
        self.base_threshold = AudioConfig.ENERGY_THRESHOLD
        self.detection_threshold = self.base_threshold * energy_multiplier
        
        logger.info(f"SimpleWakeWordDetector initialized for '{wake_word}'")

    def detect(self, audio_data: np.ndarray, sample_rate: int = AudioConfig.SAMPLE_RATE) -> bool:
        min_samples = int(sample_rate * self.min_duration_ms / 1000)
        
        if len(audio_data) < min_samples:
            return False
        
        energy = AudioInputHandler.calculate_energy(audio_data)
        
        if energy > self.detection_threshold:
            peak_energy = np.max(np.abs(audio_data))
            
            if peak_energy > self.base_threshold * 1.5:
                logger.debug(f"Wake word pattern detected (energy: {energy:.2f}, peak: {peak_energy:.2f})")
                return True
        
        return False
