import pyttsx3
import pyaudio
import wave
import io
import logging
import hashlib
import json
from pathlib import Path
from typing import Optional, Literal
from dataclasses import dataclass
from threading import Lock, Event
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class TTSConfig:
    """Configuration for TTS settings"""
    provider: Literal["pyttsx3", "openai", "edge"] = "edge"  # Natural human voice
    voice: Literal["male", "female", "neutral"] = "female"
    rate: int = 160  # Normal conversational speed
    volume: float = 10.0  # MAXIMUM volume (was 1.0 → 3.0 → 10.0)
    pitch: float = 1.2  # Higher pitch for Megumi
    sample_rate: int = 22050
    cache_enabled: bool = True
    cache_dir: str = "data/tts_cache"
    amplify_playback: bool = True  # Amplify audio during playback
    amplification_factor: float = 5.0  # MAXIMUM boost 5x (was 2.5x)


class TTSCache:
    """Cache for TTS audio to avoid regenerating common phrases"""
    
    def __init__(self, cache_dir: str = "data/tts_cache", max_cache_size_mb: int = 100):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_cache_size_mb = max_cache_size_mb
        self.metadata_file = self.cache_dir / "metadata.json"
        self.metadata = self._load_metadata()
        self.lock = Lock()
        logger.info(f"TTSCache initialized at {self.cache_dir}")
    
    def _load_metadata(self) -> dict:
        """Load cache metadata"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cache metadata: {e}")
        return {}
    
    def _save_metadata(self):
        """Save cache metadata"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache metadata: {e}")
    
    def _get_cache_key(self, text: str, config: TTSConfig) -> str:
        """Generate cache key from text and config"""
        config_str = f"{config.provider}_{config.voice}_{config.rate}_{config.pitch}"
        key_input = f"{text}_{config_str}"
        return hashlib.md5(key_input.encode()).hexdigest()
    
    def get(self, text: str, config: TTSConfig) -> Optional[bytes]:
        """Get cached audio for text"""
        if not config.cache_enabled:
            return None
        
        cache_key = self._get_cache_key(text, config)
        cache_file = self.cache_dir / f"{cache_key}.wav"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'rb') as f:
                    audio_data = f.read()
                
                with self.lock:
                    if cache_key in self.metadata:
                        self.metadata[cache_key]['hits'] += 1
                        self._save_metadata()
                
                logger.debug(f"Cache hit for: {text[:50]}...")
                return audio_data
            except Exception as e:
                logger.error(f"Failed to read from cache: {e}")
        
        return None
    
    def put(self, text: str, config: TTSConfig, audio_data: bytes):
        """Cache audio for text"""
        if not config.cache_enabled:
            return
        
        cache_key = self._get_cache_key(text, config)
        cache_file = self.cache_dir / f"{cache_key}.wav"
        
        try:
            with open(cache_file, 'wb') as f:
                f.write(audio_data)
            
            with self.lock:
                self.metadata[cache_key] = {
                    'text': text[:100],
                    'hits': 0,
                    'size_bytes': len(audio_data)
                }
                self._save_metadata()
            
            self._cleanup_if_needed()
            logger.debug(f"Cached audio for: {text[:50]}...")
        except Exception as e:
            logger.error(f"Failed to write to cache: {e}")
    
    def _cleanup_if_needed(self):
        """Remove old cache entries if size limit exceeded"""
        total_size = sum(
            f.stat().st_size for f in self.cache_dir.glob("*.wav")
        )
        
        if total_size > self.max_cache_size_mb * 1024 * 1024:
            sorted_entries = sorted(
                self.metadata.items(),
                key=lambda x: x[1].get('hits', 0)
            )
            
            for cache_key, _ in sorted_entries[:len(sorted_entries) // 2]:
                cache_file = self.cache_dir / f"{cache_key}.wav"
                if cache_file.exists():
                    cache_file.unlink()
                del self.metadata[cache_key]
            
            self._save_metadata()
            logger.info("Cache cleanup completed")


class LocalTTS:
    """Local TTS using pyttsx3"""
    
    def __init__(self, config: TTSConfig):
        self.config = config
        self.engine = pyttsx3.init()
        self._configure_engine()
        logger.info("LocalTTS initialized with pyttsx3")
    
    def _configure_engine(self):
        """Configure TTS engine with settings"""
        voices = self.engine.getProperty('voices')
        
        if self.config.voice == "female":
            for voice in voices:
                if "female" in voice.name.lower() or "zira" in voice.name.lower():
                    self.engine.setProperty('voice', voice.id)
                    break
        elif self.config.voice == "male":
            for voice in voices:
                if "male" in voice.name.lower() or "david" in voice.name.lower():
                    self.engine.setProperty('voice', voice.id)
                    break
        
        self.engine.setProperty('rate', self.config.rate)
        # pyttsx3 volume range is 0.0-1.0, max it out
        self.engine.setProperty('volume', 1.0)
    
    def synthesize(self, text: str) -> bytes:
        """Synthesize text to audio"""
        try:
            temp_file = io.BytesIO()
            
            self.engine.save_to_file(text, 'temp_tts.wav')
            self.engine.runAndWait()
            
            with open('temp_tts.wav', 'rb') as f:
                audio_data = f.read()
            
            import os
            os.remove('temp_tts.wav')
            
            return audio_data
        except Exception as e:
            logger.error(f"Local TTS synthesis failed: {e}")
            raise
    
    def get_available_voices(self) -> list[dict]:
        """Get list of available voices"""
        voices = self.engine.getProperty('voices')
        return [
            {
                'id': voice.id,
                'name': voice.name,
                'languages': voice.languages,
                'gender': voice.gender
            }
            for voice in voices
        ]


class CloudTTS:
    """Cloud-based TTS using OpenAI"""
    
    def __init__(self, config: TTSConfig, api_key: str):
        self.config = config
        self.api_key = api_key
        
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=api_key)
            logger.info("CloudTTS initialized with OpenAI")
        except ImportError:
            logger.error("OpenAI library not installed. Install with: pip install openai")
            raise
    
    def synthesize(self, text: str) -> bytes:
        """Synthesize text to audio using OpenAI TTS"""
        try:
            voice_map = {
                "female": "nova",
                "male": "onyx",
                "neutral": "alloy"
            }
            
            response = self.client.audio.speech.create(
                model="tts-1",
                voice=voice_map.get(self.config.voice, "nova"),
                input=text,
                speed=self.config.pitch
            )
            
            return response.content
        except Exception as e:
            logger.error(f"Cloud TTS synthesis failed: {e}")
            raise


class EdgeTTS:
    """Natural TTS using Edge TTS (Microsoft Azure Neural Voices)"""
    
    def __init__(self, config: TTSConfig):
        self.config = config
        try:
            import edge_tts
            import nest_asyncio
            nest_asyncio.apply()
            logger.info("EdgeTTS initialized")
        except ImportError:
            logger.error("edge-tts not installed. Install with: pip install edge-tts nest-asyncio")
            raise

    def synthesize(self, text: str) -> bytes:
        import edge_tts
        import asyncio
        
        # Select voice based on gender - using most natural sounding voices
        if self.config.voice == "male":
            voice = "en-US-AndrewNeural"  # Natural, friendly male voice
        else:
            voice = "en-IN-NeerjaNeural"  # Indian English female voice - sounds very natural and human
            
        # Calculate rate adjustment
        # Default 160 wpm. Edge uses percentage.
        # Approx: +30% is fast, -30% is slow.
        # Let's map 160 -> +0%, 200 -> +25%
        rate_diff = self.config.rate - 160
        rate_pct = int((rate_diff / 160) * 100)
        rate_str = f"{rate_pct:+d}%"
        
        async def _generate():
            communicate = edge_tts.Communicate(text, voice, rate=rate_str)
            audio_data = b""
            async for chunk in communicate.stream():
                if chunk["type"] == "audio":
                    audio_data += chunk["data"]
            return audio_data

        try:
            # Create a new loop if needed, or use existing
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
            if loop.is_running():
                 # We are in async context already?
                 # This is tricky using asyncio.run inside async loop
                 # But tts.speak is usually called from thread or sync context
                 return asyncio.run(_generate())
            else:
                 return loop.run_until_complete(_generate())
                 
        except Exception as e:
             logger.error(f"EdgeTTS synthesis failed: {e}")
             # distinct fallback to local if edge fails?
             raise


class TextToSpeech:
    """Main TTS interface with caching and playback"""
    
    def __init__(
        self,
        config: Optional[TTSConfig] = None,
        api_key: Optional[str] = None
    ):
        self.config = config or TTSConfig()
        self.cache = TTSCache(
            cache_dir=self.config.cache_dir,
            max_cache_size_mb=100
        )
        
        self.stop_playback = Event()  # Event to signal stop
        
        if self.config.provider == "openai":
            if not api_key:
                logger.warning("No API key provided for OpenAI TTS, falling back to local")
                self.config.provider = "pyttsx3"
                self.engine = LocalTTS(self.config)
            else:
                self.engine = CloudTTS(self.config, api_key)
        elif self.config.provider == "edge":
            self.engine = EdgeTTS(self.config)
        else:
            self.engine = LocalTTS(self.config)
        
        self.audio = pyaudio.PyAudio()
        logger.info(f"TextToSpeech initialized with provider: {self.config.provider}")
    
    def synthesize(self, text: str, use_cache: bool = True) -> bytes:
        """Synthesize text to audio with optional caching"""
        if not text or not text.strip():
            raise ValueError("Text cannot be empty")
        
        if use_cache:
            cached_audio = self.cache.get(text, self.config)
            if cached_audio:
                return cached_audio
        
        audio_data = self.engine.synthesize(text)
        
        if use_cache:
            self.cache.put(text, self.config, audio_data)
        
        return audio_data
    
    def speak(self, text: str, blocking: bool = True) -> Optional[bytes]:
        """Synthesize and play audio"""
        try:
            self.stop_playback.clear() # Clear stop flag before new speech
            audio_data = self.synthesize(text)
            
            if blocking:
                self._play_audio(audio_data)
            else:
                import threading
                thread = threading.Thread(target=self._play_audio, args=(audio_data,))
                thread.daemon = True
                thread.start()
            
            return audio_data
        except Exception as e:
            logger.error(f"Failed to speak text: {e}")
            return None
    
    def stop(self):
        """Stop current playback immediately"""
        self.stop_playback.set()
        logger.info("TTS playback stopped by request")

    def _play_audio(self, audio_data: bytes):
        """Play audio using PyAudio with optional amplification"""
        try:
            with io.BytesIO(audio_data) as audio_file:
                with wave.open(audio_file, 'rb') as wf:
                    stream = self.audio.open(
                        format=self.audio.get_format_from_width(wf.getsampwidth()),
                        channels=wf.getnchannels(),
                        rate=wf.getframerate(),
                        output=True
                    )
                    
                    chunk_size = 1024
                    data = wf.readframes(chunk_size)
                    
                    while data:
                        if self.stop_playback.is_set():
                            break
                        
                        if self.config.amplify_playback:
                            audio_array = np.frombuffer(data, dtype=np.int16)
                            amplified = np.clip(
                                audio_array * self.config.amplification_factor,
                                -32768, 32767
                            ).astype(np.int16)
                            data = amplified.tobytes()
                        
                        stream.write(data)
                        data = wf.readframes(chunk_size)
                    
                    stream.stop_stream()
                    stream.close()
            
            if self.stop_playback.is_set():
                logger.info("Audio playback interrupted")
            else:
                logger.debug("Audio playback completed")
        except Exception as e:
            logger.error(f"Audio playback failed: {e}")
    
    def save_to_file(self, text: str, filename: str):
        """Synthesize and save to file"""
        try:
            audio_data = self.synthesize(text)
            with open(filename, 'wb') as f:
                f.write(audio_data)
            logger.info(f"Audio saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save audio: {e}")
            raise
    
    def update_config(self, **kwargs):
        """Update TTS configuration"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        
        if isinstance(self.engine, LocalTTS):
            self.engine._configure_engine()
        
        logger.info(f"TTS config updated: {kwargs}")
    
    def get_cache_stats(self) -> dict:
        """Get cache statistics"""
        total_hits = sum(meta.get('hits', 0) for meta in self.cache.metadata.values())
        total_size = sum(meta.get('size_bytes', 0) for meta in self.cache.metadata.values())
        
        return {
            'total_entries': len(self.cache.metadata),
            'total_hits': total_hits,
            'total_size_mb': total_size / (1024 * 1024),
            'cache_dir': str(self.cache.cache_dir)
        }
    
    def clear_cache(self):
        """Clear all cached audio"""
        for cache_file in self.cache.cache_dir.glob("*.wav"):
            cache_file.unlink()
        
        self.cache.metadata = {}
        self.cache._save_metadata()
        logger.info("TTS cache cleared")
    
    def cleanup(self):
        """Cleanup resources"""
        self.audio.terminate()
        logger.info("TextToSpeech cleaned up")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
