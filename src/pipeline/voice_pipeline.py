"""
Voice Pipeline Orchestrator
Integrates: Wake Word → STT → LLM → TTS → Output
"""
import asyncio
import logging
import time
import json
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Thread, Event
from queue import Queue, Empty
import numpy as np

from src.perception.voice.wake_word import WakeWordDetector
from src.perception.voice.stt import SpeechToText
from src.perception.voice.tts import TextToSpeech, TTSConfig
from src.perception.voice.audio_utils import AudioInputHandler
from src.cognitive.llm.inference import (
    conversation_engine,
    ConversationRequest,
    IntentType
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VoiceSession:
    """Tracks an active voice conversation session"""
    session_id: str
    started_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    turn_count: int = 0
    total_processing_time: float = 0.0
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()
        self.turn_count += 1
    
    def is_expired(self, timeout_minutes: int = 5) -> bool:
        """Check if session has timed out"""
        return datetime.now() - self.last_activity > timedelta(minutes=timeout_minutes)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        duration = (datetime.now() - self.started_at).total_seconds()
        avg_processing_time = (
            self.total_processing_time / self.turn_count
            if self.turn_count > 0
            else 0
        )
        
        return {
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "duration_seconds": duration,
            "turn_count": self.turn_count,
            "avg_processing_time": avg_processing_time
        }


@dataclass
class PipelineConfig:
    """Configuration for voice pipeline"""
    wake_word: str = "hey aether"
    wake_word_sensitivity: float = 0.5
    porcupine_access_key: Optional[str] = None
    use_porcupine: bool = False
    
    stt_model: str = "base"
    stt_use_cloud: bool = False
    stt_api_key: Optional[str] = None
    stt_language: Optional[str] = None
    
    tts_provider: str = "pyttsx3"
    tts_voice: str = "female"
    tts_api_key: Optional[str] = None
    
    session_timeout_minutes: int = 5
    max_retry_attempts: int = 3
    enable_continuous_mode: bool = True


class VoicePipelineOrchestrator:
    """
    Orchestrates the complete voice interaction pipeline:
    Wake Word → STT → LLM → TTS → Audio Output
    """
    
    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        
        # Initialize components
        self.audio_handler = AudioInputHandler()
        self.wake_word_detector: Optional[WakeWordDetector] = None
        self.stt: Optional[SpeechToText] = None
        self.tts: Optional[TextToSpeech] = None
        
        # Session management
        self.sessions: Dict[str, VoiceSession] = {}
        self.current_session_id = "default"
        
        # Pipeline state
        self.is_running = False
        self.pipeline_thread: Optional[Thread] = None
        self.stop_event = Event()
        
        # Response queue for TTS output
        self.response_queue: Queue = Queue()
        self.tts_thread: Optional[Thread] = None
        
        # Performance tracking
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        
        logger.info("Voice Pipeline Orchestrator initialized")
    
    def broadcast_status(self, status: str, data: Optional[Dict] = None):
        """Broadcast status update to UI via stdout"""
        message = {
            "type": "status",
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "data": data or {}
        }
        print(json.dumps(message), flush=True)

    def initialize(self):
        """Initialize all pipeline components"""
        try:
            # Initialize wake word detector
            self.wake_word_detector = WakeWordDetector(
                wake_word=self.config.wake_word,
                sensitivity=self.config.wake_word_sensitivity,
                access_key=self.config.porcupine_access_key,
                use_porcupine=self.config.use_porcupine,
                audio_handler=self.audio_handler
            )
            logger.info(f"Wake word detector initialized: '{self.config.wake_word}'")
            
            # Initialize STT
            self.stt = SpeechToText(
                model_name=self.config.stt_model,
                use_cloud=self.config.stt_use_cloud,
                api_key=self.config.stt_api_key,
                language=self.config.stt_language
            )
            logger.info(f"STT initialized: model={self.config.stt_model}, cloud={self.config.stt_use_cloud}")
            
            # Initialize TTS
            tts_config = TTSConfig(
                provider=self.config.tts_provider,
                voice=self.config.tts_voice
            )
            self.tts = TextToSpeech(
                config=tts_config,
                api_key=self.config.tts_api_key
            )
            logger.info(f"TTS initialized: provider={self.config.tts_provider}")
            
            # Create default session
            self._create_session(self.current_session_id)
            
            logger.info("All pipeline components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize pipeline: {e}")
            raise
    
    def _create_session(self, session_id: str) -> VoiceSession:
        """Create a new voice session"""
        session = VoiceSession(session_id=session_id)
        self.sessions[session_id] = session
        logger.info(f"Created voice session: {session_id}")
        return session
    
    def _get_or_create_session(self, session_id: str) -> VoiceSession:
        """Get existing session or create new one"""
        if session_id not in self.sessions:
            return self._create_session(session_id)
        
        session = self.sessions[session_id]
        if session.is_expired(self.config.session_timeout_minutes):
            logger.info(f"Session {session_id} expired, creating new one")
            return self._create_session(session_id)
        
        return session
    
    def _cleanup_expired_sessions(self):
        """Remove expired sessions"""
        expired = [
            sid for sid, session in self.sessions.items()
            if session.is_expired(self.config.session_timeout_minutes)
        ]
        
        for session_id in expired:
            del self.sessions[session_id]
            logger.info(f"Cleaned up expired session: {session_id}")
    
    async def process_voice_request(
        self,
        audio_data: np.ndarray,
        session_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Process a single voice request through the pipeline
        Returns the AI response text
        """
        session_id = session_id or self.current_session_id
        session = self._get_or_create_session(session_id)
        
        start_time = time.time()
        self.total_requests += 1
        
        try:
            # Step 1: Speech-to-Text
            logger.info("Processing voice input...")
            self.broadcast_status("processing", {"phase": "stt"})
            
            stt_result = await self._transcribe_with_retry(audio_data)
            
            if not stt_result or not stt_result.get("text"):
                logger.warning("No speech detected or transcription failed")
                self.failed_requests += 1
                self.broadcast_status("idle", {"reason": "transcription_failed"})
                return None
            
            transcribed_text = stt_result["text"]
            confidence = stt_result.get("confidence", 0.0)
            detected_language = stt_result.get("language", "auto")
            
            # Block Turkish (Common Hallucination)
            if detected_language == "tr":
                logger.info("Ignored background noise (TR filter)")
                self.broadcast_status("idle", {"reason": "turkish_ignored"})
                return None
            
            # Check Low Confidence
            if confidence < 0.4:
                 logger.info(f"Ignored low confidence input ({confidence:.2f})")
                 self.broadcast_status("idle", {"reason": "low_confidence"})
                 return None
            
            # Check for Whisper Hallucinations
            if self._is_hallucination(transcribed_text):
                 logger.info("Ignored background noise (Hallucination filter)")
                 self.broadcast_status("idle", {"reason": "hallucination_ignored"})
                 return None

            logger.info(f"📝 Transcribed: '{transcribed_text}' (confidence={confidence:.2f})")
            self.broadcast_status("processing", {"phase": "llm", "text": transcribed_text})
            
            # Step 2: LLM Processing
            logger.info("Generating AI response...")
            conversation_request = ConversationRequest(
                user_input=transcribed_text,
                session_id=session_id
            )
            
            conversation_response = await conversation_engine.process_conversation(
                conversation_request
            )
            
            ai_response = conversation_response.content
            logger.info(f"💬 AI Response: '{ai_response[:100]}...'")
            
            # Step 3: Queue TTS response
            self.response_queue.put({
                "text": ai_response,
                "session_id": session_id
            })
            
            self.broadcast_status("speaking", {"text": ai_response})
            
            # Update session stats
            processing_time = time.time() - start_time
            session.update_activity()
            session.total_processing_time += processing_time
            
            self.successful_requests += 1
            logger.info(f"✅ Request processed in {processing_time:.2f}s")
            
            return ai_response
            
        except Exception as e:
            logger.error(f"Error processing voice request: {e}")
            self.failed_requests += 1
            
            # Speak error message
            error_message = "I encountered an error processing your request. Please try again."
            self.response_queue.put({
                "text": error_message,
                "session_id": session_id
            })
            self.broadcast_status("error", {"message": str(e)})
            
            return None
    
    async def _transcribe_with_retry(
        self,
        audio_data: np.ndarray,
        max_retries: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """Transcribe audio with retry logic"""
        max_retries = max_retries or self.config.max_retry_attempts
        
        for attempt in range(max_retries):
            try:
                result = self.stt.transcribe_audio(audio_data)
                
                # Check if transcription was successful
                if result.get("text"):
                    return result
                
                logger.warning(f"Empty transcription, attempt {attempt + 1}/{max_retries}")
                
            except Exception as e:
                logger.error(f"STT attempt {attempt + 1} failed: {e}")
                
                if attempt == max_retries - 1:
                    # Last attempt - try fallback to cloud if using local
                    if not self.config.stt_use_cloud and self.config.stt_api_key:
                        logger.info("Falling back to cloud STT...")
                        try:
                            fallback_stt = SpeechToText(
                                use_cloud=True,
                                api_key=self.config.stt_api_key
                            )
                            return fallback_stt.transcribe_audio(audio_data)
                        except Exception as fallback_error:
                            logger.error(f"Cloud fallback failed: {fallback_error}")
        
        return None
    
    def _tts_worker(self):
        """Background worker for TTS output queue"""
        logger.info("TTS worker started")
        
        while not self.stop_event.is_set():
            try:
                # Get response from queue with timeout
                response_data = self.response_queue.get(timeout=1.0)
                
                text = response_data.get("text")
                if text:
                    logger.info(f"🔊 Speaking: '{text[:50]}...'")
                    self.broadcast_status("speaking", {"text": text})
                    self.tts.speak(text, blocking=True)
                    self.broadcast_status("idle", {"reason": "speech_done"})
                
                self.response_queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                logger.error(f"TTS worker error: {e}")
        
        logger.info("TTS worker stopped")
    
    def _wake_word_callback(self):
        """Callback when wake word is detected"""
        logger.info("Wake word detected! Listening for command...")
        
        if self.tts:
            self.tts.stop()
            # Clear pending TTS queue
            while not self.response_queue.empty():
                try:
                    self.response_queue.get_nowait()
                    self.response_queue.task_done()
                except Empty:
                    break
        
        self.broadcast_status("listening", {"trigger": "wake_word"})
        
        # Record audio until silence
        try:
            if not self.audio_handler.stream:
                self.audio_handler.start_stream()
            
            audio_data = self.audio_handler.record_until_silence(
                max_duration_seconds=15,
                silence_duration_ms=800
            )
            
            if len(audio_data) > 0:
                self.broadcast_status("processing", {"phase": "transcribing"})
                # Process in async context
                asyncio.run(self.process_voice_request(audio_data))
            else:
                logger.warning("No audio captured after wake word")
                self.broadcast_status("idle", {"reason": "no_audio"})
        
        except Exception as e:
            logger.error(f"Error in wake word callback: {e}")
            self.broadcast_status("error", {"message": str(e)})
    
    def _pipeline_worker(self):
        """Main pipeline worker thread for continuous listening"""
        logger.info("Voice pipeline worker started")
        
        try:
            self.audio_handler.start_stream()
            
            if self.config.enable_continuous_mode:
                # Continuous wake word detection mode
                logger.info("Continuous listening mode enabled")
                self.wake_word_detector.listen_continuous(
                    on_wake_word=self._wake_word_callback,
                    on_error=lambda e: logger.error(f"Wake word error: {e}")
                )
            else:
                # Single detection mode (for testing)
                logger.info("Single detection mode")
                while not self.stop_event.is_set():
                    detected = self.wake_word_detector.listen_for_wake_word(
                        callback=self._wake_word_callback,
                        timeout_seconds=10
                    )
                    
                    if detected:
                        logger.info("Wake word detected and processed")
        
        except Exception as e:
            logger.error(f"Pipeline worker error: {e}")
        
        finally:
            self.audio_handler.stop_stream()
            logger.info("Voice pipeline worker stopped")
    
    def start(self):
        """Start the voice pipeline"""
        if self.is_running:
            logger.warning("Pipeline already running")
            return
        
        logger.info("=" * 60)
        logger.info("Starting Voice Pipeline")
        logger.info("=" * 60)
        
        # Initialize components if not already done
        if self.wake_word_detector is None:
            self.initialize()
        
        self.is_running = True
        self.stop_event.clear()
        
        # Start TTS worker thread
        self.tts_thread = Thread(target=self._tts_worker, daemon=True)
        self.tts_thread.start()
        
        # Start pipeline worker thread
        self.pipeline_thread = Thread(target=self._pipeline_worker, daemon=True)
        self.pipeline_thread.start()
        
        logger.info(f"✅ Voice Pipeline started successfully")
        logger.info(f"   Wake word: '{self.config.wake_word}'")
        logger.info(f"   Session timeout: {self.config.session_timeout_minutes} minutes")
        logger.info(f"   Continuous mode: {self.config.enable_continuous_mode}")
    
    def stop(self):
        """Stop the voice pipeline"""
        if not self.is_running:
            return
        
        logger.info("Stopping Voice Pipeline...")
        
        self.is_running = False
        self.stop_event.set()
        
        # Stop wake word detection
        if self.wake_word_detector:
            self.wake_word_detector.stop_listening()
        
        # Wait for threads to finish
        if self.pipeline_thread:
            self.pipeline_thread.join(timeout=5.0)
        
        if self.tts_thread:
            self.tts_thread.join(timeout=5.0)
        
        logger.info("Voice Pipeline stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics"""
        success_rate = (
            (self.successful_requests / self.total_requests * 100)
            if self.total_requests > 0
            else 0
        )
        
        return {
            "is_running": self.is_running,
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": success_rate,
            "active_sessions": len(self.sessions),
            "sessions": {
                sid: session.get_stats()
                for sid, session in self.sessions.items()
            }
        }
    
    def _is_hallucination(self, text: str) -> bool:
        """Check if text is a common Whisper hallucination"""
        hallucinations = [
            "This is a casual conversation",
            "Thank you for watching",
            "Please subscribe",
            "Subtitles by",
            "Amara.org",
            "MBC",
            "Bu videoyu",
            "izlediğiniz için",
            "teşekkürler"
        ]
        text_lower = text.lower()
        
        # Check known phrases
        if any(h.lower() in text_lower for h in hallucinations):
            return True
            
        # Check repetitive garbage
        if len(text) > 50 and len(set(text.split())) < 5:
            return True
            
        return False

    def cleanup(self):
        """Cleanup all resources"""
        self.stop()
        
        if self.wake_word_detector:
            self.wake_word_detector.cleanup()
        
        if self.stt:
            self.stt.cleanup()
        
        if self.tts:
            self.tts.cleanup()
        
        if self.audio_handler:
            self.audio_handler.cleanup()
        
        logger.info("Pipeline cleanup completed")
    
    def __enter__(self):
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


# Global pipeline instance
_pipeline_instance: Optional[VoicePipelineOrchestrator] = None


def get_pipeline(config: Optional[PipelineConfig] = None) -> VoicePipelineOrchestrator:
    """Get or create the global pipeline instance"""
    global _pipeline_instance
    
    if _pipeline_instance is None:
        _pipeline_instance = VoicePipelineOrchestrator(config)
    
    return _pipeline_instance
