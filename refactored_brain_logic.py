"""
Refactored Brain Logic - Production-Ready Async Architecture
Fixes: Blocking calls, Memory leaks, CoT integration, NPU acceleration
Target: <2s latency on Acer Swift Neo (16GB RAM, Intel NPU)
"""

import asyncio
import weakref
import time
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import deque
import numpy as np

from src.perception.voice.wake_word import WakeWordDetector
from src.perception.voice.stt import SpeechToText
from src.perception.voice.tts import TextToSpeech, TTSConfig
from src.perception.voice.audio_utils import AudioInputHandler
from src.cognitive.llm.inference import conversation_engine, ConversationRequest
from src.cognitive.reasoning.chain_of_thought import ChainOfThoughtReasoner
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class VoiceSession:
    """Memory-efficient session tracking with auto-expiry"""
    session_id: str
    started_at: datetime
    last_activity: datetime
    turn_count: int = 0
    total_processing_time: float = 0.0
    
    def is_expired(self, timeout_minutes: int = 5) -> bool:
        return datetime.now() - self.last_activity > timedelta(minutes=timeout_minutes)


class AsyncVoicePipeline:
    """
    Fully Asynchronous Voice Pipeline
    
    Fixes:
    1. No asyncio.run() blocking - pure async/await
    2. asyncio.Queue instead of Queue
    3. STT runs in executor thread pool
    4. Automatic session cleanup every 5 minutes
    5. Integrated Chain-of-Thought reasoning
    6. NPU-accelerated STT (OpenVINO backend)
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        
        self.audio_handler = AudioInputHandler()
        self.wake_word_detector: Optional[WakeWordDetector] = None
        self.stt: Optional[SpeechToText] = None
        self.tts: Optional[TextToSpeech] = None
        
        self.sessions: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self.current_session_id = "default"
        
        self.response_queue: asyncio.Queue = asyncio.Queue()
        
        self.is_running = False
        self._cleanup_task: Optional[asyncio.Task] = None
        self._tts_task: Optional[asyncio.Task] = None
        self._wake_word_task: Optional[asyncio.Task] = None
        
        self.cot_reasoner: Optional[ChainOfThoughtReasoner] = None
        
        self.total_requests = 0
        self.successful_requests = 0
        
        logger.info("✅ Async Voice Pipeline initialized")
    
    async def initialize(self):
        """Async initialization of all components"""
        try:
            self.wake_word_detector = WakeWordDetector(
                wake_word=self.config.get("wake_word", "hey aether"),
                sensitivity=self.config.get("wake_word_sensitivity", 0.5),
                audio_handler=self.audio_handler
            )
            
            use_openvino = self.config.get("use_openvino_npu", True)
            if use_openvino:
                try:
                    from src.perception.voice.stt_openvino import OpenVINOSTT
                    self.stt = OpenVINOSTT(
                        model_name=self.config.get("stt_model", "base"),
                        device="NPU"
                    )
                    logger.info("🚀 OpenVINO NPU STT initialized - Hardware acceleration enabled!")
                except ImportError:
                    logger.warning("OpenVINO not available, falling back to CPU Whisper")
                    self.stt = SpeechToText(
                        model_name=self.config.get("stt_model", "base"),
                        device="cpu"
                    )
            else:
                self.stt = SpeechToText(
                    model_name=self.config.get("stt_model", "base"),
                    device="cpu"
                )
            
            tts_config = TTSConfig(
                provider=self.config.get("tts_provider", "pyttsx3"),
                voice=self.config.get("tts_voice", "female")
            )
            self.tts = TextToSpeech(config=tts_config)
            
            self.cot_reasoner = ChainOfThoughtReasoner()
            
            self._create_session(self.current_session_id)
            
            logger.info("✅ All async components initialized")
            
        except Exception as e:
            logger.error(f"Async initialization failed: {e}")
            raise
    
    def _create_session(self, session_id: str) -> VoiceSession:
        """Create session with weak reference for auto-cleanup"""
        session = VoiceSession(
            session_id=session_id,
            started_at=datetime.now(),
            last_activity=datetime.now()
        )
        self.sessions[session_id] = session
        logger.info(f"Created session: {session_id}")
        return session
    
    async def _cleanup_expired_sessions_loop(self):
        """Automatic background cleanup every 5 minutes"""
        while self.is_running:
            await asyncio.sleep(300)
            
            expired = [
                sid for sid, session in list(self.sessions.items())
                if session.is_expired(timeout_minutes=5)
            ]
            
            for session_id in expired:
                if session_id in self.sessions:
                    del self.sessions[session_id]
                    logger.info(f"Auto-cleaned expired session: {session_id}")
    
    async def process_voice_request(
        self,
        audio_data: np.ndarray,
        session_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Fully async voice request processing with CoT reasoning
        """
        session_id = session_id or self.current_session_id
        session = self.sessions.get(session_id) or self._create_session(session_id)
        
        start_time = time.time()
        self.total_requests += 1
        
        try:
            logger.info("🎤 Processing voice input (async)...")
            
            stt_result = await asyncio.to_thread(
                self.stt.transcribe_audio,
                audio_data
            )
            
            if not stt_result or not stt_result.get("text"):
                logger.warning("STT failed or empty transcription")
                return None
            
            transcribed_text = stt_result["text"]
            confidence = stt_result.get("confidence", 0.0)
            detected_language = stt_result.get("language", "auto")
            
            if detected_language == "tr" or confidence < 0.4:
                logger.info(f"Filtered: lang={detected_language}, conf={confidence:.2f}")
                return None
            
            if self._is_hallucination(transcribed_text):
                logger.info("Filtered: hallucination detected")
                return None
            
            logger.info(f"📝 Transcribed: '{transcribed_text}' (confidence={confidence:.2f})")
            
            is_complex_task = self._is_complex_task(transcribed_text)
            
            if is_complex_task:
                logger.info("🧠 Complex task detected - Engaging Chain-of-Thought reasoning...")
                reasoning_result = self.cot_reasoner.reason(
                    problem=transcribed_text,
                    context={"session_id": session_id},
                    max_steps=5
                )
                
                logger.info(f"CoT Reasoning Path:\n{reasoning_result['reasoning_path']}")
                
                enhanced_prompt = f"""Original request: {transcribed_text}

My step-by-step analysis:
{reasoning_result['reasoning_path']}

Based on this reasoning, here's my response:"""
                
                conversation_request = ConversationRequest(
                    user_input=enhanced_prompt,
                    session_id=session_id
                )
            else:
                conversation_request = ConversationRequest(
                    user_input=transcribed_text,
                    session_id=session_id
                )
            
            logger.info("💬 Generating AI response...")
            conversation_response = await conversation_engine.process_conversation(
                conversation_request
            )
            
            ai_response = conversation_response.content
            logger.info(f"✅ AI Response: '{ai_response[:100]}...'")
            
            await self.response_queue.put({
                "text": ai_response,
                "session_id": session_id
            })
            
            processing_time = time.time() - start_time
            session.last_activity = datetime.now()
            session.turn_count += 1
            session.total_processing_time += processing_time
            
            self.successful_requests += 1
            logger.info(f"⚡ Processed in {processing_time:.2f}s")
            
            return ai_response
            
        except Exception as e:
            logger.error(f"Error in async voice request: {e}")
            error_message = "I encountered an error. Please try again."
            await self.response_queue.put({"text": error_message, "session_id": session_id})
            return None
    
    def _is_complex_task(self, text: str) -> bool:
        """Detect if task needs Chain-of-Thought reasoning"""
        complex_keywords = [
            "find all", "search for", "analyze", "summarize", "compare",
            "explain how", "step by step", "calculate", "plan", "schedule",
            "multiple", "both", "all", "every"
        ]
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in complex_keywords)
    
    def _is_hallucination(self, text: str) -> bool:
        """Detect Whisper hallucinations"""
        hallucinations = [
            "This is a casual conversation",
            "Thank you for watching",
            "Please subscribe",
            "Subtitles by",
            "Amara.org"
        ]
        text_lower = text.lower()
        return any(h.lower() in text_lower for h in hallucinations)
    
    async def _tts_worker(self):
        """Async TTS worker"""
        logger.info("TTS worker started")
        
        while self.is_running:
            try:
                response_data = await asyncio.wait_for(
                    self.response_queue.get(),
                    timeout=1.0
                )
                
                text = response_data.get("text")
                if text:
                    logger.info(f"🔊 Speaking: '{text[:50]}...'")
                    await asyncio.to_thread(self.tts.speak, text, blocking=True)
                
                self.response_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"TTS worker error: {e}")
        
        logger.info("TTS worker stopped")
    
    async def _wake_word_loop(self):
        """Async wake word detection loop"""
        logger.info("Wake word loop started")
        
        def wake_word_callback():
            logger.info("🎯 Wake word detected!")
            
            if self.tts:
                self.tts.stop()
            
            try:
                if not self.audio_handler.stream:
                    self.audio_handler.start_stream()
                
                audio_data = self.audio_handler.record_until_silence(
                    max_duration_seconds=15,
                    silence_duration_ms=800
                )
                
                if len(audio_data) > 0:
                    asyncio.create_task(self.process_voice_request(audio_data))
                else:
                    logger.warning("No audio captured after wake word")
            
            except Exception as e:
                logger.error(f"Error in wake word callback: {e}")
        
        try:
            self.audio_handler.start_stream()
            
            await asyncio.to_thread(
                self.wake_word_detector.listen_continuous,
                on_wake_word=wake_word_callback,
                on_error=lambda e: logger.error(f"Wake word error: {e}")
            )
        
        except Exception as e:
            logger.error(f"Wake word loop error: {e}")
        finally:
            self.audio_handler.stop_stream()
            logger.info("Wake word loop stopped")
    
    async def start(self):
        """Start the async pipeline"""
        if self.is_running:
            logger.warning("Pipeline already running")
            return
        
        logger.info("=" * 60)
        logger.info("🚀 Starting Async Voice Pipeline")
        logger.info("=" * 60)
        
        if self.wake_word_detector is None:
            await self.initialize()
        
        self.is_running = True
        
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_sessions_loop())
        self._tts_task = asyncio.create_task(self._tts_worker())
        self._wake_word_task = asyncio.create_task(self._wake_word_loop())
        
        logger.info("✅ Async Voice Pipeline started")
        logger.info("   Wake word: 'hey aether'")
        logger.info("   Session auto-cleanup: Every 5 minutes")
        logger.info("   CoT reasoning: Enabled for complex tasks")
    
    async def stop(self):
        """Stop the async pipeline"""
        if not self.is_running:
            return
        
        logger.info("🛑 Stopping Async Pipeline...")
        
        self.is_running = False
        
        if self.wake_word_detector:
            self.wake_word_detector.stop_listening()
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._tts_task:
            self._tts_task.cancel()
        if self._wake_word_task:
            self._wake_word_task.cancel()
        
        logger.info("✅ Async Pipeline stopped")
    
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
            "success_rate": success_rate,
            "active_sessions": len(self.sessions)
        }


async def main():
    """Example usage"""
    pipeline = AsyncVoicePipeline(config={
        "wake_word": "hey aether",
        "wake_word_sensitivity": 0.5,
        "stt_model": "base",
        "use_openvino_npu": True,
        "tts_provider": "pyttsx3",
        "tts_voice": "female"
    })
    
    await pipeline.start()
    
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await pipeline.stop()


if __name__ == "__main__":
    asyncio.run(main())
