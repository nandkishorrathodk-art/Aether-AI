"""
Integrated Voice-Activated Assistant

Combines wake word detection, speech-to-text, command processing, and text-to-speech
into a seamless voice interaction system.
"""

import asyncio
from typing import Optional, Callable, Dict, Any
from enum import Enum
from src.perception.voice.wake_word import SimpleWakeWordDetector
from src.perception.voice.stt import SpeechToText
from src.perception.voice.tts import TextToSpeech
from src.perception.voice.command_controller import VoiceCommandController
from src.perception.voice.audio_utils import AudioInputHandler
from src.utils.logger import get_logger


class AssistantState(Enum):
    """Voice assistant states"""
    IDLE = "idle"
    LISTENING_FOR_WAKE_WORD = "listening_for_wake_word"
    LISTENING_FOR_COMMAND = "listening_for_command"
    PROCESSING = "processing"
    RESPONDING = "responding"
    ERROR = "error"


class VoiceActivatedAssistant:
    """
    Complete voice-activated assistant
    
    Workflow:
    1. Listen for wake word ("Hey Aether", "Computer", etc.)
    2. Beep or say "Yes?" to acknowledge
    3. Listen for command (with auto-silence detection)
    4. Process command (determine intent and execute action)
    5. Speak response
    6. Return to listening for wake word
    
    Example:
        assistant = VoiceActivatedAssistant()
        assistant.start()
        # User: "Hey Aether"
        # Assistant: "Yes?"
        # User: "What's the weather today?"
        # Assistant: "Let me check... The weather today is..."
    """
    
    def __init__(
        self,
        wake_word: str = "jarvis",
        session_id: str = "default",
        on_state_change: Optional[Callable] = None,
        on_command: Optional[Callable] = None,
        on_response: Optional[Callable] = None
    ):
        """
        Initialize voice-activated assistant
        
        Args:
            wake_word: Wake word to listen for
            session_id: Conversation session ID
            on_state_change: Callback for state changes
            on_command: Callback when command received
            on_response: Callback when response generated
        """
        self.logger = get_logger(__name__)
        self.session_id = session_id
        self.wake_word = wake_word
        
        # Callbacks
        self.on_state_change = on_state_change
        self.on_command = on_command
        self.on_response = on_response
        
        # Components
        self.audio_input = AudioInputHandler()
        self.wake_word_detector = SimpleWakeWordDetector(wake_word=wake_word)
        self.stt = SpeechToText()
        self.tts = TextToSpeech()
        self.command_controller = VoiceCommandController()
        
        # State
        self.state = AssistantState.IDLE
        self.is_running = False
        self.wake_word_task = None
        
        # Stats
        self.stats = {
            "wake_word_detections": 0,
            "commands_processed": 0,
            "errors": 0,
            "total_interactions": 0
        }
        
        self.logger.info(f"Voice Assistant initialized with wake word: '{wake_word}'")
    
    def start(self):
        """Start the voice assistant"""
        if self.is_running:
            self.logger.warning("Assistant already running")
            return
        
        self.is_running = True
        self._change_state(AssistantState.LISTENING_FOR_WAKE_WORD)
        
        # Start wake word detection loop
        asyncio.create_task(self._wake_word_loop())
        
        self.logger.info("Voice Assistant started")
    
    def stop(self):
        """Stop the voice assistant"""
        self.is_running = False
        self._change_state(AssistantState.IDLE)
        self.logger.info("Voice Assistant stopped")
    
    async def _wake_word_loop(self):
        """Continuously listen for wake word"""
        while self.is_running:
            try:
                if self.state == AssistantState.LISTENING_FOR_WAKE_WORD:
                    # Listen for wake word
                    detected = await self._listen_for_wake_word()
                    
                    if detected:
                        self.stats["wake_word_detections"] += 1
                        self.stats["total_interactions"] += 1
                        
                        # Process interaction
                        await self._process_interaction()
                
                # Small delay to prevent CPU overload
                await asyncio.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in wake word loop: {e}")
                self.stats["errors"] += 1
                await asyncio.sleep(1)
    
    async def _listen_for_wake_word(self, timeout: float = 5.0) -> bool:
        """Listen for wake word with timeout"""
        try:
            # Record audio chunk
            audio_data = self.audio_input.record_audio_until_silence(
                timeout=timeout,
                silence_threshold=0.01,
                silence_duration=0.5
            )
            
            if audio_data is None or len(audio_data) == 0:
                return False
            
            # Check for wake word
            detected = self.wake_word_detector.detect_energy_based(audio_data)
            
            if detected:
                self.logger.info(f"Wake word '{self.wake_word}' detected!")
            
            return detected
            
        except Exception as e:
            self.logger.error(f"Error listening for wake word: {e}")
            return False
    
    async def _process_interaction(self):
        """Process a complete voice interaction"""
        try:
            # Acknowledge wake word
            self._change_state(AssistantState.PROCESSING)
            self.tts.speak("Yes?")
            
            # Listen for command
            self._change_state(AssistantState.LISTENING_FOR_COMMAND)
            command_text = await self._listen_for_command()
            
            if not command_text:
                self.tts.speak("Sorry, I didn't catch that.")
                self._change_state(AssistantState.LISTENING_FOR_WAKE_WORD)
                return
            
            self.logger.info(f"Command received: '{command_text}'")
            
            # Notify callback
            if self.on_command:
                self.on_command(command_text)
            
            # Process command
            self._change_state(AssistantState.PROCESSING)
            result = await self.command_controller.process_command(
                text=command_text,
                session_id=self.session_id
            )
            
            self.stats["commands_processed"] += 1
            
            # Get response
            response_text = result.get("response", "I'm not sure how to respond to that.")
            
            # Notify callback
            if self.on_response:
                self.on_response(response_text, result)
            
            # Speak response
            self._change_state(AssistantState.RESPONDING)
            self.tts.speak(response_text)
            
            # Return to listening
            self._change_state(AssistantState.LISTENING_FOR_WAKE_WORD)
            
        except Exception as e:
            self.logger.error(f"Error in interaction: {e}", exc_info=True)
            self.stats["errors"] += 1
            self._change_state(AssistantState.ERROR)
            
            # Apologize to user
            self.tts.speak("Sorry, I encountered an error.")
            
            # Return to listening
            await asyncio.sleep(1)
            self._change_state(AssistantState.LISTENING_FOR_WAKE_WORD)
    
    async def _listen_for_command(self, timeout: float = 10.0) -> Optional[str]:
        """Listen for voice command with silence detection"""
        try:
            # Record audio until silence
            audio_data = self.audio_input.record_audio_until_silence(
                timeout=timeout,
                silence_threshold=0.01,
                silence_duration=1.5  # Longer silence for command end
            )
            
            if audio_data is None or len(audio_data) == 0:
                return None
            
            # Transcribe audio to text
            result = self.stt.transcribe(audio_data)
            
            if not result["success"]:
                self.logger.warning(f"STT failed: {result.get('error')}")
                return None
            
            return result["text"]
            
        except Exception as e:
            self.logger.error(f"Error listening for command: {e}")
            return None
    
    def _change_state(self, new_state: AssistantState):
        """Change assistant state and notify callback"""
        if self.state != new_state:
            old_state = self.state
            self.state = new_state
            
            self.logger.debug(f"State changed: {old_state.value} -> {new_state.value}")
            
            if self.on_state_change:
                self.on_state_change(old_state, new_state)
    
    def get_state(self) -> AssistantState:
        """Get current assistant state"""
        return self.state
    
    def get_stats(self) -> Dict[str, Any]:
        """Get assistant statistics"""
        return {
            **self.stats,
            "state": self.state.value,
            "is_running": self.is_running,
            "session_id": self.session_id,
            "wake_word": self.wake_word
        }
    
    async def process_text_command(self, text: str) -> Dict[str, Any]:
        """
        Process a text command directly (bypass voice input)
        
        Useful for testing or text-based interfaces
        """
        result = await self.command_controller.process_command(
            text=text,
            session_id=self.session_id
        )
        
        response_text = result.get("response", "")
        self.tts.speak(response_text)
        
        return result


# Singleton instance for easy access
_assistant_instance: Optional[VoiceActivatedAssistant] = None


def get_assistant(wake_word: str = "jarvis") -> VoiceActivatedAssistant:
    """Get or create voice assistant singleton"""
    global _assistant_instance
    
    if _assistant_instance is None:
        _assistant_instance = VoiceActivatedAssistant(wake_word=wake_word)
    
    return _assistant_instance
