from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class VoiceSettings(BaseModel):
    wake_word: str = Field(default="jarvis", description="Wake word for activation")
    stt_provider: str = Field(default="local", description="STT provider: local or openai")
    stt_model: str = Field(default="base", description="STT model name")
    stt_language: Optional[str] = Field(default=None, description="Target language for STT")
    tts_provider: str = Field(default="pyttsx3", description="TTS provider: pyttsx3 or openai")
    tts_voice: str = Field(default="female", description="TTS voice: male, female, neutral")
    tts_rate: int = Field(default=175, ge=50, le=300, description="TTS speech rate")
    tts_volume: float = Field(default=1.0, ge=0.0, le=1.0, description="TTS volume")


class AISettings(BaseModel):
    default_provider: Optional[str] = Field(default=None, description="Default AI provider")
    default_model: Optional[str] = Field(default=None, description="Default AI model")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="Temperature")
    max_tokens: int = Field(default=1000, ge=1, le=4096, description="Max tokens")
    context_window: int = Field(default=10, ge=1, le=50, description="Conversation history size")


class MemorySettings(BaseModel):
    enable_memory: bool = Field(default=True, description="Enable long-term memory")
    auto_embed: bool = Field(default=True, description="Auto-embed important info")
    memory_retention_days: int = Field(default=90, ge=1, le=365, description="Memory retention period")


class SystemSettings(BaseModel):
    auto_launch: bool = Field(default=False, description="Launch on system startup")
    minimize_to_tray: bool = Field(default=True, description="Minimize to system tray")
    log_level: str = Field(default="INFO", description="Log level: DEBUG, INFO, WARNING, ERROR")
    api_host: str = Field(default="127.0.0.1", description="API server host")
    api_port: int = Field(default=8000, ge=1024, le=65535, description="API server port")


class Settings(BaseModel):
    voice: VoiceSettings = Field(default_factory=VoiceSettings)
    ai: AISettings = Field(default_factory=AISettings)
    memory: MemorySettings = Field(default_factory=MemorySettings)
    system: SystemSettings = Field(default_factory=SystemSettings)
    custom: Dict[str, Any] = Field(default_factory=dict, description="Custom user settings")


class SettingsUpdateRequest(BaseModel):
    voice: Optional[VoiceSettings] = None
    ai: Optional[AISettings] = None
    memory: Optional[MemorySettings] = None
    system: Optional[SystemSettings] = None
    custom: Optional[Dict[str, Any]] = None


class SettingsResponse(BaseModel):
    settings: Settings
    last_updated: Optional[str] = None
