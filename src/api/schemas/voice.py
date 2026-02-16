from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class TranscribeRequest(BaseModel):
    language: Optional[str] = Field(None, description="Target language (auto-detect if None)")
    task: str = Field(default="transcribe", description="Task: transcribe or translate")


class TranscribeResponse(BaseModel):
    text: str
    language: Optional[str] = None
    confidence: float
    source: str


class SynthesizeRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Text to synthesize")
    voice: Optional[str] = Field(None, description="Voice: male, female, neutral")
    rate: Optional[int] = Field(None, ge=50, le=300, description="Speech rate")
    pitch: Optional[float] = Field(None, ge=0.5, le=2.0, description="Voice pitch")
    use_cache: bool = Field(default=True, description="Use TTS cache")


class SpeakResponse(BaseModel):
    status: str
    text: str
    audio_size_bytes: int


class WakeWordStatusResponse(BaseModel):
    listening: bool
    wake_word: str


class AudioDeviceInfo(BaseModel):
    index: int
    name: str
    sample_rate: int
    channels: int


class AudioDeviceListResponse(BaseModel):
    devices: List[AudioDeviceInfo]
    total: int


class STTModelInfo(BaseModel):
    name: str
    description: str
    size_mb: Optional[int] = None
    languages: Optional[int] = None


class STTModelsResponse(BaseModel):
    models: List[str]
    current: str


class LanguagesResponse(BaseModel):
    languages: Dict[str, str]
    total: int


class TTSVoiceInfo(BaseModel):
    id: str
    name: str
    gender: Optional[str] = None
    language: Optional[str] = None


class TTSVoicesResponse(BaseModel):
    voices: List[TTSVoiceInfo]
    total: int


class CacheStatsResponse(BaseModel):
    total_entries: int
    total_size_mb: float
    hit_rate: float
    cache_hits: int
    cache_misses: int
