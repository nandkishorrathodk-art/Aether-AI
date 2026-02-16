import os
from pathlib import Path
from typing import Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        env_parse_none_str='none'
    )

    app_name: str = "Aether AI"
    app_version: str = "0.1.0"
    environment: str = "development"

    api_host: str = "127.0.0.1"
    api_port: int = 8000

    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    fireworks_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None

    ai_provider: str = "auto"
    default_model: str = "gpt-4-turbo-preview"
    fallback_provider: str = "groq"
    enable_cost_tracking: bool = True
    max_cost_per_day_usd: float = 10.0

    router_conversation: str = "groq"
    router_analysis: str = "anthropic"
    router_code: str = "groq"
    router_creative: str = "groq"
    router_fast: str = "groq"
    router_vision: str = "anthropic"
    router_reasoning: str = "fireworks"

    wake_word: str = "megumi"
    voice_input_enabled: bool = True
    voice_output_enabled: bool = True
    voice_gender: str = "male"
    voice_provider: str = "edge"
    tts_model: str = "tts-1"
    stt_model: str = "whisper-1"
    porcupine_api_key: Optional[str] = None

    chromadb_path: Path = Path("./data/chromadb")
    conversation_history_db: Path = Path("./data/conversations.db")
    max_context_messages: int = 10

    llm_temperature: float = 0.7
    llm_max_tokens: int = 2048
    llm_top_p: float = 0.9

    secret_key: str = "change-this-in-production"
    allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    
    def get_allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(',')]

    log_level: str = "INFO"
    log_file: Path = Path("./logs/aether.log")
    log_max_size_mb: int = 100
    log_backup_count: int = 5

    enable_automation: bool = True
    enable_analytics: bool = True
    enable_telemetry: bool = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._ensure_directories()

    def _ensure_directories(self):
        self.chromadb_path.parent.mkdir(parents=True, exist_ok=True)
        self.conversation_history_db.parent.mkdir(parents=True, exist_ok=True)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
