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
    app_version: str = "3.0.0"
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

    secret_key: Optional[str] = None  # MUST be set in .env for production
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

    # v0.9.0 - Screen Monitoring Settings
    enable_screen_monitoring: bool = False
    screen_capture_interval: int = 30
    screen_monitor_save_screenshots: bool = False
    screen_monitor_data_path: Path = Path("./data/monitoring")
    
    # v0.9.0 - Proactive AI Settings
    enable_proactive_mode: bool = True
    proactive_check_interval: int = 1800
    proactive_morning_greeting: bool = True
    proactive_daily_planning: bool = True
    proactive_suggestion_types: str = "bug_bounty,youtube,breaks,learning"
    
    def get_proactive_suggestion_types(self) -> list[str]:
        return [s.strip() for s in self.proactive_suggestion_types.split(',')]
    
    # v0.9.0 - PC Control Settings
    enable_pc_control: bool = False
    pc_control_require_confirmation: bool = True
    pc_control_allowed_actions: str = "mouse_click,keyboard_type,app_launch"
    pc_control_audit_log: Path = Path("./data/control_audit.log")
    
    def get_pc_control_allowed_actions(self) -> list[str]:
        return [a.strip() for a in self.pc_control_allowed_actions.split(',')]
    
    # v0.9.0 - Bug Bounty Autopilot Settings
    enable_bugbounty_autopilot: bool = False
    burpsuite_api_url: str = "http://127.0.0.1:1337"
    burpsuite_api_key: Optional[str] = None
    bugbounty_auto_scan: bool = False
    bugbounty_target_programs: str = "apple,google,microsoft"
    bugbounty_report_path: Path = Path("./data/bugbounty_reports")
    
    def get_bugbounty_target_programs(self) -> list[str]:
        return [p.strip() for p in self.bugbounty_target_programs.split(',')]
    
    # v1.0.0 - Bug Bounty Platform API Credentials
    hackerone_username: Optional[str] = None
    hackerone_api_token: Optional[str] = None
    bugcrowd_email: Optional[str] = None
    bugcrowd_api_key: Optional[str] = None
    intigriti_api_token: Optional[str] = None
    yeswehack_api_token: Optional[str] = None
    
    # v0.9.0 - Personality & Language Settings
    personality_mode: str = "friendly"
    personality_enable_hindi_english: bool = True
    personality_emoji_enabled: bool = True
    personality_motivational_enabled: bool = True
    personality_humor_enabled: bool = True
    
    # v0.9.0 - Daily Intelligence Settings
    enable_daily_reports: bool = True
    daily_report_time: str = "20:00"
    daily_report_path: Path = Path("./data/daily_reports")
    enable_trend_analysis: bool = True
    enable_wealth_tracking: bool = True
    
    # v2.0.0 - Autonomous Mode Security Settings
    enable_autonomous_mode: bool = False  # MUST explicitly enable
    autonomous_require_auth: bool = True  # Require API key for autonomous operations
    autonomous_allowed_targets: str = ""  # Comma-separated whitelist (empty = validate only)
    autonomous_max_duration: int = 8  # Max hours for autonomous operation
    
    # v1.0.0 - Self-Improvement & Learning Settings
    enable_self_improvement: bool = True
    self_improvement_schedule: str = "daily"  # daily, weekly, manual
    self_improvement_time: str = "03:00"  # 3 AM
    enable_user_learning: bool = True
    enable_performance_monitoring: bool = True
    performance_metrics_interval: int = 300  # seconds (5 minutes)
    auto_apply_safe_improvements: bool = True
    require_approval_for_major_changes: bool = True
    improvement_backup_retention_days: int = 30

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._validate_security()
        self._ensure_directories()
    
    def _validate_security(self):
        """Validate security-critical settings"""
        import os
        import secrets
        
        # Ensure secret_key is set
        if not self.secret_key:
            # Try environment variable first
            self.secret_key = os.getenv("AETHER_SECRET_KEY")
            
            if not self.secret_key:
                if self.environment == "production":
                    raise ValueError(
                        "CRITICAL: AETHER_SECRET_KEY must be set in production! "
                        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
                    )
                else:
                    # Development only - generate random key
                    self.secret_key = secrets.token_urlsafe(32)
                    print(f"⚠️ WARNING: Using auto-generated secret key for development")
        
        # Warn if autonomous mode enabled without auth
        if self.enable_autonomous_mode and not self.autonomous_require_auth:
            print("⚠️ WARNING: Autonomous mode enabled without authentication! This is dangerous!")

    def _ensure_directories(self):
        self.chromadb_path.parent.mkdir(parents=True, exist_ok=True)
        self.conversation_history_db.parent.mkdir(parents=True, exist_ok=True)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.screen_monitor_data_path.mkdir(parents=True, exist_ok=True)
        self.pc_control_audit_log.parent.mkdir(parents=True, exist_ok=True)
        self.bugbounty_report_path.mkdir(parents=True, exist_ok=True)
        self.daily_report_path.mkdir(parents=True, exist_ok=True)
        Path("./data/improvements").mkdir(parents=True, exist_ok=True)
        Path("./data/backups").mkdir(parents=True, exist_ok=True)
        Path("./data/user_learning").mkdir(parents=True, exist_ok=True)


settings = Settings()
