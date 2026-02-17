import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.config import Settings


class TestConfigV090:
    def test_default_values(self):
        settings = Settings()
        
        assert settings.app_name == "Aether AI"
        assert settings.app_version == "0.9.0"
        assert settings.environment == "development"
        assert settings.api_host == "127.0.0.1"
        assert settings.api_port == 8000
    
    def test_screen_monitoring_defaults(self):
        settings = Settings()
        
        assert settings.enable_screen_monitoring == False
        assert settings.screen_capture_interval == 30
        assert settings.screen_monitor_save_screenshots == False
        assert isinstance(settings.screen_monitor_data_path, Path)
    
    def test_proactive_mode_defaults(self):
        settings = Settings()
        
        assert settings.enable_proactive_mode == True
        assert settings.proactive_check_interval == 1800
        assert settings.proactive_morning_greeting == True
        assert settings.proactive_daily_planning == True
        assert settings.proactive_suggestion_types == "bug_bounty,youtube,breaks,learning"
    
    def test_proactive_suggestion_types_parsing(self):
        settings = Settings()
        
        suggestion_types = settings.get_proactive_suggestion_types()
        assert isinstance(suggestion_types, list)
        assert "bug_bounty" in suggestion_types
        assert "youtube" in suggestion_types
        assert "breaks" in suggestion_types
        assert "learning" in suggestion_types
        assert len(suggestion_types) == 4
    
    def test_pc_control_defaults(self):
        settings = Settings()
        
        assert settings.enable_pc_control == False
        assert settings.pc_control_require_confirmation == True
        assert settings.pc_control_allowed_actions == "mouse_click,keyboard_type,app_launch"
        assert isinstance(settings.pc_control_audit_log, Path)
    
    def test_pc_control_allowed_actions_parsing(self):
        settings = Settings()
        
        allowed_actions = settings.get_pc_control_allowed_actions()
        assert isinstance(allowed_actions, list)
        assert "mouse_click" in allowed_actions
        assert "keyboard_type" in allowed_actions
        assert "app_launch" in allowed_actions
        assert len(allowed_actions) == 3
    
    def test_bugbounty_autopilot_defaults(self):
        settings = Settings()
        
        assert settings.enable_bugbounty_autopilot == False
        assert settings.burpsuite_api_url == "http://127.0.0.1:1337"
        assert settings.burpsuite_api_key is None
        assert settings.bugbounty_auto_scan == False
        assert settings.bugbounty_target_programs == "apple,google,microsoft"
        assert isinstance(settings.bugbounty_report_path, Path)
    
    def test_bugbounty_target_programs_parsing(self):
        settings = Settings()
        
        target_programs = settings.get_bugbounty_target_programs()
        assert isinstance(target_programs, list)
        assert "apple" in target_programs
        assert "google" in target_programs
        assert "microsoft" in target_programs
        assert len(target_programs) == 3
    
    def test_personality_defaults(self):
        settings = Settings()
        
        assert settings.personality_mode == "friendly"
        assert settings.personality_enable_hindi_english == True
        assert settings.personality_emoji_enabled == True
        assert settings.personality_motivational_enabled == True
        assert settings.personality_humor_enabled == True
    
    def test_daily_intelligence_defaults(self):
        settings = Settings()
        
        assert settings.enable_daily_reports == True
        assert settings.daily_report_time == "20:00"
        assert isinstance(settings.daily_report_path, Path)
        assert settings.enable_trend_analysis == True
        assert settings.enable_wealth_tracking == True
    
    def test_allowed_origins_parsing(self):
        settings = Settings()
        
        origins = settings.get_allowed_origins()
        assert isinstance(origins, list)
        assert len(origins) >= 2
        assert "http://localhost:3000" in origins
    
    def test_directories_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            test_env = {
                "CHROMADB_PATH": f"{tmpdir}/chromadb",
                "CONVERSATION_HISTORY_DB": f"{tmpdir}/conversations.db",
                "LOG_FILE": f"{tmpdir}/logs/test.log",
                "SCREEN_MONITOR_DATA_PATH": f"{tmpdir}/monitoring",
                "PC_CONTROL_AUDIT_LOG": f"{tmpdir}/audit.log",
                "BUGBOUNTY_REPORT_PATH": f"{tmpdir}/reports",
                "DAILY_REPORT_PATH": f"{tmpdir}/daily",
            }
            
            with patch.dict(os.environ, test_env, clear=False):
                settings = Settings()
                
                assert settings.chromadb_path.parent.exists()
                assert settings.log_file.parent.exists()
                assert settings.screen_monitor_data_path.exists()
                assert settings.pc_control_audit_log.parent.exists()
                assert settings.bugbounty_report_path.exists()
                assert settings.daily_report_path.exists()
    
    def test_config_from_env_vars(self):
        test_env = {
            "ENABLE_SCREEN_MONITORING": "true",
            "SCREEN_CAPTURE_INTERVAL": "60",
            "ENABLE_PROACTIVE_MODE": "false",
            "ENABLE_PC_CONTROL": "true",
            "PERSONALITY_MODE": "professional",
            "BURPSUITE_API_KEY": "test-api-key-123",
        }
        
        with patch.dict(os.environ, test_env, clear=False):
            settings = Settings()
            
            assert settings.enable_screen_monitoring == True
            assert settings.screen_capture_interval == 60
            assert settings.enable_proactive_mode == False
            assert settings.enable_pc_control == True
            assert settings.personality_mode == "professional"
            assert settings.burpsuite_api_key == "test-api-key-123"
    
    def test_custom_suggestion_types(self):
        test_env = {
            "PROACTIVE_SUGGESTION_TYPES": "custom1,custom2,custom3"
        }
        
        with patch.dict(os.environ, test_env, clear=False):
            settings = Settings()
            suggestion_types = settings.get_proactive_suggestion_types()
            
            assert len(suggestion_types) == 3
            assert "custom1" in suggestion_types
            assert "custom2" in suggestion_types
            assert "custom3" in suggestion_types
    
    def test_custom_allowed_actions(self):
        test_env = {
            "PC_CONTROL_ALLOWED_ACTIONS": "action1,action2"
        }
        
        with patch.dict(os.environ, test_env, clear=False):
            settings = Settings()
            actions = settings.get_pc_control_allowed_actions()
            
            assert len(actions) == 2
            assert "action1" in actions
            assert "action2" in actions
    
    def test_custom_target_programs(self):
        test_env = {
            "BUGBOUNTY_TARGET_PROGRAMS": "program1,program2,program3,program4"
        }
        
        with patch.dict(os.environ, test_env, clear=False):
            settings = Settings()
            programs = settings.get_bugbounty_target_programs()
            
            assert len(programs) == 4
            assert "program1" in programs
            assert "program4" in programs
    
    def test_path_types(self):
        settings = Settings()
        
        assert isinstance(settings.chromadb_path, Path)
        assert isinstance(settings.conversation_history_db, Path)
        assert isinstance(settings.log_file, Path)
        assert isinstance(settings.screen_monitor_data_path, Path)
        assert isinstance(settings.pc_control_audit_log, Path)
        assert isinstance(settings.bugbounty_report_path, Path)
        assert isinstance(settings.daily_report_path, Path)
    
    def test_ai_provider_settings(self):
        settings = Settings()
        
        assert settings.ai_provider == "auto"
        assert settings.fallback_provider == "groq"
        assert settings.enable_cost_tracking == True
        assert settings.max_cost_per_day_usd == 10.0
    
    def test_voice_settings(self):
        settings = Settings()
        
        assert settings.voice_input_enabled == True
        assert settings.voice_output_enabled == True
        assert settings.wake_word == "megumi"
    
    def test_feature_flags(self):
        settings = Settings()
        
        assert settings.enable_automation == True
        assert settings.enable_analytics == True
        assert settings.enable_telemetry == False
