import pytest
import json
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from src.personality.conversational_style import (
    ConversationalStyle,
    ResponseEnhancer,
    ToneType,
)
from src.personality.motivational_engine import (
    MotivationalEngine,
    MoodLevel,
    AchievementType,
)
from src.personality.humor_generator import HumorGenerator, HumorType
from src.config import settings


@pytest.fixture
def temp_data_path(tmp_path):
    data_path = tmp_path / "personality"
    data_path.mkdir(parents=True, exist_ok=True)
    return data_path


@pytest.fixture
def conversational_style(temp_data_path):
    return ConversationalStyle(data_path=temp_data_path)


@pytest.fixture
def response_enhancer():
    return ResponseEnhancer()


@pytest.fixture
def motivational_engine(temp_data_path):
    return MotivationalEngine(data_path=temp_data_path)


@pytest.fixture
def humor_generator(temp_data_path):
    return HumorGenerator(data_path=temp_data_path)


class TestConversationalStyle:
    def test_initialization(self, conversational_style):
        assert conversational_style is not None
        assert conversational_style.hindi_english_phrases is not None
        assert conversational_style.contextual_responses is not None
        assert conversational_style.emoji_map is not None
    
    def test_get_greeting(self, conversational_style):
        with patch.object(settings, 'personality_enable_hindi_english', True):
            greeting = conversational_style.get_greeting()
            assert greeting is not None
            assert len(greeting) > 0
    
    def test_get_confirmation(self, conversational_style):
        with patch.object(settings, 'personality_enable_hindi_english', True):
            confirmation = conversational_style.get_confirmation()
            assert confirmation is not None
            assert len(confirmation) > 0
    
    def test_get_contextual_response(self, conversational_style):
        with patch.object(settings, 'personality_enable_hindi_english', True):
            response = conversational_style.get_contextual_response(
                "bug_found",
                {"severity": "critical", "estimate": 1000}
            )
            assert response is not None
            assert "critical" in response or "bug" in response.lower()
    
    def test_add_emoji(self, conversational_style):
        with patch.object(settings, 'personality_emoji_enabled', True):
            text = "Great work"
            enhanced = conversational_style.add_emoji(text, context="success")
            assert len(enhanced) >= len(text)
    
    def test_hindi_english_phrases_persistence(self, temp_data_path):
        style1 = ConversationalStyle(data_path=temp_data_path)
        phrases_file = temp_data_path / "hindi_english_phrases.json"
        assert phrases_file.exists()
        
        style2 = ConversationalStyle(data_path=temp_data_path)
        assert style2.hindi_english_phrases == style1.hindi_english_phrases


class TestResponseEnhancer:
    def test_initialization(self, response_enhancer):
        assert response_enhancer is not None
        assert response_enhancer.style is not None
        assert response_enhancer.tone_patterns is not None
    
    def test_enhance_response_friendly(self, response_enhancer):
        with patch.object(settings, 'personality_enable_hindi_english', True):
            with patch.object(settings, 'personality_emoji_enabled', True):
                text = "The task is complete"
                enhanced = response_enhancer.enhance_response(
                    text,
                    tone=ToneType.FRIENDLY,
                    add_personality=True
                )
                assert enhanced is not None
                assert len(enhanced) > 0
    
    def test_enhance_response_professional(self, response_enhancer):
        text = "The analysis shows positive results"
        enhanced = response_enhancer.enhance_response(
            text,
            tone=ToneType.PROFESSIONAL,
            add_personality=True
        )
        assert enhanced is not None
    
    def test_enhance_response_casual(self, response_enhancer):
        with patch.object(settings, 'personality_enable_hindi_english', True):
            text = "Done with the work"
            enhanced = response_enhancer.enhance_response(
                text,
                tone=ToneType.CASUAL,
                add_personality=True
            )
            assert enhanced is not None
    
    def test_enhance_with_context(self, response_enhancer):
        with patch.object(settings, 'personality_enable_hindi_english', True):
            text = "Vulnerability detected"
            enhanced = response_enhancer.enhance_with_context(
                text,
                "bug_found",
                {"severity": "high", "estimate": 500}
            )
            assert enhanced is not None
            assert len(enhanced) >= len(text)
    
    def test_detect_emoji_context(self, response_enhancer):
        test_cases = [
            ("Bug found in the system", "security"),
            ("Task completed successfully", "success"),
            ("Error occurred during execution", "error"),
            ("Payment received", "money"),
        ]
        
        for text, expected_context in test_cases:
            context = response_enhancer._detect_emoji_context(text, None)
            assert context == expected_context or context == "positive"
    
    def test_no_personality_when_disabled(self, response_enhancer):
        original = "Test message"
        enhanced = response_enhancer.enhance_response(
            original,
            add_personality=False
        )
        assert enhanced == original


class TestMotivationalEngine:
    def test_initialization(self, motivational_engine):
        assert motivational_engine is not None
        assert motivational_engine.user_progress is not None
        assert motivational_engine.achievements is not None
    
    def test_get_encouragement(self, motivational_engine):
        with patch.object(settings, 'personality_motivational_enabled', True):
            encouragement = motivational_engine.get_encouragement("general")
            assert encouragement is not None
            assert len(encouragement) > 0
    
    def test_get_encouragement_with_variables(self, motivational_engine):
        with patch.object(settings, 'personality_motivational_enabled', True):
            encouragement = motivational_engine.get_encouragement(
                "task_progress",
                {"completed": 5, "total": 10, "tasks_remaining": 5}
            )
            assert encouragement is not None
    
    def test_celebrate_achievement_bug_found(self, motivational_engine):
        with patch.object(settings, 'personality_motivational_enabled', True):
            celebration = motivational_engine.celebrate_achievement(
                AchievementType.BUG_FOUND,
                {
                    "severity": "critical",
                    "estimated_bounty": 1000,
                    "vulnerability_type": "SQL Injection"
                }
            )
            assert celebration is not None
            assert len(celebration) > 0
            assert motivational_engine.user_progress["bugs_found"] > 0
    
    def test_celebrate_achievement_task_complete(self, motivational_engine):
        with patch.object(settings, 'personality_motivational_enabled', True):
            initial_count = motivational_engine.user_progress["completed_tasks"]
            celebration = motivational_engine.celebrate_achievement(
                AchievementType.TASK_COMPLETED,
                {"task_name": "Security Scan"}
            )
            assert celebration is not None
            assert motivational_engine.user_progress["completed_tasks"] == initial_count + 1
    
    def test_provide_support(self, motivational_engine):
        with patch.object(settings, 'personality_motivational_enabled', True):
            support = motivational_engine.provide_support("failure")
            assert support is not None
            assert len(support) > 0
    
    def test_update_streak(self, motivational_engine):
        initial_streak = motivational_engine.user_progress.get("streak_days", 0)
        streak = motivational_engine.update_streak()
        assert streak >= 0
    
    def test_track_mood(self, motivational_engine):
        motivational_engine.track_mood(MoodLevel.HIGH)
        assert len(motivational_engine.user_progress.get("mood_history", [])) > 0
    
    def test_get_mood_based_message(self, motivational_engine):
        with patch.object(settings, 'personality_motivational_enabled', True):
            message = motivational_engine.get_mood_based_message(MoodLevel.LOW)
            assert message is not None
            assert len(message) > 0
    
    def test_get_progress_summary(self, motivational_engine):
        summary = motivational_engine.get_progress_summary()
        assert summary is not None
        assert "total_tasks" in summary
        assert "completed_tasks" in summary
        assert "bugs_found" in summary
        assert "success_rate" in summary
    
    def test_progress_persistence(self, temp_data_path):
        engine1 = MotivationalEngine(data_path=temp_data_path)
        engine1.user_progress["bugs_found"] = 5
        engine1._save_user_progress()
        
        engine2 = MotivationalEngine(data_path=temp_data_path)
        assert engine2.user_progress["bugs_found"] == 5
    
    def test_no_motivation_when_disabled(self, motivational_engine):
        with patch.object(settings, 'personality_motivational_enabled', False):
            result = motivational_engine.get_encouragement()
            assert result is None


class TestHumorGenerator:
    def test_initialization(self, humor_generator):
        assert humor_generator is not None
        assert humor_generator.jokes_db is not None
        assert humor_generator.puns_db is not None
        assert humor_generator.contextual_humor is not None
    
    def test_get_joke(self, humor_generator):
        with patch.object(settings, 'personality_humor_enabled', True):
            humor_generator.last_joke_time = None
            joke = humor_generator.get_joke(HumorType.TECH)
            if joke:
                assert len(joke) > 0
    
    def test_get_pun(self, humor_generator):
        with patch.object(settings, 'personality_humor_enabled', True):
            humor_generator.last_joke_time = None
            pun = humor_generator.get_pun()
            if pun:
                assert len(pun) > 0
    
    def test_get_contextual_humor(self, humor_generator):
        with patch.object(settings, 'personality_humor_enabled', True):
            humor = humor_generator.get_contextual_humor("bug_found")
            if humor:
                assert len(humor) > 0
    
    def test_add_humor_to_response(self, humor_generator):
        with patch.object(settings, 'personality_humor_enabled', True):
            text = "Analysis complete"
            enhanced = humor_generator.add_humor_to_response(text, force_humor=True)
            assert enhanced is not None
    
    def test_get_tech_humor_for_topic(self, humor_generator):
        with patch.object(settings, 'personality_humor_enabled', True):
            humor_generator.last_joke_time = None
            humor = humor_generator.get_tech_humor_for_topic("python programming")
            if humor:
                assert "python" in humor.lower() or "code" in humor.lower()
    
    def test_get_timing_based_humor(self, humor_generator):
        with patch.object(settings, 'personality_humor_enabled', True):
            humor = humor_generator.get_timing_based_humor()
    
    def test_joke_interval_enforcement(self, humor_generator):
        with patch.object(settings, 'personality_humor_enabled', True):
            humor_generator.last_joke_time = datetime.now()
            should_add = humor_generator.should_add_humor()
            assert should_add is False
            
            humor_generator.last_joke_time = datetime.now() - timedelta(hours=1)
            should_add = humor_generator.should_add_humor()
    
    def test_no_humor_when_disabled(self, humor_generator):
        with patch.object(settings, 'personality_humor_enabled', False):
            result = humor_generator.get_joke()
            assert result is None
    
    def test_jokes_persistence(self, temp_data_path):
        generator1 = HumorGenerator(data_path=temp_data_path)
        jokes_file = temp_data_path / "jokes.json"
        assert jokes_file.exists()
        
        generator2 = HumorGenerator(data_path=temp_data_path)
        assert generator2.jokes_db == generator1.jokes_db


class TestIntegration:
    def test_full_personality_pipeline(
        self,
        response_enhancer,
        motivational_engine,
        humor_generator
    ):
        with patch.object(settings, 'personality_enable_hindi_english', True):
            with patch.object(settings, 'personality_emoji_enabled', True):
                with patch.object(settings, 'personality_motivational_enabled', True):
                    with patch.object(settings, 'personality_humor_enabled', True):
                        original = "Task completed successfully"
                        
                        enhanced = response_enhancer.enhance_response(
                            original,
                            tone=ToneType.FRIENDLY,
                            add_personality=True
                        )
                        
                        with_humor = humor_generator.add_humor_to_response(enhanced)
                        
                        celebration = motivational_engine.celebrate_achievement(
                            AchievementType.TASK_COMPLETED,
                            {"task_name": "Integration Test"}
                        )
                        
                        assert enhanced is not None
                        assert celebration is not None
    
    def test_personality_with_different_tones(self, response_enhancer):
        text = "The analysis is complete"
        
        tones = [
            ToneType.FRIENDLY,
            ToneType.PROFESSIONAL,
            ToneType.CASUAL,
            ToneType.MOTIVATIONAL,
            ToneType.HUMOROUS,
        ]
        
        for tone in tones:
            enhanced = response_enhancer.enhance_response(
                text,
                tone=tone,
                add_personality=True
            )
            assert enhanced is not None
    
    def test_contextual_personality_application(
        self,
        response_enhancer,
        motivational_engine,
        humor_generator
    ):
        with patch.object(settings, 'personality_enable_hindi_english', True):
            bug_text = "SQL injection vulnerability found"
            
            enhanced = response_enhancer.enhance_with_context(
                bug_text,
                "bug_found",
                {"severity": "critical", "estimate": 2000}
            )
            
            celebration = motivational_engine.celebrate_achievement(
                AchievementType.BUG_FOUND,
                {"severity": "critical", "estimated_bounty": 2000}
            )
            
            contextual_humor = humor_generator.get_contextual_humor("bug_found")
            
            assert enhanced is not None
            assert celebration is not None
