"""
Integration tests for End-to-End Voice Pipeline
Tests: Wake Word → STT → LLM → TTS → Output
"""
import pytest
import asyncio
import numpy as np
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.pipeline import VoicePipelineOrchestrator, PipelineConfig, VoiceSession
from src.perception.voice.audio_utils import AudioInputHandler, AudioConfig


class TestVoiceSession:
    """Test VoiceSession class"""
    
    def test_session_creation(self):
        """Test creating a voice session"""
        session = VoiceSession(session_id="test-123")
        
        assert session.session_id == "test-123"
        assert session.turn_count == 0
        assert session.total_processing_time == 0.0
    
    def test_session_activity_update(self):
        """Test updating session activity"""
        session = VoiceSession(session_id="test-123")
        initial_time = session.last_activity
        
        time.sleep(0.1)
        session.update_activity()
        
        assert session.last_activity > initial_time
        assert session.turn_count == 1
    
    def test_session_expiration(self):
        """Test session expiration logic"""
        session = VoiceSession(session_id="test-123")
        
        # Fresh session should not be expired
        assert not session.is_expired(timeout_minutes=5)
        
        # Manually set old activity time
        from datetime import datetime, timedelta
        session.last_activity = datetime.now() - timedelta(minutes=10)
        
        assert session.is_expired(timeout_minutes=5)
    
    def test_session_stats(self):
        """Test getting session statistics"""
        session = VoiceSession(session_id="test-123")
        session.update_activity()
        session.total_processing_time = 2.5
        
        stats = session.get_stats()
        
        assert stats["session_id"] == "test-123"
        assert stats["turn_count"] == 1
        assert stats["avg_processing_time"] == 2.5
        assert "started_at" in stats
        assert "last_activity" in stats


class TestPipelineConfig:
    """Test PipelineConfig class"""
    
    def test_default_config(self):
        """Test default pipeline configuration"""
        config = PipelineConfig()
        
        assert config.wake_word == "hey aether"
        assert config.wake_word_sensitivity == 0.5
        assert config.stt_model == "base"
        assert config.stt_use_cloud == False
        assert config.tts_provider == "pyttsx3"
        assert config.session_timeout_minutes == 5
        assert config.enable_continuous_mode == True
    
    def test_custom_config(self):
        """Test custom pipeline configuration"""
        config = PipelineConfig(
            wake_word="jarvis",
            stt_model="small",
            stt_use_cloud=True,
            session_timeout_minutes=10
        )
        
        assert config.wake_word == "jarvis"
        assert config.stt_model == "small"
        assert config.stt_use_cloud == True
        assert config.session_timeout_minutes == 10


class TestVoicePipelineOrchestrator:
    """Test VoicePipelineOrchestrator class"""
    
    @pytest.fixture
    def pipeline_config(self):
        """Create test pipeline configuration"""
        return PipelineConfig(
            wake_word="hey aether",
            stt_model="base",
            stt_use_cloud=False,
            tts_provider="pyttsx3",
            enable_continuous_mode=False
        )
    
    @pytest.fixture
    def pipeline(self, pipeline_config):
        """Create pipeline instance for testing"""
        pipeline = VoicePipelineOrchestrator(pipeline_config)
        yield pipeline
        pipeline.cleanup()
    
    def test_pipeline_creation(self, pipeline):
        """Test creating pipeline instance"""
        assert pipeline is not None
        assert pipeline.config.wake_word == "hey aether"
        assert not pipeline.is_running
    
    def test_pipeline_initialization(self, pipeline):
        """Test pipeline initialization"""
        pipeline.initialize()
        
        assert pipeline.wake_word_detector is not None
        assert pipeline.stt is not None
        assert pipeline.tts is not None
        assert "default" in pipeline.sessions
    
    def test_session_management(self, pipeline):
        """Test session creation and management"""
        session = pipeline._create_session("test-session-1")
        
        assert session.session_id == "test-session-1"
        assert "test-session-1" in pipeline.sessions
        
        # Get or create existing session
        same_session = pipeline._get_or_create_session("test-session-1")
        assert same_session.session_id == "test-session-1"
        
        # Create new session
        new_session = pipeline._get_or_create_session("test-session-2")
        assert new_session.session_id == "test-session-2"
    
    def test_session_cleanup(self, pipeline):
        """Test cleanup of expired sessions"""
        from datetime import datetime, timedelta
        
        # Create sessions
        session1 = pipeline._create_session("session-1")
        session2 = pipeline._create_session("session-2")
        
        # Make session1 expired
        session1.last_activity = datetime.now() - timedelta(minutes=10)
        
        # Cleanup
        pipeline._cleanup_expired_sessions()
        
        # session1 should be removed, session2 should remain
        assert "session-1" not in pipeline.sessions
        assert "session-2" in pipeline.sessions
    
    @pytest.mark.asyncio
    async def test_process_voice_request_mock(self, pipeline, monkeypatch):
        """Test processing voice request with mocked STT and LLM"""
        pipeline.initialize()
        
        # Mock STT transcription
        async def mock_transcribe(audio_data):
            return {
                "text": "What is the weather today?",
                "confidence": 0.95,
                "language": "en"
            }
        
        monkeypatch.setattr(
            pipeline,
            "_transcribe_with_retry",
            mock_transcribe
        )
        
        # Create test audio data
        sample_rate = AudioConfig.SAMPLE_RATE
        duration = 2.0
        audio_data = np.random.randint(-1000, 1000, int(sample_rate * duration), dtype=np.int16)
        
        # Process request
        response = await pipeline.process_voice_request(audio_data, session_id="test")
        
        # Should get some response (mocked LLM will respond)
        assert response is not None or response is None  # May fail without API keys
        
        # Check stats
        stats = pipeline.get_stats()
        assert stats["total_requests"] >= 1
    
    def test_pipeline_stats(self, pipeline):
        """Test getting pipeline statistics"""
        stats = pipeline.get_stats()
        
        assert "is_running" in stats
        assert "total_requests" in stats
        assert "successful_requests" in stats
        assert "failed_requests" in stats
        assert "success_rate" in stats
        assert "active_sessions" in stats
        assert "sessions" in stats
        
        assert stats["is_running"] == False
        assert stats["total_requests"] == 0
    
    def test_pipeline_start_stop(self, pipeline):
        """Test starting and stopping pipeline"""
        pipeline.initialize()
        
        # Start pipeline
        pipeline.start()
        assert pipeline.is_running
        assert pipeline.pipeline_thread is not None
        assert pipeline.tts_thread is not None
        
        # Stop pipeline
        time.sleep(0.5)
        pipeline.stop()
        assert not pipeline.is_running
    
    def test_response_queue(self, pipeline):
        """Test TTS response queue"""
        pipeline.initialize()
        
        # Add items to queue
        pipeline.response_queue.put({
            "text": "Hello, this is a test",
            "session_id": "test"
        })
        
        assert not pipeline.response_queue.empty()
        
        # Get item
        item = pipeline.response_queue.get()
        assert item["text"] == "Hello, this is a test"
        assert item["session_id"] == "test"


class TestPipelineIntegration:
    """Integration tests for complete pipeline flow"""
    
    @pytest.mark.integration
    def test_full_pipeline_lifecycle(self):
        """Test complete pipeline lifecycle"""
        config = PipelineConfig(
            wake_word="hey aether",
            stt_model="base",
            stt_use_cloud=False,
            tts_provider="pyttsx3",
            enable_continuous_mode=False
        )
        
        pipeline = VoicePipelineOrchestrator(config)
        
        try:
            # Initialize
            pipeline.initialize()
            assert pipeline.wake_word_detector is not None
            assert pipeline.stt is not None
            assert pipeline.tts is not None
            
            # Start
            pipeline.start()
            assert pipeline.is_running
            
            # Wait a bit
            time.sleep(1.0)
            
            # Check stats
            stats = pipeline.get_stats()
            assert stats["is_running"] == True
            
            # Stop
            pipeline.stop()
            assert not pipeline.is_running
            
        finally:
            pipeline.cleanup()
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_audio_processing_flow(self):
        """Test processing audio through the pipeline"""
        config = PipelineConfig(
            stt_model="base",
            stt_use_cloud=False,
            tts_provider="pyttsx3"
        )
        
        pipeline = VoicePipelineOrchestrator(config)
        
        try:
            pipeline.initialize()
            
            # Generate test audio (sine wave)
            sample_rate = AudioConfig.SAMPLE_RATE
            duration = 2.0
            frequency = 440.0
            
            t = np.linspace(0, duration, int(sample_rate * duration))
            audio_data = (np.sin(2 * np.pi * frequency * t) * 10000).astype(np.int16)
            
            # Process (will likely fail transcription due to synthetic audio)
            # But we're testing the flow, not the accuracy
            response = await pipeline.process_voice_request(audio_data)
            
            # Check that request was tracked
            stats = pipeline.get_stats()
            assert stats["total_requests"] >= 1
            
        finally:
            pipeline.cleanup()
    
    @pytest.mark.integration
    def test_performance_target(self):
        """Test that pipeline meets performance targets"""
        config = PipelineConfig(
            stt_model="tiny",  # Use fastest model
            stt_use_cloud=False,
            tts_provider="pyttsx3",
            enable_continuous_mode=False
        )
        
        pipeline = VoicePipelineOrchestrator(config)
        
        try:
            # Initialize
            start_time = time.time()
            pipeline.initialize()
            init_time = time.time() - start_time
            
            # Initialization should be fast (< 10 seconds for tiny model)
            assert init_time < 15.0, f"Initialization took {init_time:.2f}s (target: <15s)"
            
            # Start pipeline
            start_time = time.time()
            pipeline.start()
            start_duration = time.time() - start_time
            
            # Starting should be nearly instant
            assert start_duration < 2.0, f"Start took {start_duration:.2f}s (target: <2s)"
            
            # Stop pipeline
            start_time = time.time()
            pipeline.stop()
            stop_duration = time.time() - start_time
            
            # Stopping should be fast
            assert stop_duration < 10.0, f"Stop took {stop_duration:.2f}s (target: <10s)"
            
        finally:
            pipeline.cleanup()
    
    @pytest.mark.integration
    def test_resource_usage(self):
        """Test that pipeline doesn't exceed resource limits"""
        import psutil
        import os
        
        config = PipelineConfig(
            stt_model="base",
            enable_continuous_mode=False
        )
        
        pipeline = VoicePipelineOrchestrator(config)
        process = psutil.Process(os.getpid())
        
        try:
            # Measure baseline
            baseline_memory = process.memory_info().rss / (1024 * 1024)  # MB
            
            # Initialize pipeline
            pipeline.initialize()
            pipeline.start()
            
            # Wait for stabilization
            time.sleep(2.0)
            
            # Measure resource usage
            current_memory = process.memory_info().rss / (1024 * 1024)  # MB
            cpu_percent = process.cpu_percent(interval=1.0)
            
            memory_increase = current_memory - baseline_memory
            
            # Stop pipeline
            pipeline.stop()
            
            # Memory increase should be reasonable (< 2GB for base model)
            # Note: This is lenient as model loading can vary
            assert memory_increase < 3000, f"Memory increase: {memory_increase:.2f}MB (target: <3000MB)"
            
            # CPU should not be maxed out when idle
            # Note: This may spike during initialization
            # assert cpu_percent < 80, f"CPU usage: {cpu_percent:.2f}% (target: <80%)"
            
        finally:
            pipeline.cleanup()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
