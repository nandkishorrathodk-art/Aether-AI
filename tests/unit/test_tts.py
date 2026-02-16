import pytest
import wave
import io
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import numpy as np

from src.perception.voice.tts import (
    TTSConfig,
    TTSCache,
    LocalTTS,
    CloudTTS,
    TextToSpeech
)
from src.perception.voice.output_queue import TTSOutputQueue, TTSRequest


@pytest.fixture
def temp_cache_dir(tmp_path):
    """Create temporary cache directory"""
    cache_dir = tmp_path / "tts_cache"
    cache_dir.mkdir()
    return str(cache_dir)


@pytest.fixture
def tts_config():
    """Create default TTS config"""
    return TTSConfig(
        provider="pyttsx3",
        voice="female",
        rate=175,
        cache_enabled=True
    )


@pytest.fixture
def tts_cache(temp_cache_dir):
    """Create TTS cache instance"""
    return TTSCache(cache_dir=temp_cache_dir, max_cache_size_mb=10)


class TestTTSConfig:
    """Test TTS configuration"""
    
    def test_default_config(self):
        config = TTSConfig()
        assert config.provider == "pyttsx3"
        assert config.voice == "female"
        assert config.rate == 175
        assert config.cache_enabled is True
    
    def test_custom_config(self):
        config = TTSConfig(
            provider="openai",
            voice="male",
            rate=200,
            pitch=1.2,
            cache_enabled=False
        )
        assert config.provider == "openai"
        assert config.voice == "male"
        assert config.rate == 200
        assert config.pitch == 1.2
        assert config.cache_enabled is False


class TestTTSCache:
    """Test TTS cache functionality"""
    
    def test_cache_initialization(self, tts_cache, temp_cache_dir):
        assert tts_cache.cache_dir == Path(temp_cache_dir)
        assert tts_cache.cache_dir.exists()
        assert tts_cache.metadata == {}
    
    def test_cache_key_generation(self, tts_cache, tts_config):
        key1 = tts_cache._get_cache_key("Hello world", tts_config)
        key2 = tts_cache._get_cache_key("Hello world", tts_config)
        key3 = tts_cache._get_cache_key("Different text", tts_config)
        
        assert key1 == key2
        assert key1 != key3
        assert len(key1) == 32
    
    def test_cache_put_and_get(self, tts_cache, tts_config):
        text = "Test phrase"
        audio_data = b"fake_audio_data"
        
        result = tts_cache.get(text, tts_config)
        assert result is None
        
        tts_cache.put(text, tts_config, audio_data)
        
        result = tts_cache.get(text, tts_config)
        assert result == audio_data
    
    def test_cache_hit_tracking(self, tts_cache, tts_config):
        text = "Test phrase"
        audio_data = b"fake_audio_data"
        
        tts_cache.put(text, tts_config, audio_data)
        cache_key = tts_cache._get_cache_key(text, tts_config)
        
        assert tts_cache.metadata[cache_key]['hits'] == 0
        
        tts_cache.get(text, tts_config)
        assert tts_cache.metadata[cache_key]['hits'] == 1
        
        tts_cache.get(text, tts_config)
        assert tts_cache.metadata[cache_key]['hits'] == 2
    
    def test_cache_disabled(self, tts_cache):
        config = TTSConfig(cache_enabled=False)
        text = "Test phrase"
        audio_data = b"fake_audio_data"
        
        tts_cache.put(text, config, audio_data)
        result = tts_cache.get(text, config)
        
        assert result is None
    
    def test_metadata_persistence(self, temp_cache_dir, tts_config):
        cache1 = TTSCache(cache_dir=temp_cache_dir)
        cache1.put("Test", tts_config, b"data")
        
        cache2 = TTSCache(cache_dir=temp_cache_dir)
        assert len(cache2.metadata) > 0


class TestLocalTTS:
    """Test local TTS with pyttsx3"""
    
    @patch('pyttsx3.init')
    def test_local_tts_initialization(self, mock_init, tts_config):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = LocalTTS(tts_config)
        
        assert tts.config == tts_config
        mock_init.assert_called_once()
    
    @patch('pyttsx3.init')
    def test_engine_configuration(self, mock_init, tts_config):
        mock_engine = MagicMock()
        mock_engine.getProperty.return_value = [
            MagicMock(name="Female voice", id="voice1"),
            MagicMock(name="Male voice", id="voice2")
        ]
        mock_init.return_value = mock_engine
        
        tts = LocalTTS(tts_config)
        
        mock_engine.setProperty.assert_any_call('rate', 175)
        mock_engine.setProperty.assert_any_call('volume', 0.9)
    
    @patch('pyttsx3.init')
    def test_get_available_voices(self, mock_init):
        mock_engine = MagicMock()
        mock_voice1 = MagicMock(id="v1", name="Voice 1", languages=["en"], gender="female")
        mock_voice2 = MagicMock(id="v2", name="Voice 2", languages=["en"], gender="male")
        mock_engine.getProperty.return_value = [mock_voice1, mock_voice2]
        mock_init.return_value = mock_engine
        
        tts = LocalTTS(TTSConfig())
        voices = tts.get_available_voices()
        
        assert len(voices) == 2
        assert voices[0]['id'] == "v1"
        assert voices[1]['gender'] == "male"


class TestCloudTTS:
    """Test cloud TTS with OpenAI"""
    
    def test_cloud_tts_initialization(self, tts_config):
        pytest.skip("OpenAI client initialization test - requires actual API")
    
    def test_cloud_synthesis(self):
        try:
            from openai import OpenAI
            with patch.object(OpenAI, '__init__', return_value=None):
                config = TTSConfig(provider="openai", voice="female")
                tts = CloudTTS(config, api_key="test_key")
                
                mock_response = MagicMock()
                mock_response.content = b"synthesized_audio"
                
                with patch.object(tts.client.audio.speech, 'create', return_value=mock_response) as mock_create:
                    result = tts.synthesize("Hello world")
                    
                    assert result == b"synthesized_audio"
                    mock_create.assert_called_once()
        except (ImportError, AttributeError):
            pytest.skip("OpenAI library not available or incompatible")
    
    def test_voice_mapping(self):
        pytest.skip("Voice mapping test requires OpenAI API - tested in integration")


class TestTextToSpeech:
    """Test main TTS interface"""
    
    @patch('pyttsx3.init')
    def test_tts_initialization_local(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        config = TTSConfig(provider="pyttsx3")
        tts = TextToSpeech(config=config)
        
        assert isinstance(tts.engine, LocalTTS)
        assert tts.config.provider == "pyttsx3"
    
    def test_empty_text_validation(self):
        tts = TextToSpeech()
        
        with pytest.raises(ValueError, match="Text cannot be empty"):
            tts.synthesize("")
        
        with pytest.raises(ValueError, match="Text cannot be empty"):
            tts.synthesize("   ")
    
    @patch('pyttsx3.init')
    @patch('os.remove')
    def test_synthesis_with_cache(self, mock_remove, mock_init, temp_cache_dir):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__ = Mock(return_value=io.BytesIO(b"audio_data"))
            
            config = TTSConfig(cache_enabled=True, cache_dir=temp_cache_dir)
            tts = TextToSpeech(config=config)
            
            with patch.object(tts.engine, 'synthesize', return_value=b"audio_data"):
                result1 = tts.synthesize("Test phrase")
                result2 = tts.synthesize("Test phrase")
                
                assert result1 == b"audio_data"
    
    @patch('pyttsx3.init')
    def test_config_update(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        
        tts.update_config(rate=200, voice="male")
        
        assert tts.config.rate == 200
        assert tts.config.voice == "male"
    
    @patch('pyttsx3.init')
    def test_cache_stats(self, mock_init, temp_cache_dir):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        config = TTSConfig(cache_dir=temp_cache_dir)
        tts = TextToSpeech(config=config)
        
        stats = tts.get_cache_stats()
        
        assert 'total_entries' in stats
        assert 'total_hits' in stats
        assert 'total_size_mb' in stats
        assert stats['cache_dir'] == str(Path(temp_cache_dir))
    
    @patch('pyttsx3.init')
    def test_clear_cache(self, mock_init, temp_cache_dir):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        config = TTSConfig(cache_dir=temp_cache_dir, cache_enabled=True)
        tts = TextToSpeech(config=config)
        
        tts.cache.put("Test", config, b"data")
        assert len(tts.cache.metadata) > 0
        
        tts.clear_cache()
        assert len(tts.cache.metadata) == 0
    
    @patch('pyttsx3.init')
    @patch('pyaudio.PyAudio')
    def test_audio_playback(self, mock_pyaudio, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        mock_audio = MagicMock()
        mock_stream = MagicMock()
        mock_audio.open.return_value = mock_stream
        mock_pyaudio.return_value = mock_audio
        
        audio_bytes = io.BytesIO()
        with wave.open(audio_bytes, 'wb') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(16000)
            wf.writeframes(b'\x00' * 1000)
        
        tts = TextToSpeech()
        tts._play_audio(audio_bytes.getvalue())
        
        mock_stream.write.assert_called()
        mock_stream.stop_stream.assert_called_once()
        mock_stream.close.assert_called_once()


class TestTTSOutputQueue:
    """Test TTS output queue management"""
    
    @patch('pyttsx3.init')
    def test_queue_initialization(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        queue = TTSOutputQueue(tts, max_queue_size=10)
        
        assert queue.max_queue_size == 10
        assert queue.running is False
        assert queue.requests_processed == 0
    
    @patch('pyttsx3.init')
    def test_queue_start_stop(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        queue = TTSOutputQueue(tts)
        
        queue.start()
        assert queue.running is True
        assert queue.worker_thread is not None
        
        queue.stop()
        assert queue.running is False
    
    @patch('pyttsx3.init')
    def test_add_request(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        queue = TTSOutputQueue(tts)
        
        result = queue.add("Test message", priority=5)
        
        assert result is True
        assert queue.queue.qsize() == 1
    
    @patch('pyttsx3.init')
    def test_priority_ordering(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        queue = TTSOutputQueue(tts)
        
        queue.add("Low priority", priority=10)
        queue.add("High priority", priority=1)
        queue.add("Medium priority", priority=5)
        
        request1 = queue.queue.get()
        request2 = queue.queue.get()
        request3 = queue.queue.get()
        
        assert request1.priority == 1
        assert request2.priority == 5
        assert request3.priority == 10
    
    @patch('pyttsx3.init')
    def test_queue_full_handling(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        queue = TTSOutputQueue(tts, max_queue_size=2)
        
        assert queue.add("Message 1") is True
        assert queue.add("Message 2") is True
        assert queue.add("Message 3", blocking=False) is False
    
    @patch('pyttsx3.init')
    def test_queue_clear(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        queue = TTSOutputQueue(tts)
        
        queue.add("Message 1")
        queue.add("Message 2")
        assert queue.queue.qsize() == 2
        
        queue.clear()
        assert queue.queue.qsize() == 0
    
    @patch('pyttsx3.init')
    def test_queue_stats(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        queue = TTSOutputQueue(tts, max_queue_size=50)
        
        queue.add("Test")
        stats = queue.get_stats()
        
        assert stats['queue_size'] == 1
        assert stats['max_queue_size'] == 50
        assert stats['running'] is False
    
    @patch('pyttsx3.init')
    def test_context_manager(self, mock_init):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        tts = TextToSpeech()
        
        with TTSOutputQueue(tts) as queue:
            assert queue.running is True
        
        assert queue.running is False


class TestTTSRequest:
    """Test TTS request dataclass"""
    
    def test_request_creation(self):
        request = TTSRequest(text="Test", priority=5)
        
        assert request.text == "Test"
        assert request.priority == 5
        assert request.callback is None
        assert request.timestamp is not None
    
    def test_request_priority_comparison(self):
        import time
        
        request1 = TTSRequest(text="Test 1", priority=5)
        time.sleep(0.01)
        request2 = TTSRequest(text="Test 2", priority=3)
        request3 = TTSRequest(text="Test 3", priority=5)
        
        assert request2 < request1
        assert request1 < request3


class TestIntegration:
    """Integration tests for TTS pipeline"""
    
    @patch('pyttsx3.init')
    @patch('pyaudio.PyAudio')
    def test_full_tts_pipeline(self, mock_pyaudio, mock_init, temp_cache_dir):
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        mock_audio = MagicMock()
        mock_stream = MagicMock()
        mock_audio.open.return_value = mock_stream
        mock_pyaudio.return_value = mock_audio
        
        config = TTSConfig(cache_dir=temp_cache_dir)
        tts = TextToSpeech(config=config)
        
        with patch.object(tts.engine, 'synthesize', return_value=b"audio_data"):
            result = tts.synthesize("Test phrase")
            assert result == b"audio_data"
            
            cached_result = tts.synthesize("Test phrase")
            assert cached_result == b"audio_data"
    
    @patch('pyttsx3.init')
    def test_tts_latency_target(self, mock_init, temp_cache_dir):
        """Test that cached synthesis meets < 1s latency target"""
        import time
        
        mock_engine = MagicMock()
        mock_init.return_value = mock_engine
        
        config = TTSConfig(cache_dir=temp_cache_dir)
        tts = TextToSpeech(config=config)
        
        with patch.object(tts.engine, 'synthesize', return_value=b"audio_data"):
            tts.synthesize("Test phrase for latency")
            
            start = time.time()
            tts.synthesize("Test phrase for latency")
            latency = time.time() - start
            
            assert latency < 1.0, f"Latency {latency}s exceeds 1s target"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
