import pytest
import numpy as np
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from src.perception.voice.stt import (
    SpeechToText,
    STTConfig
)


class TestSTTConfig:
    def test_whisper_models_exist(self):
        assert "tiny" in STTConfig.WHISPER_MODELS
        assert "base" in STTConfig.WHISPER_MODELS
        assert "small" in STTConfig.WHISPER_MODELS
        assert "medium" in STTConfig.WHISPER_MODELS
        assert "large" in STTConfig.WHISPER_MODELS

    def test_model_properties(self):
        tiny_model = STTConfig.WHISPER_MODELS["tiny"]
        assert "size_mb" in tiny_model
        assert "speed" in tiny_model
        assert "accuracy" in tiny_model

    def test_recommended_model_low_ram(self):
        model = STTConfig.get_recommended_model(ram_gb=3, has_gpu=False)
        assert model == "tiny"

    def test_recommended_model_medium_ram(self):
        model = STTConfig.get_recommended_model(ram_gb=6, has_gpu=False)
        assert model == "base"

    def test_recommended_model_high_ram_no_gpu(self):
        model = STTConfig.get_recommended_model(ram_gb=12, has_gpu=False)
        assert model == "small"

    def test_recommended_model_with_gpu(self):
        model = STTConfig.get_recommended_model(ram_gb=20, has_gpu=True)
        assert model == "large-v3"


class TestSpeechToTextCloud:
    @pytest.fixture
    def mock_openai_client(self):
        with patch('src.perception.voice.stt.OpenAI') as mock:
            client = MagicMock()
            mock.return_value = client
            yield client

    @pytest.fixture
    def stt_cloud(self, mock_openai_client):
        return SpeechToText(
            model_name="whisper-1",
            use_cloud=True,
            api_key="test_key"
        )

    def test_initialization_cloud(self, stt_cloud):
        assert stt_cloud.use_cloud is True
        assert stt_cloud.client is not None
        assert stt_cloud.model is None

    def test_initialization_cloud_no_key(self):
        with pytest.raises(ValueError, match="API key required"):
            SpeechToText(use_cloud=True, api_key=None)

    def test_empty_result(self, stt_cloud):
        result = stt_cloud._empty_result()
        assert result["text"] == ""
        assert result["confidence"] == 0.0
        assert result["source"] == "cloud"

    def test_empty_result_with_error(self, stt_cloud):
        result = stt_cloud._empty_result(error="test error")
        assert "error" in result
        assert result["error"] == "test error"

    def test_transcribe_empty_array(self, stt_cloud):
        empty_audio = np.array([], dtype=np.int16)
        result = stt_cloud.transcribe_audio(empty_audio)
        assert result["text"] == ""
        assert result["confidence"] == 0.0

    @patch('builtins.open', create=True)
    def test_transcribe_cloud_from_file(self, mock_open, stt_cloud, mock_openai_client):
        mock_response = MagicMock()
        mock_response.text = "Hello world"
        mock_openai_client.audio.transcriptions.create.return_value = mock_response
        
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = stt_cloud._transcribe_cloud_from_file("test.wav", language="en")
        
        assert result["text"] == "Hello world"
        assert result["source"] == "cloud"
        assert result["language"] == "en"

    def test_get_available_models(self, stt_cloud):
        models = stt_cloud.get_available_models()
        assert isinstance(models, list)
        assert "tiny" in models
        assert "base" in models
        assert "large-v3" in models

    def test_get_supported_languages(self, stt_cloud):
        languages = stt_cloud.get_supported_languages()
        assert isinstance(languages, list)
        assert "en" in languages
        assert "es" in languages
        assert "fr" in languages
        assert "zh" in languages


class TestSpeechToTextLocal:
    @pytest.fixture
    def mock_whisper_model(self):
        with patch('src.perception.voice.stt.whisper.load_model') as mock:
            model = MagicMock()
            mock.return_value = model
            yield model

    @pytest.fixture
    def stt_local(self, mock_whisper_model):
        return SpeechToText(
            model_name="base",
            use_cloud=False,
            device="cpu"
        )

    def test_initialization_local(self, stt_local, mock_whisper_model):
        assert stt_local.use_cloud is False
        assert stt_local.client is None
        assert stt_local.model is not None

    def test_transcribe_local(self, stt_local, mock_whisper_model):
        mock_whisper_model.transcribe.return_value = {
            "text": "Test transcription",
            "language": "en",
            "segments": [
                {"avg_logprob": -0.5, "text": "Test transcription"}
            ]
        }
        
        audio = np.random.randn(16000).astype(np.float32)
        result = stt_local._transcribe_local(
            audio,
            language="en",
            task="transcribe",
            temperature=0.0,
            best_of=5,
            beam_size=5
        )
        
        assert result["text"] == "Test transcription"
        assert result["language"] == "en"
        assert result["source"] == "local"
        assert result["confidence"] > 0

    def test_calculate_confidence_with_segments(self, stt_local):
        result = {
            "segments": [
                {"avg_logprob": -0.1},
                {"avg_logprob": -0.2},
                {"avg_logprob": -0.3}
            ]
        }
        confidence = stt_local._calculate_confidence(result)
        assert 0.0 <= confidence <= 1.0

    def test_calculate_confidence_no_segments(self, stt_local):
        result = {"segments": []}
        confidence = stt_local._calculate_confidence(result)
        assert confidence == 0.5

    def test_calculate_confidence_with_no_speech_prob(self, stt_local):
        result = {
            "segments": [
                {"no_speech_prob": 0.1},
                {"no_speech_prob": 0.2}
            ]
        }
        confidence = stt_local._calculate_confidence(result)
        assert 0.0 <= confidence <= 1.0

    @patch('src.perception.voice.stt.AudioInputHandler')
    def test_transcribe_realtime(self, mock_audio_handler, stt_local, mock_whisper_model):
        mock_handler = MagicMock()
        mock_handler.read_audio.return_value = np.random.randint(-1000, 1000, 16000, dtype=np.int16)
        mock_audio_handler.return_value = mock_handler
        
        mock_whisper_model.transcribe.return_value = {
            "text": "Real-time test",
            "language": "en",
            "segments": []
        }
        
        result = stt_local.transcribe_realtime(mock_handler, duration_seconds=1.0)
        
        assert result["text"] == "Real-time test"
        mock_handler.read_audio.assert_called_once_with(1.0)

    @patch('src.perception.voice.stt.AudioInputHandler')
    def test_transcribe_until_silence(self, mock_audio_handler, stt_local, mock_whisper_model):
        mock_handler = MagicMock()
        mock_handler.record_until_silence.return_value = np.random.randint(-1000, 1000, 16000, dtype=np.int16)
        mock_audio_handler.return_value = mock_handler
        
        mock_whisper_model.transcribe.return_value = {
            "text": "Silence test",
            "language": "en",
            "segments": []
        }
        
        result = stt_local.transcribe_until_silence(mock_handler)
        
        assert result["text"] == "Silence test"
        mock_handler.record_until_silence.assert_called_once()

    def test_transcribe_invalid_type(self, stt_local):
        with pytest.raises(ValueError, match="audio_data must be"):
            stt_local.transcribe_audio(12345)

    def test_cleanup(self, stt_local):
        stt_local.cleanup()
        assert stt_local.model is None


class TestSpeechToTextIntegration:
    @patch('src.perception.voice.stt.whisper.load_model')
    def test_transcribe_numpy_array(self, mock_load_model):
        mock_model = MagicMock()
        mock_model.transcribe.return_value = {
            "text": "Integration test",
            "language": "en",
            "segments": [{"avg_logprob": -0.3}]
        }
        mock_load_model.return_value = mock_model
        
        stt = SpeechToText(model_name="base", use_cloud=False)
        audio = np.random.randint(-1000, 1000, 16000, dtype=np.int16)
        
        result = stt.transcribe_audio(audio)
        
        assert result["text"] == "Integration test"
        assert result["confidence"] > 0
        stt.cleanup()

    @patch('src.perception.voice.stt.whisper.load_model')
    @patch('src.perception.voice.stt.whisper.load_audio')
    @patch('os.path.exists')
    def test_transcribe_from_file(self, mock_exists, mock_load_audio, mock_load_model):
        mock_exists.return_value = True
        mock_load_audio.return_value = np.random.randn(16000).astype(np.float32)
        
        mock_model = MagicMock()
        mock_model.transcribe.return_value = {
            "text": "File test",
            "language": "en",
            "segments": []
        }
        mock_load_model.return_value = mock_model
        
        stt = SpeechToText(model_name="base", use_cloud=False)
        result = stt.transcribe_audio("test.wav")
        
        assert result["text"] == "File test"
        stt.cleanup()

    @patch('src.perception.voice.stt.whisper.load_model')
    def test_transcribe_file_not_found(self, mock_load_model):
        mock_model = MagicMock()
        mock_load_model.return_value = mock_model
        
        stt = SpeechToText(model_name="base", use_cloud=False)
        
        with pytest.raises(FileNotFoundError):
            stt.transcribe_audio("nonexistent.wav")
        
        stt.cleanup()

    @patch('src.perception.voice.stt.whisper.load_model')
    def test_language_specification(self, mock_load_model):
        mock_model = MagicMock()
        mock_model.transcribe.return_value = {
            "text": "Hola mundo",
            "language": "es",
            "segments": []
        }
        mock_load_model.return_value = mock_model
        
        stt = SpeechToText(model_name="base", use_cloud=False, language="es")
        audio = np.random.randint(-1000, 1000, 16000, dtype=np.int16)
        
        result = stt.transcribe_audio(audio)
        
        assert result["language"] == "es"
        stt.cleanup()

    @patch('src.perception.voice.stt.whisper.load_model')
    def test_transcribe_with_custom_parameters(self, mock_load_model):
        mock_model = MagicMock()
        mock_model.transcribe.return_value = {
            "text": "Custom params",
            "language": "en",
            "segments": []
        }
        mock_load_model.return_value = mock_model
        
        stt = SpeechToText(model_name="base", use_cloud=False)
        audio = np.random.randint(-1000, 1000, 16000, dtype=np.int16)
        
        result = stt.transcribe_audio(
            audio,
            language="en",
            task="translate",
            temperature=0.5,
            best_of=3,
            beam_size=3
        )
        
        assert result["text"] == "Custom params"
        
        call_kwargs = mock_model.transcribe.call_args[1]
        assert call_kwargs["task"] == "translate"
        assert call_kwargs["temperature"] == 0.5
        
        stt.cleanup()
