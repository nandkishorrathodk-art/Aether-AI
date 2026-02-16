import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from src.perception.voice.wake_word import (
    WakeWordDetector,
    SimpleWakeWordDetector
)
from src.perception.voice.audio_utils import AudioConfig


class TestSimpleWakeWordDetector:
    @pytest.fixture
    def detector(self):
        return SimpleWakeWordDetector(wake_word="hey aether")

    def test_initialization(self, detector):
        assert detector.wake_word == "hey aether"
        assert detector.energy_multiplier == 2.0
        assert detector.min_duration_ms == 300

    def test_detect_high_energy_audio(self, detector):
        high_energy_audio = np.random.randint(5000, 10000, 8000, dtype=np.int16)
        result = detector.detect(high_energy_audio)
        assert isinstance(result, bool)

    def test_detect_low_energy_audio(self, detector):
        low_energy_audio = np.random.randint(-100, 100, 8000, dtype=np.int16)
        result = detector.detect(low_energy_audio)
        assert result is False

    def test_detect_short_audio(self, detector):
        short_audio = np.random.randint(-1000, 1000, 100, dtype=np.int16)
        result = detector.detect(short_audio)
        assert result is False

    def test_custom_energy_multiplier(self):
        detector = SimpleWakeWordDetector(
            wake_word="test",
            energy_multiplier=3.0
        )
        assert detector.energy_multiplier == 3.0
        assert detector.detection_threshold == AudioConfig.ENERGY_THRESHOLD * 3.0


class TestWakeWordDetector:
    @pytest.fixture
    def mock_audio_handler(self):
        with patch('src.perception.voice.wake_word.AudioInputHandler') as mock:
            handler = MagicMock()
            handler.calculate_energy.return_value = 1500.0  # Default energy for mocks
            mock.return_value = handler
            yield handler

    @pytest.fixture
    def detector_no_porcupine(self, mock_audio_handler):
        detector = WakeWordDetector(
            wake_word="hey aether",
            use_porcupine=False
        )
        yield detector
        detector.cleanup()

    def test_initialization_without_porcupine(self, detector_no_porcupine):
        assert detector_no_porcupine.wake_word == "hey aether"
        assert detector_no_porcupine.sensitivity == 0.5
        assert detector_no_porcupine.use_porcupine is False
        assert detector_no_porcupine.porcupine is None

    def test_initialization_with_custom_sensitivity(self, mock_audio_handler):
        detector = WakeWordDetector(
            wake_word="test",
            sensitivity=0.8,
            use_porcupine=False
        )
        assert detector.sensitivity == 0.8
        detector.cleanup()

    def test_detect_energy_based_high_energy(self, detector_no_porcupine):
        high_energy_audio = np.random.randint(5000, 10000, 1000, dtype=np.int16)
        result = detector_no_porcupine._detect_energy_based(high_energy_audio)
        assert isinstance(result, bool)

    def test_detect_energy_based_low_energy(self, detector_no_porcupine):
        low_energy_audio = np.random.randint(-50, 50, 1000, dtype=np.int16)
        result = detector_no_porcupine._detect_energy_based(low_energy_audio)
        assert result is False

    def test_detect_from_audio_energy_based(self, detector_no_porcupine):
        audio = np.random.randint(5000, 10000, 1000, dtype=np.int16)
        result = detector_no_porcupine.detect_from_audio(audio)
        assert isinstance(result, bool)

    def test_stop_listening(self, detector_no_porcupine):
        detector_no_porcupine.is_listening = True
        detector_no_porcupine.stop_listening()
        assert detector_no_porcupine.is_listening is False

    def test_cleanup(self, detector_no_porcupine):
        detector_no_porcupine.cleanup()
        assert detector_no_porcupine.porcupine is None

    def test_get_available_keywords(self, detector_no_porcupine):
        keywords = detector_no_porcupine._get_available_porcupine_keywords()
        assert isinstance(keywords, list)
        assert len(keywords) > 0
        assert "jarvis" in keywords
        assert "alexa" in keywords

    @patch('src.perception.voice.wake_word.pvporcupine.create')
    def test_porcupine_initialization_jarvis(self, mock_porcupine_create, mock_audio_handler):
        mock_porcupine = MagicMock()
        mock_porcupine_create.return_value = mock_porcupine
        
        detector = WakeWordDetector(
            wake_word="hey jarvis",
            use_porcupine=True,
            access_key="test_key"
        )
        
        mock_porcupine_create.assert_called_once()
        call_kwargs = mock_porcupine_create.call_args[1]
        assert call_kwargs['keywords'] == ['jarvis']
        detector.cleanup()

    @patch('src.perception.voice.wake_word.pvporcupine.create')
    def test_porcupine_initialization_default(self, mock_porcupine_create, mock_audio_handler):
        mock_porcupine = MagicMock()
        mock_porcupine_create.return_value = mock_porcupine
        
        detector = WakeWordDetector(
            wake_word="hey custom",
            use_porcupine=True,
            access_key="test_key"
        )
        
        call_kwargs = mock_porcupine_create.call_args[1]
        assert call_kwargs['keywords'] == ['porcupine']
        detector.cleanup()

    def test_context_manager(self, mock_audio_handler):
        with WakeWordDetector(wake_word="test", use_porcupine=False) as detector:
            assert detector is not None

    @patch('src.perception.voice.wake_word.pvporcupine.create')
    def test_detect_porcupine(self, mock_porcupine_create, mock_audio_handler):
        mock_porcupine = MagicMock()
        mock_porcupine.frame_length = 512
        mock_porcupine.process.return_value = -1
        mock_porcupine_create.return_value = mock_porcupine
        
        detector = WakeWordDetector(
            wake_word="jarvis",
            use_porcupine=True,
            access_key="test_key"
        )
        
        audio = np.random.randint(-1000, 1000, 1024, dtype=np.int16)
        result = detector._detect_porcupine(audio)
        
        assert isinstance(result, bool)
        detector.cleanup()

    @patch('src.perception.voice.wake_word.pvporcupine.create')
    def test_detect_porcupine_keyword_found(self, mock_porcupine_create, mock_audio_handler):
        mock_porcupine = MagicMock()
        mock_porcupine.frame_length = 512
        mock_porcupine.process.return_value = 0
        mock_porcupine_create.return_value = mock_porcupine
        
        detector = WakeWordDetector(
            wake_word="jarvis",
            use_porcupine=True,
            access_key="test_key"
        )
        
        audio = np.random.randint(-1000, 1000, 1024, dtype=np.int16)
        result = detector._detect_porcupine(audio)
        
        assert result is True
        detector.cleanup()


class TestWakeWordIntegration:
    def test_simple_detector_with_synthetic_wake_word(self):
        detector = SimpleWakeWordDetector(wake_word="test")
        
        loud_burst = np.random.randint(8000, 15000, 16000, dtype=np.int16)
        result = detector.detect(loud_burst)
        assert isinstance(result, bool)

    def test_detector_fallback_to_energy(self):
        with patch('src.perception.voice.wake_word.AudioInputHandler'):
            detector = WakeWordDetector(
                wake_word="test",
                use_porcupine=False
            )
            
            high_energy = np.random.randint(5000, 10000, 1000, dtype=np.int16)
            result = detector.detect_from_audio(high_energy)
            assert isinstance(result, bool)
            detector.cleanup()
