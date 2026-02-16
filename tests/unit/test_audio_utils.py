import pytest
import numpy as np
from unittest.mock import Mock, patch, MagicMock
from src.perception.voice.audio_utils import (
    AudioInputHandler,
    AudioConfig
)


class TestAudioConfig:
    def test_config_values(self):
        assert AudioConfig.SAMPLE_RATE == 16000
        assert AudioConfig.CHANNELS == 1
        assert AudioConfig.CHUNK_SIZE == 1024
        assert AudioConfig.FRAME_DURATION_MS == 30
        assert AudioConfig.VAD_MODE == 3
        assert AudioConfig.ENERGY_THRESHOLD == 500
        assert AudioConfig.SILENCE_DURATION_MS == 1500


class TestAudioInputHandler:
    @pytest.fixture
    def audio_handler(self):
        with patch('pyaudio.PyAudio') as mock_pyaudio_class:
            mock_pyaudio_instance = MagicMock()
            mock_pyaudio_class.return_value = mock_pyaudio_instance
            # Set the return value for get_sample_size to match AudioConfig.FORMAT (paInt16 is 2 bytes)
            mock_pyaudio_instance.get_sample_size.return_value = 2
            
            handler = AudioInputHandler()
            yield handler
            handler.cleanup()

    def test_initialization(self, audio_handler):
        assert audio_handler.sample_rate == AudioConfig.SAMPLE_RATE
        assert audio_handler.channels == AudioConfig.CHANNELS
        assert audio_handler.chunk_size == AudioConfig.CHUNK_SIZE
        assert audio_handler.vad_enabled is True
        assert audio_handler.stream is None
        assert audio_handler.is_recording is False

    def test_initialization_without_vad(self):
        with patch('pyaudio.PyAudio'):
            handler = AudioInputHandler(vad_enabled=False)
            assert handler.vad is None
            handler.cleanup()

    def test_calculate_energy(self):
        audio_data = np.array([100, 200, 300, 400, 500], dtype=np.int16)
        energy = AudioInputHandler.calculate_energy(audio_data)
        assert isinstance(energy, float)
        assert energy > 0

    def test_calculate_energy_silent(self):
        silent_audio = np.zeros(1000, dtype=np.int16)
        energy = AudioInputHandler.calculate_energy(silent_audio)
        assert energy == 0.0

    def test_normalize_audio(self):
        audio_data = np.array([100, 200, 300], dtype=np.int16)
        normalized = AudioInputHandler.normalize_audio(audio_data)
        assert normalized.dtype == np.int16
        assert len(normalized) == len(audio_data)
        assert np.max(np.abs(normalized)) <= 32767

    def test_normalize_audio_silent(self):
        silent_audio = np.zeros(100, dtype=np.int16)
        normalized = AudioInputHandler.normalize_audio(silent_audio)
        assert np.all(normalized == 0)

    def test_apply_noise_reduction(self):
        noisy_audio = np.random.randint(-1000, 1000, 1000, dtype=np.int16)
        reduced = AudioInputHandler.apply_noise_reduction(noisy_audio)
        assert len(reduced) == len(noisy_audio)
        assert reduced.dtype == noisy_audio.dtype

    def test_apply_noise_reduction_short_audio(self):
        short_audio = np.array([10, 20, 30], dtype=np.int16)
        reduced = AudioInputHandler.apply_noise_reduction(short_audio)
        assert np.array_equal(reduced, short_audio)

    def test_is_speech_with_high_energy(self, audio_handler):
        high_energy_audio = np.random.randint(1000, 5000, 1000, dtype=np.int16)
        result = audio_handler.is_speech(high_energy_audio)
        assert isinstance(result, bool)

    def test_is_silence_with_low_energy(self, audio_handler):
        low_energy_audio = np.random.randint(-50, 50, 1000, dtype=np.int16)
        result = audio_handler.is_silence(low_energy_audio)
        assert isinstance(result, bool)

    def test_audio_to_bytes(self, audio_handler):
        audio_data = np.random.randint(-1000, 1000, 1000, dtype=np.int16)
        audio_bytes = audio_handler.audio_to_bytes(audio_data)
        assert isinstance(audio_bytes, bytes)
        assert len(audio_bytes) > 0

    def test_read_chunk_empty_buffer(self, audio_handler):
        chunk = audio_handler.read_chunk()
        assert chunk is None

    def test_read_audio_empty_buffer(self, audio_handler):
        audio = audio_handler.read_audio(1.0)
        assert isinstance(audio, np.ndarray)
        assert len(audio) == 0

    @patch('pyaudio.PyAudio')
    def test_start_stream(self, mock_pyaudio):
        mock_audio = MagicMock()
        mock_stream = MagicMock()
        mock_pyaudio.return_value = mock_audio
        mock_audio.open.return_value = mock_stream
        
        handler = AudioInputHandler()
        handler.start_stream()
        
        mock_audio.open.assert_called_once()
        mock_stream.start_stream.assert_called_once()
        handler.cleanup()

    @patch('pyaudio.PyAudio')
    def test_stop_stream(self, mock_pyaudio):
        mock_audio = MagicMock()
        mock_stream = MagicMock()
        mock_pyaudio.return_value = mock_audio
        mock_audio.open.return_value = mock_stream
        
        handler = AudioInputHandler()
        handler.start_stream()
        handler.stop_stream()
        
        mock_stream.stop_stream.assert_called_once()
        mock_stream.close.assert_called_once()
        handler.cleanup()

    def test_context_manager(self):
        with patch('pyaudio.PyAudio'):
            with AudioInputHandler() as handler:
                assert handler is not None
                assert handler.stream is not None

    @patch('pyaudio.PyAudio')
    def test_list_audio_devices(self, mock_pyaudio):
        mock_audio = MagicMock()
        mock_pyaudio.return_value = mock_audio
        mock_audio.get_device_count.return_value = 2
        mock_audio.get_device_info_by_index.side_effect = [
            {
                'name': 'Microphone 1',
                'maxInputChannels': 2,
                'defaultSampleRate': 44100.0
            },
            {
                'name': 'Microphone 2',
                'maxInputChannels': 1,
                'defaultSampleRate': 16000.0
            }
        ]
        
        handler = AudioInputHandler()
        devices = handler.list_audio_devices()
        
        assert len(devices) == 2
        assert devices[0]['name'] == 'Microphone 1'
        assert devices[1]['channels'] == 1
        handler.cleanup()


class TestAudioIntegration:
    def test_buffer_operations(self):
        with patch('pyaudio.PyAudio'):
            handler = AudioInputHandler()
            
            test_chunk = np.random.randint(-1000, 1000, 1024, dtype=np.int16)
            handler.buffer.append(test_chunk)
            
            retrieved_chunk = handler.read_chunk()
            assert np.array_equal(retrieved_chunk, test_chunk)
            
            handler.cleanup()

    def test_energy_threshold_detection(self):
        with patch('pyaudio.PyAudio'):
            handler = AudioInputHandler()
            
            loud_audio = np.random.randint(5000, 10000, 1000, dtype=np.int16)
            quiet_audio = np.random.randint(-100, 100, 1000, dtype=np.int16)
            
            assert handler.is_speech(loud_audio)
            assert handler.is_silence(quiet_audio)
            
            handler.cleanup()
