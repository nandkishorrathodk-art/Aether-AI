# Text-to-Speech (TTS) System Guide

## Overview

The TTS system provides natural voice output for Aether AI with both local and cloud-based synthesis options, intelligent caching, and priority-based queue management.

## Architecture

```
TextToSpeech (Main Interface)
├── LocalTTS (pyttsx3)
│   ├── Voice selection (male/female/neutral)
│   ├── Speed and pitch control
│   └── Offline synthesis
├── CloudTTS (OpenAI)
│   ├── High-quality voices
│   ├── Multiple voice options
│   └── Cloud-based synthesis
├── TTSCache
│   ├── Intelligent phrase caching
│   ├── Hit tracking
│   └── Automatic cleanup
└── TTSOutputQueue
    ├── Priority-based queuing
    ├── Concurrent request handling
    └── Background processing
```

## Quick Start

### Basic Usage (Local TTS)

```python
from src.perception.voice import TextToSpeech, TTSConfig

config = TTSConfig(
    provider="pyttsx3",
    voice="female",
    rate=175,
    cache_enabled=True
)

tts = TextToSpeech(config=config)

tts.speak("Hello! I am Aether AI.")

tts.cleanup()
```

### Cloud TTS (OpenAI)

```python
config = TTSConfig(
    provider="openai",
    voice="female",
    cache_enabled=True
)

tts = TextToSpeech(config=config, api_key="your_openai_api_key")
tts.speak("High quality cloud-based speech.")
tts.cleanup()
```

### Queue-Based Processing

```python
from src.perception.voice.output_queue import TTSOutputQueue

tts = TextToSpeech()
queue = TTSOutputQueue(tts, max_queue_size=50)

queue.start()

queue.add_urgent("System alert!")
queue.add_normal("Task completed successfully.")
queue.add_low("Background notification.")

queue.wait_completion()
queue.stop()
```

## Configuration Options

### TTSConfig Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `provider` | str | "pyttsx3" | TTS provider: "pyttsx3" or "openai" |
| `voice` | str | "female" | Voice type: "male", "female", or "neutral" |
| `rate` | int | 175 | Speech rate (words per minute) |
| `volume` | float | 0.9 | Volume level (0.0 to 1.0) |
| `pitch` | float | 1.0 | Pitch multiplier (for cloud TTS) |
| `sample_rate` | int | 16000 | Audio sample rate in Hz |
| `cache_enabled` | bool | True | Enable phrase caching |
| `cache_dir` | str | "data/tts_cache" | Cache directory path |

## Features

### 1. Intelligent Caching

The TTS cache stores synthesized audio to avoid re-generating common phrases:

```python
tts.synthesize("Hello world")  # First synthesis - stored in cache
tts.synthesize("Hello world")  # Cache hit - instant retrieval

stats = tts.get_cache_stats()
print(f"Cache hits: {stats['total_hits']}")
print(f"Cache size: {stats['total_size_mb']:.2f} MB")

tts.clear_cache()
```

**Performance**: Cache hits typically reduce latency from 500-1000ms to <50ms.

### 2. Voice Selection

**Local Voices (pyttsx3)**:
- Automatically selects best available system voice
- Supports Windows SAPI voices
- Works offline

**Cloud Voices (OpenAI)**:
- `female` → "nova" (warm, friendly)
- `male` → "onyx" (deep, authoritative)
- `neutral` → "alloy" (balanced, professional)

### 3. Dynamic Configuration

Update TTS settings on-the-fly:

```python
tts = TextToSpeech()

tts.update_config(
    rate=200,
    voice="male",
    volume=1.0
)
```

### 4. Priority Queue Management

Handle multiple TTS requests with priority levels:

```python
queue = TTSOutputQueue(tts)
queue.start()

queue.add_urgent("Critical alert!", priority=1)
queue.add_normal("Information", priority=5)
queue.add_low("Background task", priority=10)

stats = queue.get_stats()
print(f"Queue size: {stats['queue_size']}")
print(f"Processed: {stats['requests_processed']}")
```

**Priority Levels**:
- `1-3`: Urgent (system alerts, errors)
- `4-6`: Normal (responses, confirmations)
- `7-10`: Low (background notifications)

### 5. Audio Playback Control

**Blocking Playback** (wait for completion):
```python
audio_data = tts.speak("Hello", blocking=True)
```

**Non-blocking Playback** (background):
```python
audio_data = tts.speak("Hello", blocking=False)
```

**Synthesis Only** (no playback):
```python
audio_data = tts.synthesize("Hello")
```

**Save to File**:
```python
tts.save_to_file("Hello world", "output.wav")
```

## API Endpoints

### POST /api/v1/voice/synthesize

Synthesize text to speech and return audio file.

**Request**:
```json
{
  "text": "Hello world",
  "voice": "female",
  "rate": 175,
  "pitch": 1.0,
  "use_cache": true
}
```

**Response**: WAV audio file (audio/wav)

### POST /api/v1/voice/speak

Synthesize and play text through speakers.

**Request**:
```json
{
  "text": "Hello world",
  "voice": "male",
  "rate": 200
}
```

**Response**:
```json
{
  "status": "speaking",
  "text": "Hello world",
  "audio_size_bytes": 44144
}
```

### GET /api/v1/voice/tts/cache/stats

Get cache statistics.

**Response**:
```json
{
  "total_entries": 15,
  "total_hits": 42,
  "total_size_mb": 2.34,
  "cache_dir": "data/tts_cache"
}
```

### POST /api/v1/voice/tts/cache/clear

Clear TTS cache.

**Response**:
```json
{
  "status": "success",
  "message": "TTS cache cleared"
}
```

### GET /api/v1/voice/tts/voices

List available TTS voices.

**Response**:
```json
{
  "voices": [
    {"id": "female", "name": "Female Voice"},
    {"id": "male", "name": "Male Voice"},
    {"id": "neutral", "name": "Neutral Voice"}
  ],
  "total": 3
}
```

## Performance Targets

| Metric | Target | Typical |
|--------|--------|---------|
| First synthesis | < 2s | 500-1000ms (local), 800-1500ms (cloud) |
| Cached synthesis | < 1s | 10-50ms |
| Queue processing | Continuous | 1-3 requests/sec |
| Cache hit rate | > 40% | 50-70% for common phrases |
| Memory usage | < 500MB | 100-300MB |

## Troubleshooting

### Issue: No audio playback

**Solution**:
1. Check system audio device is working
2. Verify PyAudio is installed: `pip install pyaudio`
3. Test with: `python -m scripts.test_tts_pipeline`

### Issue: pyttsx3 voice sounds robotic

**Solution**:
1. Install better Windows SAPI voices
2. Switch to cloud TTS (OpenAI) for higher quality
3. Adjust rate and pitch settings

### Issue: Cache growing too large

**Solution**:
```python
tts = TextToSpeech()
stats = tts.get_cache_stats()

if stats['total_size_mb'] > 100:
    tts.clear_cache()
```

### Issue: OpenAI TTS fails

**Solution**:
1. Check API key is valid
2. Verify internet connection
3. Check OpenAI API status
4. Fallback to local TTS:
   ```python
   config.provider = "pyttsx3"
   ```

## Testing

### Run Unit Tests

```bash
pytest tests/unit/test_tts.py -v
```

**Expected**: 30 passed, 3 skipped

### Run Integration Tests

```bash
python scripts/test_tts_pipeline.py
```

**Tests**:
- Local TTS synthesis
- Audio playback
- Voice selection
- Configuration updates
- Output queue management
- Cache performance
- Cloud TTS (if API key set)
- File saving

## Best Practices

### 1. Use Caching for Common Phrases

```python
common_phrases = [
    "How can I help you?",
    "Processing your request...",
    "Task completed successfully.",
    "Would you like to continue?"
]

for phrase in common_phrases:
    tts.synthesize(phrase)
```

### 2. Queue Urgent Messages

```python
queue.add_urgent("System error detected!")
queue.add_normal("Analysis complete.")
```

### 3. Cleanup Resources

```python
with TextToSpeech() as tts:
    tts.speak("Hello")
```

### 4. Handle Errors Gracefully

```python
try:
    tts.speak(user_input)
except Exception as e:
    logger.error(f"TTS failed: {e}")
    print(f"[Speaking: {user_input}]")
```

## Future Enhancements

- [ ] Emotion/tone control (happy, sad, urgent)
- [ ] SSML support for advanced speech markup
- [ ] Voice cloning for personalized voices
- [ ] Real-time streaming synthesis
- [ ] Multi-language support
- [ ] Voice effects (echo, reverb)
- [ ] Phonetic correction dictionary
- [ ] Background noise mixing

## References

- [pyttsx3 Documentation](https://pyttsx3.readthedocs.io/)
- [OpenAI TTS API](https://platform.openai.com/docs/guides/text-to-speech)
- [PyAudio Documentation](https://people.csail.mit.edu/hubert/pyaudio/)
