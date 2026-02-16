"""
Manual Test Script for End-to-End Voice Pipeline Integration
Tests the complete flow: Wake Word → STT → LLM → TTS → Output
"""
import sys
import io
import time
import asyncio
import numpy as np
from pathlib import Path

# Fix Windows console encoding issues
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pipeline import VoicePipelineOrchestrator, PipelineConfig
from src.perception.voice.audio_utils import AudioInputHandler, AudioConfig
from src.utils.logger import get_logger

logger = get_logger(__name__)


def print_section(title):
    """Print section header"""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def test_pipeline_initialization():
    """Test 1: Pipeline Initialization"""
    print_section("TEST 1: Pipeline Initialization")
    
    try:
        config = PipelineConfig(
            wake_word="hey aether",
            stt_model="base",
            stt_use_cloud=False,
            tts_provider="pyttsx3",
            enable_continuous_mode=False
        )
        
        print(f"✓ Configuration created")
        print(f"  - Wake word: {config.wake_word}")
        print(f"  - STT model: {config.stt_model}")
        print(f"  - TTS provider: {config.tts_provider}")
        
        pipeline = VoicePipelineOrchestrator(config)
        print(f"✓ Pipeline instance created")
        
        start_time = time.time()
        pipeline.initialize()
        init_time = time.time() - start_time
        
        print(f"✓ Pipeline initialized in {init_time:.2f}s")
        print(f"  - Wake word detector: {'✓' if pipeline.wake_word_detector else '✗'}")
        print(f"  - STT engine: {'✓' if pipeline.stt else '✗'}")
        print(f"  - TTS engine: {'✓' if pipeline.tts else '✗'}")
        print(f"  - Audio handler: {'✓' if pipeline.audio_handler else '✗'}")
        
        pipeline.cleanup()
        print(f"✓ Pipeline cleaned up")
        
        return True
    
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False


def test_session_management():
    """Test 2: Session Management"""
    print_section("TEST 2: Session Management")
    
    try:
        config = PipelineConfig(enable_continuous_mode=False)
        pipeline = VoicePipelineOrchestrator(config)
        pipeline.initialize()
        
        # Create sessions
        session1 = pipeline._create_session("user-1")
        session2 = pipeline._create_session("user-2")
        
        print(f"✓ Created 2 sessions")
        print(f"  - Session 1: {session1.session_id}")
        print(f"  - Session 2: {session2.session_id}")
        
        # Update activity
        session1.update_activity()
        session1.total_processing_time = 2.5
        
        print(f"✓ Updated session activity")
        
        # Get stats
        stats1 = session1.get_stats()
        print(f"✓ Session stats:")
        print(f"  - Turn count: {stats1['turn_count']}")
        print(f"  - Avg processing time: {stats1['avg_processing_time']:.2f}s")
        
        # Test expiration
        from datetime import datetime, timedelta
        session2.last_activity = datetime.now() - timedelta(minutes=10)
        
        expired = session2.is_expired(timeout_minutes=5)
        print(f"✓ Session expiration detection: {expired}")
        
        # Cleanup expired
        pipeline._cleanup_expired_sessions()
        
        remaining = len(pipeline.sessions)
        print(f"✓ Cleaned up expired sessions")
        print(f"  - Remaining sessions: {remaining}")
        
        pipeline.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False


async def test_audio_processing():
    """Test 3: Audio Processing Flow"""
    print_section("TEST 3: Audio Processing Flow")
    
    try:
        config = PipelineConfig(
            stt_model="base",
            stt_use_cloud=False,
            tts_provider="pyttsx3"
        )
        
        pipeline = VoicePipelineOrchestrator(config)
        pipeline.initialize()
        
        print(f"✓ Pipeline initialized")
        
        # Generate test audio (silence + some noise)
        print(f"⏳ Generating test audio...")
        sample_rate = AudioConfig.SAMPLE_RATE
        duration = 2.0
        
        # Create audio with some energy (to simulate speech)
        t = np.linspace(0, duration, int(sample_rate * duration))
        audio_data = (np.random.randn(len(t)) * 1000).astype(np.int16)
        
        print(f"✓ Generated {duration}s of audio")
        print(f"  - Sample rate: {sample_rate} Hz")
        print(f"  - Samples: {len(audio_data)}")
        
        # Process through pipeline
        print(f"⏳ Processing through pipeline...")
        start_time = time.time()
        
        response = await pipeline.process_voice_request(audio_data, session_id="test")
        
        processing_time = time.time() - start_time
        
        print(f"✓ Processing completed in {processing_time:.2f}s")
        print(f"  - Response: {response if response else 'None (expected for random audio)'}")
        
        # Get stats
        stats = pipeline.get_stats()
        print(f"✓ Pipeline stats:")
        print(f"  - Total requests: {stats['total_requests']}")
        print(f"  - Successful: {stats['successful_requests']}")
        print(f"  - Failed: {stats['failed_requests']}")
        print(f"  - Success rate: {stats['success_rate']:.1f}%")
        
        pipeline.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_pipeline_lifecycle():
    """Test 4: Start/Stop Lifecycle"""
    print_section("TEST 4: Pipeline Start/Stop Lifecycle")
    
    try:
        config = PipelineConfig(
            wake_word="hey aether",
            enable_continuous_mode=False  # Disable continuous for testing
        )
        
        pipeline = VoicePipelineOrchestrator(config)
        pipeline.initialize()
        
        print(f"✓ Pipeline initialized")
        
        # Start pipeline
        print(f"⏳ Starting pipeline...")
        start_time = time.time()
        pipeline.start()
        start_duration = time.time() - start_time
        
        print(f"✓ Pipeline started in {start_duration:.2f}s")
        print(f"  - Running: {pipeline.is_running}")
        print(f"  - Pipeline thread: {'✓' if pipeline.pipeline_thread else '✗'}")
        print(f"  - TTS thread: {'✓' if pipeline.tts_thread else '✗'}")
        
        # Run for a bit
        print(f"⏳ Running for 2 seconds...")
        time.sleep(2.0)
        
        # Check stats during run
        stats = pipeline.get_stats()
        print(f"✓ Runtime stats:")
        print(f"  - Active sessions: {stats['active_sessions']}")
        
        # Stop pipeline
        print(f"⏳ Stopping pipeline...")
        start_time = time.time()
        pipeline.stop()
        stop_duration = time.time() - start_time
        
        print(f"✓ Pipeline stopped in {stop_duration:.2f}s")
        print(f"  - Running: {pipeline.is_running}")
        
        pipeline.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_performance_metrics():
    """Test 5: Performance Metrics"""
    print_section("TEST 5: Performance Metrics")
    
    try:
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Measure baseline
        baseline_memory = process.memory_info().rss / (1024 * 1024)
        print(f"📊 Baseline memory: {baseline_memory:.2f} MB")
        
        config = PipelineConfig(
            stt_model="base",
            enable_continuous_mode=False
        )
        
        pipeline = VoicePipelineOrchestrator(config)
        
        # Initialize and measure
        start_time = time.time()
        pipeline.initialize()
        init_time = time.time() - start_time
        
        current_memory = process.memory_info().rss / (1024 * 1024)
        memory_increase = current_memory - baseline_memory
        
        print(f"✓ Initialization metrics:")
        print(f"  - Time: {init_time:.2f}s")
        print(f"  - Memory increase: {memory_increase:.2f} MB")
        print(f"  - Current memory: {current_memory:.2f} MB")
        
        # Start and measure CPU
        pipeline.start()
        time.sleep(1.0)
        
        cpu_percent = process.cpu_percent(interval=1.0)
        
        print(f"✓ Runtime metrics:")
        print(f"  - CPU usage: {cpu_percent:.2f}%")
        
        # Performance targets
        print(f"\n📊 Performance Targets:")
        print(f"  - Init time < 15s: {'✓' if init_time < 15 else '✗'} ({init_time:.2f}s)")
        print(f"  - Memory < 3000MB: {'✓' if memory_increase < 3000 else '✗'} ({memory_increase:.2f}MB)")
        
        pipeline.stop()
        pipeline.cleanup()
        
        return True
    
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_error_handling():
    """Test 6: Error Handling"""
    print_section("TEST 6: Error Handling")
    
    try:
        config = PipelineConfig(enable_continuous_mode=False)
        pipeline = VoicePipelineOrchestrator(config)
        pipeline.initialize()
        
        print(f"✓ Pipeline initialized")
        
        # Test with empty audio
        print(f"⏳ Testing with empty audio...")
        empty_audio = np.array([], dtype=np.int16)
        
        async def test_empty():
            result = await pipeline.process_voice_request(empty_audio)
            return result
        
        result = asyncio.run(test_empty())
        print(f"✓ Empty audio handled gracefully: {result is None}")
        
        # Test with very short audio
        print(f"⏳ Testing with very short audio...")
        short_audio = np.array([0] * 100, dtype=np.int16)
        
        async def test_short():
            result = await pipeline.process_voice_request(short_audio)
            return result
        
        result = asyncio.run(test_short())
        print(f"✓ Short audio handled gracefully: {result is None}")
        
        # Check error stats
        stats = pipeline.get_stats()
        print(f"✓ Error handling stats:")
        print(f"  - Total requests: {stats['total_requests']}")
        print(f"  - Failed requests: {stats['failed_requests']}")
        
        pipeline.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all integration tests"""
    print("\n" + "=" * 70)
    print("  VOICE PIPELINE INTEGRATION TEST SUITE")
    print("=" * 70)
    print(f"  Testing End-to-End Voice Pipeline")
    print(f"  Wake Word -> STT -> LLM -> TTS -> Output")
    print("=" * 70)
    
    results = []
    
    # Run tests
    results.append(("Initialization", test_pipeline_initialization()))
    results.append(("Session Management", test_session_management()))
    results.append(("Audio Processing", asyncio.run(test_audio_processing())))
    results.append(("Lifecycle", test_pipeline_lifecycle()))
    results.append(("Performance", test_performance_metrics()))
    results.append(("Error Handling", test_error_handling()))
    
    # Summary
    print_section("TEST SUMMARY")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "-" * 70)
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("-" * 70)
    
    if passed == total:
        print("\n🎉 All tests passed! Voice pipeline integration is working correctly.")
        return 0
    else:
        print(f"\n⚠️ {total - passed} test(s) failed. Please review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
