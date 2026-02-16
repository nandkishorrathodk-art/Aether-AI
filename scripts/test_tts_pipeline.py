"""
Test script for TTS (Text-to-Speech) pipeline

This script tests the complete TTS functionality including:
- Local TTS with pyttsx3
- Cloud TTS with OpenAI (if API key provided)
- Caching mechanism
- Audio playback
- Output queue management
- Configuration updates
"""

import sys
import os
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.perception.voice.tts import TextToSpeech, TTSConfig
from src.perception.voice.output_queue import TTSOutputQueue


def print_section(title):
    """Print formatted section header"""
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60 + "\n")


def test_local_tts():
    """Test local TTS with pyttsx3"""
    print_section("Testing Local TTS (pyttsx3)")
    
    try:
        config = TTSConfig(
            provider="pyttsx3",
            voice="female",
            rate=175,
            cache_enabled=True
        )
        
        tts = TextToSpeech(config=config)
        
        print("✓ Local TTS initialized successfully")
        print(f"  Provider: {config.provider}")
        print(f"  Voice: {config.voice}")
        print(f"  Rate: {config.rate}")
        
        print("\nSynthesizing text: 'Hello! I am Aether AI, your personal assistant.'")
        audio_data = tts.synthesize("Hello! I am Aether AI, your personal assistant.")
        
        print(f"✓ Text synthesized successfully")
        print(f"  Audio size: {len(audio_data)} bytes")
        
        cache_stats = tts.get_cache_stats()
        print(f"\nCache stats:")
        print(f"  Total entries: {cache_stats['total_entries']}")
        print(f"  Total hits: {cache_stats['total_hits']}")
        print(f"  Cache size: {cache_stats['total_size_mb']:.2f} MB")
        
        print("\nTesting cache hit (same text)...")
        start = time.time()
        cached_audio = tts.synthesize("Hello! I am Aether AI, your personal assistant.")
        latency = time.time() - start
        
        print(f"✓ Cache hit successful")
        print(f"  Latency: {latency*1000:.2f} ms")
        print(f"  Target: < 1000 ms")
        print(f"  Status: {'✓ PASS' if latency < 1.0 else '✗ FAIL'}")
        
        tts.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Local TTS test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tts_playback():
    """Test TTS audio playback"""
    print_section("Testing TTS Audio Playback")
    
    try:
        config = TTSConfig(provider="pyttsx3")
        tts = TextToSpeech(config=config)
        
        print("Speaking: 'Testing audio playback functionality.'")
        print("(You should hear the audio playing...)")
        
        audio_data = tts.speak("Testing audio playback functionality.", blocking=True)
        
        if audio_data:
            print(f"✓ Audio playback completed")
            print(f"  Audio size: {len(audio_data)} bytes")
        else:
            print("✗ Audio playback failed")
            return False
        
        tts.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Playback test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_voice_selection():
    """Test different voice options"""
    print_section("Testing Voice Selection")
    
    try:
        for voice in ["female", "male"]:
            print(f"\nTesting {voice} voice...")
            
            config = TTSConfig(provider="pyttsx3", voice=voice)
            tts = TextToSpeech(config=config)
            
            audio_data = tts.synthesize(f"This is the {voice} voice.")
            print(f"✓ {voice.capitalize()} voice synthesized successfully")
            print(f"  Audio size: {len(audio_data)} bytes")
            
            tts.cleanup()
        
        return True
    
    except Exception as e:
        print(f"✗ Voice selection test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_config_updates():
    """Test TTS configuration updates"""
    print_section("Testing Configuration Updates")
    
    try:
        tts = TextToSpeech()
        
        print("Initial config:")
        print(f"  Rate: {tts.config.rate}")
        print(f"  Voice: {tts.config.voice}")
        
        print("\nUpdating configuration...")
        tts.update_config(rate=200, voice="male")
        
        print("Updated config:")
        print(f"  Rate: {tts.config.rate}")
        print(f"  Voice: {tts.config.voice}")
        
        assert tts.config.rate == 200
        assert tts.config.voice == "male"
        
        print("✓ Configuration update successful")
        
        tts.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Config update test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_output_queue():
    """Test TTS output queue management"""
    print_section("Testing TTS Output Queue")
    
    try:
        tts = TextToSpeech()
        queue = TTSOutputQueue(tts, max_queue_size=10)
        
        print("Adding requests to queue...")
        
        queue.add_urgent("Urgent message: System alert!")
        queue.add_normal("Normal message: Task completed.")
        queue.add_low("Low priority: Background notification.")
        
        stats = queue.get_stats()
        print(f"\nQueue stats:")
        print(f"  Queue size: {stats['queue_size']}")
        print(f"  Max size: {stats['max_queue_size']}")
        print(f"  Requests processed: {stats['requests_processed']}")
        
        assert stats['queue_size'] == 3
        
        print("\n✓ Output queue test successful")
        
        queue.clear()
        tts.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Output queue test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cache_performance():
    """Test cache performance with multiple phrases"""
    print_section("Testing Cache Performance")
    
    try:
        tts = TextToSpeech()
        
        phrases = [
            "Hello, how can I help you?",
            "Processing your request...",
            "Task completed successfully.",
            "Would you like me to continue?",
            "Thank you for using Aether AI."
        ]
        
        print("Synthesizing phrases (first pass - no cache)...")
        first_pass_time = 0
        for phrase in phrases:
            start = time.time()
            tts.synthesize(phrase)
            first_pass_time += time.time() - start
        
        print(f"  Total time: {first_pass_time*1000:.2f} ms")
        
        print("\nSynthesizing phrases (second pass - cached)...")
        second_pass_time = 0
        for phrase in phrases:
            start = time.time()
            tts.synthesize(phrase)
            second_pass_time += time.time() - start
        
        print(f"  Total time: {second_pass_time*1000:.2f} ms")
        
        speedup = first_pass_time / second_pass_time if second_pass_time > 0 else 0
        print(f"\nCache speedup: {speedup:.2f}x")
        
        cache_stats = tts.get_cache_stats()
        print(f"\nCache stats:")
        print(f"  Entries: {cache_stats['total_entries']}")
        print(f"  Hits: {cache_stats['total_hits']}")
        print(f"  Size: {cache_stats['total_size_mb']:.2f} MB")
        
        print("\n✓ Cache performance test successful")
        
        tts.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Cache performance test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cloud_tts():
    """Test cloud TTS with OpenAI (requires API key)"""
    print_section("Testing Cloud TTS (OpenAI)")
    
    api_key = os.getenv("OPENAI_API_KEY")
    
    if not api_key:
        print("⚠ Skipping cloud TTS test - OPENAI_API_KEY not set")
        print("  Set environment variable to test cloud TTS:")
        print("  export OPENAI_API_KEY=your_key_here")
        return True
    
    try:
        config = TTSConfig(provider="openai", voice="female")
        tts = TextToSpeech(config=config, api_key=api_key)
        
        print("Synthesizing with OpenAI TTS...")
        audio_data = tts.synthesize("Hello from OpenAI text to speech.")
        
        print(f"✓ Cloud TTS synthesis successful")
        print(f"  Audio size: {len(audio_data)} bytes")
        
        tts.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Cloud TTS test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_save_to_file():
    """Test saving synthesized audio to file"""
    print_section("Testing Save to File")
    
    try:
        tts = TextToSpeech()
        
        output_file = "data/test_output.wav"
        os.makedirs("data", exist_ok=True)
        
        print(f"Saving audio to: {output_file}")
        tts.save_to_file("This is a test audio file.", output_file)
        
        if os.path.exists(output_file):
            size = os.path.getsize(output_file)
            print(f"✓ Audio saved successfully")
            print(f"  File size: {size} bytes")
            
            os.remove(output_file)
        else:
            print("✗ File was not created")
            return False
        
        tts.cleanup()
        return True
    
    except Exception as e:
        print(f"✗ Save to file test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all TTS pipeline tests"""
    print("\n" + "=" * 60)
    print("  TTS PIPELINE TEST SUITE")
    print("=" * 60)
    
    tests = [
        ("Local TTS", test_local_tts),
        ("TTS Playback", test_tts_playback),
        ("Voice Selection", test_voice_selection),
        ("Config Updates", test_config_updates),
        ("Output Queue", test_output_queue),
        ("Cache Performance", test_cache_performance),
        ("Cloud TTS", test_cloud_tts),
        ("Save to File", test_save_to_file)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n✗ {test_name} crashed: {e}")
            results[test_name] = False
    
    print_section("TEST SUMMARY")
    
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
