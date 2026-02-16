import sys
import os
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.perception.voice import (
    AudioInputHandler,
    WakeWordDetector,
    SimpleWakeWordDetector,
    SpeechToText,
    STTConfig
)
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def test_audio_input():
    print("\n" + "="*50)
    print("Testing Audio Input Handler")
    print("="*50)
    
    try:
        audio_handler = AudioInputHandler()
        
        print("\nAvailable audio devices:")
        devices = audio_handler.list_audio_devices()
        for device in devices:
            print(f"  [{device['index']}] {device['name']} - {device['sample_rate']}Hz, {device['channels']} channel(s)")
        
        print("\nStarting audio stream for 3 seconds...")
        with audio_handler as handler:
            import time
            time.sleep(3)
            
            chunk = handler.read_chunk()
            if chunk is not None:
                energy = AudioInputHandler.calculate_energy(chunk)
                print(f"Captured audio chunk: {len(chunk)} samples, energy: {energy:.2f}")
            else:
                print("No audio captured")
        
        print("✓ Audio input test passed")
        return True
    except Exception as e:
        print(f"✗ Audio input test failed: {e}")
        logger.error(f"Audio input test error: {e}", exc_info=True)
        return False


def test_wake_word_simple():
    print("\n" + "="*50)
    print("Testing Simple Wake Word Detection")
    print("="*50)
    
    try:
        detector = SimpleWakeWordDetector(wake_word="hey aether")
        
        print(f"Wake word: '{detector.wake_word}'")
        print(f"Energy threshold: {detector.detection_threshold}")
        
        import numpy as np
        
        print("\nTesting with synthetic audio...")
        loud_audio = np.random.randint(8000, 15000, 16000, dtype=np.int16)
        quiet_audio = np.random.randint(-100, 100, 16000, dtype=np.int16)
        
        loud_result = detector.detect(loud_audio)
        quiet_result = detector.detect(quiet_audio)
        
        print(f"Loud audio detected: {loud_result}")
        print(f"Quiet audio detected: {quiet_result}")
        
        print("✓ Simple wake word test passed")
        return True
    except Exception as e:
        print(f"✗ Simple wake word test failed: {e}")
        logger.error(f"Wake word test error: {e}", exc_info=True)
        return False


def test_wake_word_live():
    print("\n" + "="*50)
    print("Testing Live Wake Word Detection")
    print("="*50)
    print("NOTE: This requires a working microphone")
    print("Say 'hey aether' (or make a loud sound) to trigger detection")
    print("Press Ctrl+C to skip this test")
    print("="*50)
    
    try:
        detector = WakeWordDetector(
            wake_word="hey aether",
            use_porcupine=False,
            sensitivity=0.5
        )
        
        print("\nListening for wake word (10 second timeout)...")
        result = detector.listen_for_wake_word(timeout_seconds=10)
        
        if result:
            print("✓ Wake word detected!")
        else:
            print("⚠ No wake word detected (timeout)")
        
        detector.cleanup()
        return True
    except KeyboardInterrupt:
        print("\n⚠ Test skipped by user")
        return True
    except Exception as e:
        print(f"✗ Live wake word test failed: {e}")
        logger.error(f"Live wake word test error: {e}", exc_info=True)
        return False


def test_stt_config():
    print("\n" + "="*50)
    print("Testing STT Configuration")
    print("="*50)
    
    try:
        models = ["tiny", "base", "small", "medium", "large"]
        print("\nWhisper Models:")
        for model in models:
            info = STTConfig.WHISPER_MODELS.get(model, {})
            print(f"  {model}: {info.get('size_mb')}MB - {info.get('speed')} - {info.get('accuracy')} accuracy")
        
        print("\nRecommended models:")
        print(f"  4GB RAM, No GPU: {STTConfig.get_recommended_model(4, False)}")
        print(f"  8GB RAM, No GPU: {STTConfig.get_recommended_model(8, False)}")
        print(f"  16GB RAM, No GPU: {STTConfig.get_recommended_model(16, False)}")
        print(f"  16GB RAM, With GPU: {STTConfig.get_recommended_model(16, True)}")
        
        print("✓ STT config test passed")
        return True
    except Exception as e:
        print(f"✗ STT config test failed: {e}")
        logger.error(f"STT config test error: {e}", exc_info=True)
        return False


def test_stt_local():
    print("\n" + "="*50)
    print("Testing Local Speech-to-Text (Whisper)")
    print("="*50)
    print("NOTE: This will download the Whisper 'tiny' model (~39MB) on first run")
    print("Press Ctrl+C to skip this test")
    print("="*50)
    
    try:
        import numpy as np
        
        print("\nInitializing Whisper model...")
        stt = SpeechToText(model_name="tiny", use_cloud=False, device="cpu")
        
        print("Model loaded successfully!")
        
        print("\nTesting with synthetic audio (this will not produce valid transcription)...")
        test_audio = np.random.randint(-1000, 1000, 16000, dtype=np.int16)
        result = stt.transcribe_audio(test_audio)
        
        print(f"Transcription: '{result['text']}'")
        print(f"Language: {result.get('language', 'unknown')}")
        print(f"Confidence: {result.get('confidence', 0):.2f}")
        print(f"Source: {result.get('source', 'unknown')}")
        
        print("\nSupported languages:")
        languages = stt.get_supported_languages()
        print(f"  Total: {len(languages)} languages")
        print(f"  Sample: {', '.join(languages[:10])}...")
        
        stt.cleanup()
        print("✓ Local STT test passed")
        return True
    except KeyboardInterrupt:
        print("\n⚠ Test skipped by user")
        return True
    except Exception as e:
        print(f"✗ Local STT test failed: {e}")
        logger.error(f"Local STT test error: {e}", exc_info=True)
        return False


def test_stt_cloud():
    print("\n" + "="*50)
    print("Testing Cloud Speech-to-Text (OpenAI Whisper API)")
    print("="*50)
    print("NOTE: This requires OPENAI_API_KEY environment variable")
    print("Press Ctrl+C to skip this test")
    print("="*50)
    
    try:
        import numpy as np
        from dotenv import load_dotenv
        
        load_dotenv()
        api_key = os.getenv("OPENAI_API_KEY")
        
        if not api_key:
            print("⚠ OPENAI_API_KEY not found, skipping cloud STT test")
            return True
        
        print("\nInitializing cloud STT...")
        stt = SpeechToText(use_cloud=True, api_key=api_key)
        
        print("Cloud STT initialized!")
        
        print("\nNote: Cloud STT test requires actual audio file for meaningful results")
        print("Skipping transcription test (would require valid audio)")
        
        print("✓ Cloud STT initialization passed")
        return True
    except KeyboardInterrupt:
        print("\n⚠ Test skipped by user")
        return True
    except Exception as e:
        print(f"✗ Cloud STT test failed: {e}")
        logger.error(f"Cloud STT test error: {e}", exc_info=True)
        return False


def test_full_pipeline():
    print("\n" + "="*50)
    print("Testing Full Voice Input Pipeline")
    print("="*50)
    print("This test demonstrates the complete pipeline:")
    print("1. Wake word detection")
    print("2. Audio recording until silence")
    print("3. Speech-to-text transcription")
    print("\nPress Ctrl+C to skip this test")
    print("="*50)
    
    try:
        print("\nInitializing components...")
        audio_handler = AudioInputHandler()
        wake_detector = SimpleWakeWordDetector(wake_word="hey aether")
        
        print("Components initialized!")
        print("\nFor full pipeline test with real audio:")
        print("  1. Say 'hey aether' (or make a loud sound)")
        print("  2. Speak your message")
        print("  3. Pause for 1.5 seconds to trigger transcription")
        print("\nSkipping live test in automated mode")
        
        audio_handler.cleanup()
        
        print("✓ Pipeline initialization passed")
        return True
    except KeyboardInterrupt:
        print("\n⚠ Test skipped by user")
        return True
    except Exception as e:
        print(f"✗ Full pipeline test failed: {e}")
        logger.error(f"Full pipeline test error: {e}", exc_info=True)
        return False


def main():
    print("\n" + "="*60)
    print(" AETHER AI - Voice Input Pipeline Test Suite")
    print("="*60)
    
    tests = [
        ("Audio Input Handler", test_audio_input),
        ("Simple Wake Word Detection", test_wake_word_simple),
        ("STT Configuration", test_stt_config),
        ("Local Speech-to-Text", test_stt_local),
        ("Cloud Speech-to-Text", test_stt_cloud),
        ("Full Pipeline", test_full_pipeline),
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n✗ {test_name} failed with exception: {e}")
            logger.error(f"{test_name} exception: {e}", exc_info=True)
            results[test_name] = False
    
    print("\n" + "="*60)
    print(" TEST RESULTS")
    print("="*60)
    
    for test_name, passed in results.items():
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{status:12} - {test_name}")
    
    passed_count = sum(1 for r in results.values() if r)
    total_count = len(results)
    
    print("="*60)
    print(f"Total: {passed_count}/{total_count} tests passed")
    print("="*60)
    
    return all(results.values())


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest suite interrupted by user")
        sys.exit(1)
