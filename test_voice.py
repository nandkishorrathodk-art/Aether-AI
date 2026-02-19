"""
Quick test to demo natural human voice vs robotic voice
"""

from src.perception.voice.tts import TextToSpeech, TTSConfig

def test_voices():
    print("=" * 60)
    print("AETHER VOICE TEST - Natural vs Robotic")
    print("=" * 60)
    
    test_message = "Ji boss! Main Aether hoon. Aapki voice assistant. Kaise madad kar sakti hoon?"
    
    print("\n[1/2] Testing ROBOTIC voice (pyttsx3)...")
    print(f"Message: {test_message}")
    
    try:
        robotic_tts = TextToSpeech(config=TTSConfig(
            provider="pyttsx3",
            voice="female",
            rate=165
        ))
        robotic_tts.speak(test_message)
        print("✓ Robotic voice played")
    except Exception as e:
        print(f"✗ Robotic voice failed: {e}")
    
    print("\n[2/2] Testing NATURAL HUMAN voice (Edge TTS)...")
    print(f"Message: {test_message}")
    
    try:
        natural_tts = TextToSpeech(config=TTSConfig(
            provider="edge",
            voice="female",
            rate=165
        ))
        natural_tts.speak(test_message)
        print("✓ Natural human voice played")
    except Exception as e:
        print(f"✗ Natural voice failed: {e}")
    
    print("\n" + "=" * 60)
    print("Which one sounds more natural and human?")
    print("Edge TTS (option 2) is now the DEFAULT for Aether!")
    print("=" * 60)

if __name__ == "__main__":
    test_voices()
