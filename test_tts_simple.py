"""
Simple TTS Test - Direct pyttsx3 test
"""
import pyttsx3
import time

print("=" * 60)
print("SIMPLE TTS TEST")
print("=" * 60)

# Test 1: Direct pyttsx3
print("\n1. Testing pyttsx3 directly...")
engine = pyttsx3.init()

# List voices
voices = engine.getProperty('voices')
print(f"\nAvailable voices ({len(voices)}):")
for i, voice in enumerate(voices):
    print(f"  {i}. {voice.name} ({voice.id})")

# Set volume to max
engine.setProperty('volume', 1.0)
engine.setProperty('rate', 160)

# Select female voice
for voice in voices:
    if "zira" in voice.name.lower() or "female" in voice.name.lower():
        print(f"\nUsing voice: {voice.name}")
        engine.setProperty('voice', voice.id)
        break

print("\nSpeaking: 'Hello, this is a TTS test. Can you hear me?'")
engine.say("Hello, this is a TTS test. Can you hear me?")
engine.runAndWait()

print("\n2. Speaking in Hinglish...")
engine.say("Namaste! Main Aether hoon. Kya aap meri awaaz sun sakte hain?")
engine.runAndWait()

print("\n✅ TTS Test Complete!")
print("If you didn't hear anything, check:")
print("  1. System volume is not muted")
print("  2. Correct audio output device selected")
print("  3. Speaker/headphone connections")
