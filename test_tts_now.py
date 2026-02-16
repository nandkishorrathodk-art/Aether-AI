"""Quick TTS Test"""
import sys
sys.stdout.reconfigure(encoding='utf-8')

print("Testing TTS...")

# Test 1: pyttsx3
try:
    import pyttsx3
    engine = pyttsx3.init()
    engine.setProperty('volume', 3.0)  # Max volume
    
    print("Speaking with pyttsx3...")
    engine.say("Hello, can you hear me now?")
    engine.runAndWait()
    print("Done speaking!")
    
except Exception as e:
    print(f"pyttsx3 Error: {e}")

# Test 2: Check audio devices
try:
    import pyaudio
    p = pyaudio.PyAudio()
    
    print("\nAvailable Audio Devices:")
    for i in range(p.get_device_count()):
        info = p.get_device_info_by_index(i)
        if info['maxOutputChannels'] > 0:
            print(f"  [{i}] {info['name']} (Output)")
    
    p.terminate()
except Exception as e:
    print(f"PyAudio Error: {e}")
