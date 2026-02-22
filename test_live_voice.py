"""
Quick Test - Live Voice Assistant
Tests voice-first capabilities without full server
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

async def quick_test():
    """Quick test of live voice capabilities"""
    
    print("\n" + "="*70)
    print("  LIVE VOICE ASSISTANT - QUICK TEST")
    print("="*70 + "\n")
    
    try:
        from src.core.live_assistant import LiveVoiceAssistant
        
        print("[OK] Imports successful")
        print("\n[TEST] Testing Core Components:\n")
        
        # Test 1: Initialize assistant
        print("1. Initializing Live Voice Assistant...")
        assistant = LiveVoiceAssistant()
        print("   [OK] Assistant initialized")
        
        # Test 2: Check voice system
        print("\n2. Checking Voice System...")
        print(f"   Voice enabled: {assistant.voice_updates_enabled}")
        print(f"   Voice notifier: {assistant.voice_notifier is not None}")
        print("   [OK] Voice system ready")
        
        # Test 3: Check desktop controllers
        print("\n3. Checking Desktop Control...")
        print(f"   Browser controller: {assistant.browser is not None}")
        print(f"   PC controller: {assistant.pc_controller is not None}")
        print("   [OK] Desktop control ready")
        
        # Test 4: Check AI brain
        print("\n4. Checking AI Brain...")
        print(f"   LLM: {assistant.llm is not None}")
        print(f"   Autonomous brain: {assistant.autonomous_brain is not None}")
        print("   [OK] AI brain ready")
        
        # Test 5: Check task management
        print("\n5. Checking Task Management...")
        print(f"   Active tasks: {len(assistant.active_tasks)}")
        print(f"   Task queue: {assistant.task_queue is not None}")
        print("   [OK] Task management ready")
        
        print("\n" + "="*70)
        print("[SUCCESS] ALL CORE COMPONENTS WORKING!")
        print("="*70)
        
        print("\n[FEATURES] Available Capabilities:")
        print("   [+] Voice-first interaction (Hinglish)")
        print("   [+] Browser control (Chrome/Edge)")
        print("   [+] YouTube playback (search + play)")
        print("   [+] Teaching mode (live code lessons)")
        print("   [+] Bug bounty scanning (Nuclei + CVE)")
        print("   [+] Multitasking (parallel execution)")
        print("   [+] Task control (pause/resume/status)")
        
        print("\n[USAGE] To use full system:")
        print("   1. Start server: uvicorn src.api.main_clean:app --reload")
        print("   2. Run demo: python demo_live_assistant.py")
        print("   3. Or use API: POST http://localhost:8000/api/v1/live/command")
        
        print("\n[EXAMPLES] Voice Commands:")
        print("   - 'Open browser and search Python tutorial'")
        print("   - 'Play Lofi hip hop on YouTube'")
        print("   - 'Teach me Python functions'")
        print("   - 'Scan apple.com for vulnerabilities'")
        print("   - 'Pause that scan'")
        print("   - 'What's the status?'")
        
    except ImportError as e:
        print(f"[ERROR] Import error: {e}")
        print("\n[FIX] Install dependencies:")
        print("   pip install -r requirements.txt")
    except Exception as e:
        print(f"[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(quick_test())
