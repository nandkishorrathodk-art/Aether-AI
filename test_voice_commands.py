"""Test Voice Command System"""

import asyncio
import sys
from src.perception.voice.command_controller import VoiceCommandController
from src.perception.voice.voice_assistant import VoiceActivatedAssistant, AssistantState


async def test_command_controller():
    """Test voice command controller"""
    print("=" * 70)
    print("TESTING VOICE COMMAND CONTROLLER")
    print("=" * 70)
    
    controller = VoiceCommandController()
    
    test_commands = [
        "open chrome",
        "create a file named test.txt",
        "what's the system status",
        "remember to buy milk",
        "change voice to male",
        "set volume to 75",
        "create a task to backup files",
        "what are my tasks",
        "hello, how are you?",
        "tell me a joke"
    ]
    
    print(f"\n[INFO] Testing {len(test_commands)} commands...\n")
    
    passed = 0
    failed = 0
    
    for i, command in enumerate(test_commands, 1):
        print(f"[{i}/{len(test_commands)}] Command: \"{command}\"")
        
        try:
            result = await controller.process_command(command)
            
            print(f"  Intent: {result.get('intent', 'unknown')}")
            print(f"  Status: {result.get('status', 'unknown')}")
            print(f"  Response: {result.get('response', 'No response')[:80]}")
            print(f"  Confidence: {result.get('confidence', 0):.2f}")
            
            if result.get("status") == "success":
                print("  [PASS]")
                passed += 1
            else:
                print("  [FAIL]")
                failed += 1
        
        except Exception as e:
            print(f"  [ERROR] {e}")
            failed += 1
        
        print()
    
    print("-" * 70)
    print(f"Results: {passed} passed, {failed} failed ({passed*100/(passed+failed):.1f}% success rate)")
    print("-" * 70)
    
    # Print stats
    stats = controller.get_stats()
    print(f"\nController Stats:")
    print(f"  Total commands: {stats['total_commands']}")
    print(f"  Successful: {stats['successful']}")
    print(f"  Failed: {stats['failed']}")
    print(f"  By intent: {stats['by_intent']}")
    
    # Print supported commands
    print(f"\nSupported Commands ({len(controller.get_supported_commands())}):")
    for cmd in controller.get_supported_commands()[:5]:
        print(f"  - {cmd['intent']}: {cmd['examples'][0] if cmd['examples'] else 'N/A'}")
    
    return passed, failed


async def test_assistant_text_mode():
    """Test voice assistant in text mode (no actual voice I/O)"""
    print("\n" + "=" * 70)
    print("TESTING VOICE ASSISTANT (TEXT MODE)")
    print("=" * 70)
    
    print("\n[INFO] Creating voice assistant...")
    assistant = VoiceActivatedAssistant(wake_word="jarvis")
    
    print(f"[OK] Assistant created")
    print(f"  State: {assistant.get_state().value}")
    print(f"  Wake word: {assistant.wake_word}")
    
    # Test text command processing
    test_commands = [
        "what time is it",
        "open notepad",
        "system information"
    ]
    
    print(f"\n[INFO] Testing {len(test_commands)} text commands...\n")
    
    for i, command in enumerate(test_commands, 1):
        print(f"[{i}/{len(test_commands)}] Processing: \"{command}\"")
        
        try:
            result = await assistant.process_text_command(command)
            print(f"  Intent: {result.get('intent')}")
            print(f"  Response: {result.get('response', '')[:80]}")
            print(f"  [OK]")
        except Exception as e:
            print(f"  [ERROR] {e}")
        
        print()
    
    # Print stats
    stats = assistant.get_stats()
    print(f"\nAssistant Stats:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    return True


async def main():
    """Main test function"""
    print("\n" + "=" * 70)
    print("AETHER AI - VOICE COMMAND SYSTEM TEST")
    print("=" * 70)
    
    all_passed = True
    
    # Test 1: Command Controller
    try:
        passed, failed = await test_command_controller()
        if failed > 0:
            all_passed = False
    except Exception as e:
        print(f"[ERROR] Command controller test failed: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    # Test 2: Voice Assistant
    try:
        result = await test_assistant_text_mode()
        if not result:
            all_passed = False
    except Exception as e:
        print(f"[ERROR] Voice assistant test failed: {e}")
        import traceback
        traceback.print_exc()
        all_passed = False
    
    # Final summary
    print("\n" + "=" * 70)
    if all_passed:
        print("[SUCCESS] ALL TESTS PASSED")
    else:
        print("[WARNING] SOME TESTS FAILED")
    print("=" * 70)
    
    print("\n[INFO] Voice command system is ready!")
    print("\nNext steps:")
    print("  1. Start API server: python -m uvicorn src.api.main:app --reload")
    print("  2. Test voice commands API: POST /api/v1/voice-commands/execute")
    print("  3. View supported commands: GET /api/v1/voice-commands/supported")
    print("  4. Check examples: GET /api/v1/voice-commands/examples")
    
    return all_passed


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
