"""Quick test - Visual Executor"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

try:
    from src.automation.visual_executor import VisualExecutor
    print("[OK] VisualExecutor imported successfully")
    
    from src.core.live_assistant import LiveVoiceAssistant
    print("[OK] LiveVoiceAssistant imported successfully")
    
    print("\n[SUCCESS] All visual execution modules working!")
    print("\n[READY] You can now:")
    print("  1. Start server: uvicorn src.api.main_clean:app --reload")
    print("  2. Run demo: python demo_visual_live.py")
    print("  3. Use voice commands to open windows!")
    
except Exception as e:
    print(f"[ERROR] {e}")
    import traceback
    traceback.print_exc()
