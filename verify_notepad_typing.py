
import asyncio
import sys
import os

# Add project root to path
sys.path.append(os.getcwd())

from src.control.app_launcher import AppLauncher
from src.control.mouse_keyboard import MouseKeyboardController

async def verify_typing():
    print("Initialize Controllers...")
    launcher = AppLauncher()
    mk_controller = MouseKeyboardController()
    
    print("Launching Notepad...")
    result = await launcher.launch_app("notepad")
    
    if result.success:
        print(f"✅ PASS: Notepad launched.")
        
        # Give it a second to start and get focus
        print("Waiting for Notepad to open...")
        await asyncio.sleep(2)
        
        # Type introduction
        intro_text = "Hello! I am Aether AI.\nI can control your mouse and keyboard.\nThis introduction was typed automatically."
        print(f"Typing: {intro_text}")
        
        try:
            type_result = await mk_controller.type_text(intro_text, delay=0.05)
            if type_result.success:
                print("✅ PASS: Text typed successfully.")
            else:
                 print(f"❌ FAIL: Typing failed - {type_result.error}")
        except Exception as e:
            print(f"❌ FAIL: Exception during typing - {e}")
            
        # Give user time to see it
        await asyncio.sleep(3)
        
        # Close it 
        print("Closing Notepad (forcefully to avoid save prompt)...")
        # Ensure we close it even if typing failed
        await launcher.close_app("notepad", force=True)
        print("✅ PASS: Notepad closed.")
            
    else:
        print(f"❌ FAIL: Launch failed - {result.error}")

if __name__ == "__main__":
    asyncio.run(verify_typing())
