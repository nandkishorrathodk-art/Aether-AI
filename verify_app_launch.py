
import asyncio
import sys
import os

# Add project root to path
sys.path.append(os.getcwd())

from src.control.app_launcher import AppLauncher

async def verify_launch():
    print("Initialize AppLauncher...")
    launcher = AppLauncher()
    
    print("Launching Notepad...")
    result = await launcher.launch_app("notepad")
    
    if result.success:
        print(f"✅ PASS: Notepad launched (PID in message: {result.message})")
        
        # Give it a second to start
        await asyncio.sleep(2)
        
        # Check if running
        is_running = await launcher.is_app_running("notepad")
        if is_running:
             print("✅ PASS: Notepad process detected running.")
        else:
             print("❌ FAIL: Notepad process not found after launch.")
             
        # Close it to be polite
        print("Closing Notepad...")
        close_result = await launcher.close_app("notepad")
        if close_result.success:
            print("✅ PASS: Notepad closed successfully.")
        else:
            print(f"⚠️ WARNING: Could not close Notepad: {close_result.error}")
            
    else:
        print(f"❌ FAIL: Launch failed - {result.error}")

if __name__ == "__main__":
    asyncio.run(verify_launch())
