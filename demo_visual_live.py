"""
Visual Live Execution Demo
Shows REAL windows opening, BurpSuite launching, live scans
Everything visible like a human working!
"""

import asyncio
import aiohttp
import time

API_BASE = "http://localhost:8000/api/v1"


async def test_visual_execution():
    """Test visual live execution capabilities"""
    
    print("\n" + "="*70)
    print("  VISUAL LIVE EXECUTION DEMO - REAL WINDOWS, REAL TOOLS")
    print("="*70 + "\n")
    
    print("[INFO] This demo shows:")
    print("  1. REAL CMD windows opening (visible)")
    print("  2. BurpSuite GUI launching")
    print("  3. Nuclei scans running in live windows")
    print("  4. Everything you can SEE happening\n")
    
    input("Press Enter to start the demo...")
    
    async with aiohttp.ClientSession() as session:
        
        # Test 1: Open CMD Window
        print("\n[TEST 1] Opening CMD Window")
        print("-" * 70)
        result = await send_command(session, "Open cmd terminal")
        print(f"[OK] CMD window opened: {result.get('success')}")
        await asyncio.sleep(3)
        
        # Test 2: Launch BurpSuite
        print("\n[TEST 2] Launching BurpSuite GUI")
        print("-" * 70)
        print("[NOTE] BurpSuite must be installed for this to work")
        result = await send_command(session, "Launch BurpSuite")
        print(f"[OK] BurpSuite launch: {result.get('success')}")
        if not result.get('success'):
            print(f"[INFO] {result.get('message', 'BurpSuite not found')}")
        await asyncio.sleep(5)
        
        # Test 3: Run Nuclei Scan in VISIBLE Window
        print("\n[TEST 3] Running Nuclei Scan in LIVE Window")
        print("-" * 70)
        print("[NOTE] You will see a CMD window open with scan running")
        result = await send_command(session, "Scan example.com for vulnerabilities")
        print(f"[OK] Scan started in visible window")
        print("[WATCH] Check the CMD window that just opened!")
        print("[INFO] You can see the scan running LIVE with all output")
        await asyncio.sleep(10)
        
        # Test 4: Run Custom Command in CMD
        print("\n[TEST 4] Running Custom Command in Visible Window")
        print("-" * 70)
        result = await send_command(session, "Open cmd run ipconfig /all")
        print(f"[OK] Command running in visible window")
        await asyncio.sleep(3)
        
        # Test 5: Multiple Windows
        print("\n[TEST 5] Opening Multiple Windows Simultaneously")
        print("-" * 70)
        print("[NOTE] Watch multiple CMD windows open!")
        
        await send_command(session, "Open cmd run echo Hello from Window 1!")
        await asyncio.sleep(1)
        await send_command(session, "Open cmd run ping google.com")
        await asyncio.sleep(1)
        await send_command(session, "Open cmd run dir C:\\")
        
        print("[OK] Multiple windows opened - all visible!")
        await asyncio.sleep(5)
        
        # Test 6: Check Active Tasks
        print("\n[TEST 6] Checking Active Tasks")
        print("-" * 70)
        tasks = await get_active_tasks(session)
        print(f"[INFO] Active tasks: {tasks.get('count', 0)}")
        for task in tasks.get('tasks', []):
            print(f"  - {task['name']}: {task['status']} ({task['progress']:.0f}%)")
        
        print("\n" + "="*70)
        print("  DEMO COMPLETE!")
        print("="*70)
        
        print("\n[SUMMARY] What You Saw:")
        print("  [+] Real CMD windows opening (not background)")
        print("  [+] BurpSuite GUI launching (if installed)")
        print("  [+] Nuclei scan running in visible window")
        print("  [+] Custom commands executing in live windows")
        print("  [+] Multiple simultaneous visible windows")
        
        print("\n[HOW IT WORKS]:")
        print("  - Uses Windows 'start' command to open new windows")
        print("  - All processes stay visible (not hidden)")
        print("  - You can see EVERYTHING happening in real-time")
        print("  - BurpSuite GUI opens just like you would manually")
        print("  - Nuclei scans show live output in CMD window")
        
        print("\n[VOICE COMMANDS YOU CAN USE]:")
        print("  - 'Launch BurpSuite'")
        print("  - 'Open cmd terminal'")
        print("  - 'Open cmd run [your command]'")
        print("  - 'Scan example.com for vulnerabilities'")
        print("  - 'Search CVE for Apache'")
        
        print("\n[NOTE] Close the opened windows manually when done.")
        print("       All windows stay open so you can review results.\n")


async def send_command(session, command: str) -> dict:
    """Send voice command to API"""
    try:
        async with session.post(
            f"{API_BASE}/live/command",
            json={"command": command},
            timeout=aiohttp.ClientTimeout(total=30)
        ) as resp:
            return await resp.json()
    except Exception as e:
        print(f"[ERROR] Command failed: {e}")
        return {"success": False, "error": str(e)}


async def get_active_tasks(session) -> dict:
    """Get active tasks"""
    try:
        async with session.get(
            f"{API_BASE}/live/tasks",
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            return await resp.json()
    except Exception as e:
        print(f"[ERROR] Get tasks failed: {e}")
        return {"tasks": [], "count": 0}


if __name__ == "__main__":
    print("\n" + "="*70)
    print("  AETHER AI v4.5 - VISUAL LIVE EXECUTION")
    print("="*70)
    print("\n[PREREQUISITE] Make sure the server is running:")
    print("  uvicorn src.api.main_clean:app --reload\n")
    
    try:
        asyncio.run(test_visual_execution())
    except KeyboardInterrupt:
        print("\n\n[STOPPED] Demo interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
