"""
Live Voice Assistant Demo
Shows all voice-first capabilities:
- YouTube playback
- Teaching mode
- Bug bounty scanning
- Multitasking
"""

import asyncio
import aiohttp
import time

API_BASE = "http://localhost:8000/api/v1"


async def test_live_assistant():
    """Test all live assistant capabilities"""
    
    print("\n" + "="*70)
    print("🎙️  LIVE VOICE ASSISTANT DEMO")
    print("="*70 + "\n")
    
    async with aiohttp.ClientSession() as session:
        
        # Test 1: Open Browser
        print("\n🌐 Test 1: Open Browser")
        print("-" * 70)
        result = await send_command(session, "Open browser and go to Google")
        print(f"✅ Result: {result.get('action')}")
        await asyncio.sleep(3)
        
        # Test 2: Play YouTube
        print("\n🎵 Test 2: Play YouTube Music")
        print("-" * 70)
        result = await send_command(session, "Play Lofi hip hop on YouTube")
        print(f"✅ Result: {result.get('action')}")
        await asyncio.sleep(5)
        
        # Test 3: Teaching Mode (while music plays!)
        print("\n🎓 Test 3: Teaching Mode (Multitasking!)")
        print("-" * 70)
        result = await send_command(session, "Teach me Python functions")
        print(f"✅ Result: {result.get('action')}")
        print(f"📝 Topic: {result.get('data', {}).get('topic')}")
        await asyncio.sleep(10)  # Listen to teaching
        
        # Test 4: Bug Bounty Scan (in background)
        print("\n🐛 Test 4: Security Scan (Background)")
        print("-" * 70)
        result = await send_command(session, "Scan example.com for vulnerabilities")
        print(f"✅ Scan started: Task ID {result.get('data', {}).get('task_id')}")
        
        # Test 5: Check task status while scan runs
        print("\n📊 Test 5: Check Task Status")
        print("-" * 70)
        await asyncio.sleep(3)
        tasks = await get_active_tasks(session)
        for task in tasks.get('tasks', []):
            print(f"   📌 {task['name']}: {task['status']} ({task['progress']:.0f}%)")
        
        # Test 6: Search Google
        print("\n🔍 Test 6: Google Search")
        print("-" * 70)
        result = await send_command(session, "Search Google for Python tutorial")
        print(f"✅ Result: {result.get('action')}")
        await asyncio.sleep(3)
        
        # Test 7: CVE Search
        print("\n🔒 Test 7: CVE Database Search")
        print("-" * 70)
        result = await send_command(session, "Search CVE for Apache vulnerabilities")
        print(f"✅ Result: {result.get('action')}")
        print(f"📋 Found {len(result.get('data', {}).get('results', []))} CVEs")
        
        # Test 8: Pause tasks
        print("\n⏸️  Test 8: Pause All Tasks")
        print("-" * 70)
        result = await send_command(session, "Pause all tasks")
        print(f"✅ Result: {result.get('action')}")
        
        # Test 9: Resume tasks
        print("\n▶️  Test 9: Resume Tasks")
        print("-" * 70)
        await asyncio.sleep(2)
        result = await send_command(session, "Resume tasks")
        print(f"✅ Result: {result.get('action')}")
        
        # Test 10: General conversation
        print("\n💬 Test 10: General Conversation")
        print("-" * 70)
        result = await send_command(session, "What's your name?")
        print(f"✅ Response: {result.get('data', {}).get('response', 'N/A')[:100]}...")
        
        # Final status
        print("\n" + "="*70)
        print("✅ ALL TESTS COMPLETE!")
        print("="*70)
        
        # Show final task status
        tasks = await get_active_tasks(session)
        print(f"\n📊 Final Tasks: {len(tasks.get('tasks', []))} active")
        for task in tasks.get('tasks', []):
            print(f"   • {task['name']}: {task['status']} ({task['progress']:.0f}%)")


async def send_command(session: aiohttp.ClientSession, command: str) -> dict:
    """Send voice command to API"""
    print(f"🎤 Sending: \"{command}\"")
    
    try:
        async with session.post(
            f"{API_BASE}/live/command",
            json={"command": command}
        ) as response:
            if response.status == 200:
                result = await response.json()
                return result
            else:
                error = await response.text()
                print(f"❌ Error: {error}")
                return {"success": False, "error": error}
    
    except Exception as e:
        print(f"❌ Exception: {e}")
        return {"success": False, "error": str(e)}


async def get_active_tasks(session: aiohttp.ClientSession) -> dict:
    """Get active background tasks"""
    try:
        async with session.get(f"{API_BASE}/live/tasks") as response:
            if response.status == 200:
                return await response.json()
            else:
                return {"tasks": []}
    
    except Exception as e:
        print(f"❌ Error getting tasks: {e}")
        return {"tasks": []}


async def test_speak_directly():
    """Test direct speech (without command processing)"""
    print("\n🗣️  Testing Direct Speech...")
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{API_BASE}/live/speak",
            params={"text": "Ji boss! Aether AI ready hai! Koi bhi kaam batao!"}
        ) as response:
            if response.status == 200:
                print("✅ Speech test successful!")
            else:
                print(f"❌ Speech test failed: {await response.text()}")


async def check_health():
    """Check live assistant health"""
    print("\n🏥 Checking Health...")
    
    async with aiohttp.ClientSession() as session:
        async with session.get(f"{API_BASE}/live/health") as response:
            if response.status == 200:
                health = await response.json()
                print(f"✅ Status: {health['status']}")
                print(f"   Voice Enabled: {health['voice_enabled']}")
                print(f"   Active Tasks: {health['active_tasks']}")
                print(f"   Browser Running: {health['browser_running']}")
            else:
                print(f"❌ Health check failed")


if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║   🎙️  AETHER AI - LIVE VOICE ASSISTANT DEMO 🎙️                 ║
    ║                                                                  ║
    ║   This demo shows TRUE human-like multitasking:                 ║
    ║   - Talks while working (not just results)                      ║
    ║   - Opens browser, plays YouTube, teaches code                  ║
    ║   - Runs security scans in background                           ║
    ║   - Conversational task control                                 ║
    ║                                                                  ║
    ║   🎯 100% Voice-First - No Typing Required!                     ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    ⚠️  IMPORTANT: Start the API server first!
    
        cd C:\\Users\\nandk\\aether-ai
        python -m src.api.main_clean
    
    Press Ctrl+C to stop the demo at any time.
    """)
    
    input("\n📢 Press ENTER when API server is running...\n")
    
    try:
        # Run all tests
        asyncio.run(check_health())
        time.sleep(1)
        
        asyncio.run(test_speak_directly())
        time.sleep(2)
        
        asyncio.run(test_live_assistant())
        
        print("\n✅ Demo complete! Check the API logs for voice output.\n")
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo stopped by user.")
    
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
