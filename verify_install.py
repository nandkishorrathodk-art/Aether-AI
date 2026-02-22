"""
Quick Verification - Check if Live Voice Assistant is installed
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

print("\n" + "="*70)
print("  AETHER AI v4.5 - LIVE VOICE ASSISTANT VERIFICATION")
print("="*70 + "\n")

# Test imports
print("[1/5] Checking core imports...")
try:
    from src.core.live_assistant import LiveVoiceAssistant
    print("      [OK] Live Assistant core")
except Exception as e:
    print(f"      [FAIL] {e}")
    sys.exit(1)

print("\n[2/5] Checking API imports...")
try:
    from src.api.live_assistant_api import router
    print("      [OK] Live Assistant API")
except Exception as e:
    print(f"      [FAIL] {e}")
    sys.exit(1)

print("\n[3/5] Checking voice pipeline...")
try:
    from src.pipeline.voice_pipeline import VoicePipelineOrchestrator
    print("      [OK] Voice Pipeline")
except Exception as e:
    print(f"      [FAIL] {e}")
    sys.exit(1)

print("\n[4/5] Checking automation...")
try:
    from src.automation.browser_controller import BrowserController
    from src.control.pc_controller import PCController
    print("      [OK] Browser & PC Control")
except Exception as e:
    print(f"      [FAIL] {e}")
    sys.exit(1)

print("\n[5/5] Checking security modules...")
try:
    from src.security.nuclei_scanner import get_nuclei_scanner
    from src.security.cve_database import get_cve_database
    print("      [OK] Security Suite (Nuclei + CVE)")
except Exception as e:
    print(f"      [FAIL] {e}")
    sys.exit(1)

print("\n" + "="*70)
print("  [SUCCESS] ALL MODULES INSTALLED CORRECTLY!")
print("="*70)

print("\n[READY] Live Voice Assistant v4.5 Features:")
print("  [+] Voice-first multitasking (Hinglish)")
print("  [+] Browser automation (Chrome/Edge)")
print("  [+] YouTube control (search + play)")
print("  [+] Teaching mode (live code lessons)")
print("  [+] Bug bounty automation (Nuclei + CVE database)")
print("  [+] Real parallel multitasking")
print("  [+] Conversational task control")

print("\n[START] To run the system:")
print("  1. Start API server:")
print("     uvicorn src.api.main_clean:app --host 0.0.0.0 --port 8000")
print("\n  2. In another terminal, run demo:")
print("     python demo_live_assistant.py")
print("\n  3. Or use voice commands via API:")
print("     POST http://localhost:8000/api/v1/live/command")
print("     { \"command\": \"Play Lofi hip hop on YouTube\" }")

print("\n[EXAMPLES] Voice Commands You Can Use:")
print("  - 'Open browser and search Python tutorial'")
print("  - 'Play Lofi hip hop on YouTube'")
print("  - 'Teach me Python functions'")
print("  - 'Scan apple.com for vulnerabilities'")
print("  - 'Search CVE for Apache'")
print("  - 'Pause that scan'")
print("  - 'What's the status?'")
print("  - 'Resume tasks'")

print("\n[NOTE] System will respond in Hinglish (Hindi + English mix)")
print("       Example: 'Boss! Scan shuru ho gaya... Templates load ho rahe hain...'")

print("\n" + "="*70 + "\n")
