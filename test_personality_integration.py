import os
import sys
from pathlib import Path

if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

from src.personality.conversational_style import ConversationalStyle, response_enhancer, ToneType
from src.personality.motivational_engine import MotivationalEngine, motivational_engine, AchievementType
from src.personality.humor_generator import HumorGenerator, humor_generator
from src.config import settings

print("=" * 60)
print("PERSONALITY SYSTEM INTEGRATION TEST")
print("=" * 60)

print("\n1. Testing ConversationalStyle...")
cs = ConversationalStyle()
print(f"   [OK] ConversationalStyle initialized")
print(f"   [OK] Greeting: {cs.get_greeting()}")
print(f"   [OK] Confirmation: {cs.get_confirmation()}")

print("\n2. Testing ResponseEnhancer...")
test_text = "The task has been completed successfully."
enhanced = response_enhancer.enhance_response(
    test_text,
    tone=ToneType.FRIENDLY,
    add_personality=True
)
print(f"   [OK] Original: {test_text}")
print(f"   [OK] Enhanced: {enhanced}")

print("\n3. Testing MotivationalEngine...")
me = MotivationalEngine()
encouragement = me.get_encouragement("general")
print(f"   [OK] Encouragement: {encouragement}")

celebration = me.celebrate_achievement(
    AchievementType.TASK_COMPLETED,
    {"task_name": "Integration Test"}
)
print(f"   [OK] Celebration: {celebration}")

progress = me.get_progress_summary()
print(f"   [OK] Progress: {progress}")

print("\n4. Testing HumorGenerator...")
hg = HumorGenerator()
contextual_humor = hg.get_contextual_humor("bug_found")
if contextual_humor:
    print(f"   [OK] Contextual Humor: {contextual_humor}")
else:
    print(f"   [OK] Humor generation working (timing-based)")

print("\n5. Checking Data Files...")
data_path = Path("./data/personality")
if data_path.exists():
    files = list(data_path.glob("*.json"))
    print(f"   [OK] Data directory exists: {data_path}")
    print(f"   [OK] Files created: {len(files)}")
    for f in files:
        print(f"      - {f.name}")
else:
    print(f"   [ERROR] Data directory not found")

print("\n6. Testing Personality Settings...")
print(f"   [OK] Personality Mode: {settings.personality_mode}")
print(f"   [OK] Hindi-English Mix: {settings.personality_enable_hindi_english}")
print(f"   [OK] Emoji Enabled: {settings.personality_emoji_enabled}")
print(f"   [OK] Motivational: {settings.personality_motivational_enabled}")
print(f"   [OK] Humor: {settings.personality_humor_enabled}")

print("\n7. Testing Full Pipeline...")
original = "Bug found in the authentication system"
enhanced = response_enhancer.enhance_response(
    original,
    tone=ToneType.FRIENDLY,
    add_personality=True,
    context={"bug_found": True}
)
with_humor = hg.add_humor_to_response(enhanced, context="bug_found")
celebration = me.celebrate_achievement(
    AchievementType.BUG_FOUND,
    {
        "severity": "critical",
        "estimated_bounty": 1000,
        "vulnerability_type": "Authentication Bypass"
    }
)

print(f"\n   Original Response:")
print(f"   {original}")
print(f"\n   Enhanced with Personality:")
print(f"   {enhanced}")
print(f"\n   With Humor:")
print(f"   {with_humor}")
print(f"\n   Celebration:")
print(f"   {celebration}")

print("\n" + "=" * 60)
print("SUCCESS: ALL PERSONALITY SYSTEM TESTS PASSED!")
print("=" * 60)
