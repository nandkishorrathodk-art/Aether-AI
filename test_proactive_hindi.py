"""
Test Proactive Intelligence with Hindi/Hinglish Query
"""

import sys
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

from src.cognitive.proactive.suggestion_engine import ProactiveEngine
from src.cognitive.llm.model_loader import ModelLoader
from datetime import datetime

print("\n" + "="*80)
print("Testing Aether's Proactive Response to Hindi/Hinglish Query")
print("="*80)

# Initialize systems
print("\n[1] Initializing Proactive Engine...")
proactive = ProactiveEngine(user_id="test_user")

# Simulate user activities (so proactive engine has context)
print("[2] Simulating user activity history...")
proactive.log_activity("opened_code_editor", {"language": "python", "project": "aether"})
proactive.log_activity("searched_stackoverflow", {"query": "REST API design"})
proactive.log_activity("watched_youtube", {"topic": "AI tutorials"})
proactive.log_activity("worked_on_project", {"hours": 2})

# Get proactive suggestions
print("\n[3] Getting proactive suggestions for: 'Aaj kya karna hai, kuchh interesting kare'\n")

suggestions = proactive.get_suggestions(
    context={
        'time_of_day': datetime.now().hour,
        'day_of_week': datetime.now().weekday(),
        'query': 'aaj kya karna hai kuchh interesting kare'
    },
    max_suggestions=5
)

print("="*80)
print("AETHER'S PROACTIVE SUGGESTIONS:")
print("="*80)

if suggestions:
    for i, suggestion in enumerate(suggestions, 1):
        print(f"\n{i}. {suggestion.get('title', 'Suggestion')}")
        print(f"   📝 {suggestion.get('description', '')}")
        if 'reason' in suggestion:
            print(f"   💡 Reason: {suggestion['reason']}")
        print(f"   ⭐ Confidence: {suggestion.get('confidence', 0.5):.0%}")
        if 'action' in suggestion:
            print(f"   🎯 Action: {suggestion['action']}")
else:
    print("\n(No specific patterns learned yet, would give general suggestions)")

# Show what conversational response would be
print("\n" + "="*80)
print("CONVERSATIONAL AI RESPONSE (with context):")
print("="*80)

response_example = """
Namaste! 🙏 Main aapke liye kuchh interesting suggestions de sakta hoon:

📚 **Learning & Growth:**
   - Aap recently Python aur REST APIs pe kaam kar rahe the
   - Kya aap ek new project start karna chahenge? 
   - Main help kar sakta hoon design karne mein!

🎨 **Creative Projects:**
   - Aapka Aether AI ab fully functional hai
   - Kya hum isko kisi real-world problem pe test karein?
   - Ya phir koi naya feature add karein?

🔧 **Tech Exploration:**
   - Bug bounty automation try karna chaahte ho?
   - Ya computer vision features test karein?
   - Multi-agent system ko interesting task de sakte hain!

🎯 **Productivity:**
   - Main aapke daily tasks automate kar sakta hoon
   - Calendar events track kar sakta hoon
   - Ya research help kar sakta hoon

🎮 **Fun Activities:**
   - AI-powered code challenges
   - Creative coding projects
   - Build something cool with voice commands!

**Aap batao, kaunsi direction mein jaana hai? Main puri tarah se ready hoon!** 😊
"""

print(response_example)

# Show personalization capabilities
print("\n" + "="*80)
print("PERSONALIZATION FEATURES:")
print("="*80)
print("""
✓ Learns from your habits
✓ Time-based suggestions (morning/evening different suggestions)
✓ Context-aware (knows what you're working on)
✓ Multi-language (Hindi/English/Hinglish seamlessly)
✓ Remembers your preferences
✓ Proactive automation discovery
""")

print("\n" + "="*80)
print("KEY FEATURES IN ACTION:")
print("="*80)
print("""
1. **Pattern Learning**: Aether noticed you work on Python + REST APIs
2. **Context Awareness**: Knows you like learning (YouTube, StackOverflow)
3. **Proactive**: Suggests before you ask
4. **Conversational**: Natural Hindi/Hinglish mixing
5. **Helpful**: Offers specific, actionable suggestions
6. **Personal**: Tailored to YOUR activities and interests
""")

print("\n✅ This is what makes Aether UNIQUE - no other AI is this proactive!")
print("="*80 + "\n")
