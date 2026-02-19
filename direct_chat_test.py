import requests
import json

print("=== AETHER AI DIRECT CHAT TEST ===\n")

tests = [
    {
        "name": "1. Basic Hello",
        "prompt": "Hello! Who are you? Answer in 10 words.",
        "task_type": "conversation"
    },
    {
        "name": "2. Vision Awareness",
        "prompt": "Can you see my screen?",
        "task_type": "conversation"
    },
    {
        "name": "3. Hinglish Response",
        "prompt": "Boss aaj kya plan hai?",
        "task_type": "conversation"
    },
    {
        "name": "4. Automation Knowledge",
        "prompt": "What apps can you open?",
        "task_type": "automation"
    }
]

for test in tests:
    print(f"\nTEST: {test['name']}")
    print(f"Prompt: {test['prompt']}")
    print("-" * 60)
    
    try:
        response = requests.post(
            "http://localhost:8000/api/v1/chat/",
            json={
                "prompt": test['prompt'],
                "task_type": test['task_type'],
                "temperature": 0.7,
                "max_tokens": 150
            },
            timeout=20
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"RESPONSE: {data.get('content', 'No content')}")
            print(f"Model: {data.get('model')}, Cost: ${data.get('cost_usd', 0):.4f}, Time: {data.get('latency_ms', 0)}ms")
            print("STATUS: PASS")
        else:
            print(f"ERROR: Status {response.status_code}")
            print(f"Response: {response.text[:200]}")
            print("STATUS: FAIL")
            
    except requests.exceptions.Timeout:
        print("ERROR: Timeout after 20 seconds")
        print("STATUS: FAIL")
    except Exception as e:
        print(f"ERROR: {e}")
        print("STATUS: FAIL")

print("\n" + "=" * 60)
print("Testing complete! Check if Aether:")
print("1. Identifies as Aether (not generic AI)")
print("2. Knows it can see the screen")
print("3. Responds in Hinglish when asked")
print("4. Knows about automation capabilities")
