"""
Test Groq AI Chat
"""

import requests
import json

print("\n" + "="*60)
print("  TESTING AETHER AI CHAT WITH GROQ")
print("="*60 + "\n")

print("Sending message to Aether AI...\n")

try:
    response = requests.post(
        'http://127.0.0.1:8000/api/v1/chat/conversation',
        json={
            'message': 'Hello! Please introduce yourself in 2-3 sentences.',
            'session_id': 'groq_test',
            'stream': False
        },
        timeout=30
    )
    
    if response.status_code == 200:
        data = response.json()
        
        print("="*60)
        print("SUCCESS! Aether AI is working with Groq!")
        print("="*60 + "\n")
        print(f"Aether AI: {data['content']}\n")
        print("="*60)
        print(f"Provider: {data['provider']}")
        print(f"Model: {data['model']}")
        print(f"Tokens: {data.get('tokens_used', 'N/A')}")
        print(f"Cost: ${data.get('cost_usd', 0):.6f}")
        print(f"Latency: {data.get('latency_ms', 'N/A')}ms")
        print("="*60 + "\n")
        
        print("AI Chat is now FULLY WORKING!")
        print("You can now use CHAT.bat to talk with Aether AI\n")
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        print("\nPlease restart the server:")
        print("  1. Press Ctrl+C in server window")
        print("  2. Run: CLICK-ME.bat or RUN.bat\n")

except Exception as e:
    print(f"Error: {e}")
    print("\nMake sure:")
    print("  1. Server is running")
    print("  2. Server was restarted after adding API key\n")
