"""Test Aether AI Chat Endpoint"""
import requests
import json

# Test chat endpoint with Groq (fastest and free)
url = "http://127.0.0.1:8000/api/v1/chat"

payload = {
    "prompt": "What is 2+2? Answer in one word.",
    "task_type": "conversation",
    "provider": "groq",
    "model": "llama3-8b-8192"
}

print("Testing Aether AI Chat Endpoint...")
print(f"Prompt: {payload['prompt']}")
print(f"Provider: {payload['provider']}")
print(f"Model: {payload['model']}\n")

try:
    response = requests.post(url, json=payload, timeout=30)
    
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print("\n✓ CHAT SUCCESS")
        print(f"Response: {data.get('response', 'N/A')}")
        print(f"Provider Used: {data.get('provider_used', 'N/A')}")
        print(f"Model Used: {data.get('model_used', 'N/A')}")
        
        if 'metadata' in data:
            print(f"\nMetadata:")
            print(f"  - Tokens: {data['metadata'].get('total_tokens', 'N/A')}")
            print(f"  - Cost: ${data['metadata'].get('cost', 0):.6f}")
    else:
        print(f"\n✗ Error: {response.text}")
        
except Exception as e:
    print(f"\n✗ Exception: {e}")
