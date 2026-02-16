import requests
import json

print("\nTesting Aether AI with Fireworks provider...\n")

response = requests.post(
    'http://127.0.0.1:8000/api/v1/chat/',
    json={
        'prompt': 'Hello! Please introduce yourself in one sentence.',
        'task_type': 'conversation',
        'provider': 'fireworks',
        'model': 'accounts/fireworks/models/llama-v3-70b-instruct'
    },
    timeout=30
)

if response.status_code == 200:
    data = response.json()
    print("="*60)
    print("SUCCESS! Aether AI is working!")
    print("="*60)
    print(f"\nAether AI: {data['content']}\n")
    print(f"Provider: {data['provider']}")
    print(f"Model: {data['model']}")
    print(f"Cost: ${data.get('cost_usd', 0):.6f}")
    print("="*60 + "\n")
else:
    print(f"Error: {response.status_code}")
    print(response.text)
