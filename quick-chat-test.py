import requests
import json

response = requests.post(
    'http://127.0.0.1:8000/api/v1/chat/conversation',
    json={
        'message': 'Hello! Please introduce yourself in one sentence.',
        'session_id': 'test123'
    },
    timeout=30
)

if response.status_code == 200:
    data = response.json()
    print("\n" + "="*60)
    print("Aether AI Response:")
    print("="*60)
    print(data['content'])
    print("\nProvider:", data['provider'])
    print("Model:", data['model'])
    print("="*60 + "\n")
else:
    print(f"Error: {response.status_code}")
    print(response.text)
