import requests
import sys

print("Testing Aether backend...")

try:
    print("1. Checking providers endpoint...")
    response = requests.get("http://localhost:8000/api/v1/chat/providers", timeout=3)
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        print(f"   Success! Found providers: {list(response.json().get('providers', {}).keys())}")
    else:
        print(f"   Error: {response.text}")
        sys.exit(1)
    
    print("\n2. Testing simple chat...")
    response = requests.post(
        "http://localhost:8000/api/v1/chat/",
        json={"prompt": "Say hi in 5 words", "task_type": "conversation", "max_tokens": 50},
        timeout=15
    )
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"   Response: {data.get('content', 'No content')}")
        print(f"   Model: {data.get('model')}, Cost: ${data.get('cost_usd', 0):.4f}")
        print("\n SUCCESS! Backend is working!")
    else:
        print(f"   Error: {response.text}")
        sys.exit(1)
        
except requests.exceptions.Timeout:
    print("ERROR: Request timed out. Backend might be overloaded.")
    sys.exit(1)
except requests.exceptions.ConnectionError:
    print("ERROR: Cannot connect to backend. Is it running on port 8000?")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
