import os
import requests
import json

API_KEY = "fw_GzB2Zvh5tiZ8cQ31Hud8NJ"
BASE_URL = "https://api.fireworks.ai/inference/v1/chat/completions"

models_to_test = [
    "accounts/fireworks/models/deepseek-v2p5",
    "accounts/fireworks/models/deepseek-v3",
    "accounts/fireworks/models/llama-v3p1-70b-instruct",
    "accounts/fireworks/models/llama-v3p1-8b-instruct",
    "accounts/fireworks/models/mixtral-8x7b-instruct",
    "accounts/fireworks/models/firellava-13b",
]

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

print(f"Testing API Key: {API_KEY[:5]}...")

for model in models_to_test:
    print(f"\nTesting model: {model}")
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Hello"}],
        "max_tokens": 10
    }
    
    try:
        response = requests.post(BASE_URL, headers=headers, json=payload)
        if response.status_code == 200:
            print(f"✅ SUCCESS! {model} works.")
            print("Response:", response.json()['choices'][0]['message']['content'])
            break # Found a working one
        else:
            print(f"❌ FAILED. Status: {response.status_code}")
            print("Error:", response.text)
    except Exception as e:
        print(f"❌ Exception: {e}")
