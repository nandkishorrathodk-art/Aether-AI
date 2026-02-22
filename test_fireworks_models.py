
import asyncio
import os
import sys
from openai import AsyncOpenAI

# Load env vars manually or use python-dotenv if available, but for now just read the file or assume loaded if run in venv
# Actually, I'll just hardcode the key from the .env I saw earlier for this test script to be sure
# Key from user: fw_FBBHpyHVgPch5Twj8ik14Z

API_KEY = "fw_FBBHpyHVgPch5Twj8ik14Z" 

MODELS_TO_TEST = [
    "accounts/fireworks/models/llama-v3p1-70b-instruct",
    "accounts/fireworks/models/llama-v3-70b-instruct",
    "accounts/fireworks/models/llama-v3p3-70b-instruct",
    "accounts/fireworks/models/mixtral-8x7b-instruct",
    "accounts/fireworks/models/qwen2p5-72b-instruct",
]

async def test_models():
    client = AsyncOpenAI(
        api_key=API_KEY,
        base_url="https://api.fireworks.ai/inference/v1"
    )
    
    for model in MODELS_TO_TEST:
        print(f"Testing model: {model}...")
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Hi"}],
                max_tokens=10
            )
            print(f"✅ SUCCESS: {model}")
            print(f"Output: {response.choices[0].message.content}")
            return
        except Exception as e:
            print(f"❌ FAILED: {model} - {e}")

if __name__ == "__main__":
    asyncio.run(test_models())
