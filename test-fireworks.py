"""Quick test for Fireworks AI API"""
import os
import sys
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Suppress warnings
import warnings
warnings.filterwarnings('ignore')

print("=" * 60)
print("Testing Fireworks AI Connection")
print("=" * 60)
print()

# Check API key
api_key = os.getenv("FIREWORKS_API_KEY")
if not api_key:
    print("❌ ERROR: FIREWORKS_API_KEY not found in .env")
    sys.exit(1)

print(f"✓ API Key found: {api_key[:10]}...")
print()

# Test connection
print("Testing AI response...")
try:
    from openai import OpenAI
    
    client = OpenAI(
        api_key=api_key,
        base_url="https://api.fireworks.ai/inference/v1"
    )
    
    response = client.chat.completions.create(
        model="accounts/fireworks/models/llama-v3p1-8b-instruct",
        messages=[{"role": "user", "content": "Say 'Aether AI is ready!' in one sentence"}],
        max_tokens=50
    )
    
    print("✅ SUCCESS!")
    print()
    print("AI Response:")
    print("-" * 60)
    print(response.choices[0].message.content)
    print("-" * 60)
    print()
    print("✅ Fireworks AI is working correctly!")
    
except Exception as e:
    print(f"❌ ERROR: {e}")
    sys.exit(1)
