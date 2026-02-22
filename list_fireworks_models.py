import os
import asyncio
from openai import AsyncOpenAI
from dotenv import load_dotenv

async def list_models():
    # Try to load from the worktree .env first
    env_path = r"C:\Users\nandk\.zenflow\worktrees\aether-00f9\aether-ai-repo\.env"
    load_dotenv(env_path)
    
    api_key = os.getenv("FIREWORKS_API_KEY")
    if not api_key:
        print("Error: FIREWORKS_API_KEY not found in .env")
        # Try finding .env in the same dir
        load_dotenv(".env")
        api_key = os.getenv("FIREWORKS_API_KEY")
        if not api_key:
            return

    print(f"Using API Key starting with: {api_key[:10]}...")
    client = AsyncOpenAI(
        api_key=api_key,
        base_url="https://api.fireworks.ai/inference/v1"
    )

    try:
        models = await client.models.list()
        with open("models.txt", "w") as f:
            for model in models.data:
                f.write(f"{model.id}\n")
        print(f"Total Models Found: {len(models.data)}. List saved to models.txt")
    except Exception as e:
        print(f"Error listing models: {e}")

if __name__ == "__main__":
    asyncio.run(list_models())
