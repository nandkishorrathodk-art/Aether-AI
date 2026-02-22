
import asyncio
import sys
import os

sys.path.append(os.getcwd())

from src.cognitive.llm.model_loader import model_loader
from src.cognitive.llm.providers.base import TaskType
from src.config import settings

async def test_loader():
    print(f"Testing Model Loader with settings.router_conversation={settings.router_conversation}...")
    try:
        response = await model_loader.generate(
            prompt="Hello, who are you?",
            task_type=TaskType.CONVERSATION
        )
        print(f"Response: {response.content}")
        print(f"Provider: {response.provider}")
        print(f"Model: {response.model}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_loader())
