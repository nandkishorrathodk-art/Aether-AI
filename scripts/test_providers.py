import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.cognitive.llm import model_loader, TaskType
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


async def test_providers():
    print("=" * 60)
    print("AETHER AI - Multi-Provider Test")
    print("=" * 60)
    
    print("\n[1] Available Providers:")
    providers = model_loader.get_available_providers()
    print(f"   {', '.join(providers)}")
    
    print("\n[2] Provider Details:")
    stats = model_loader.get_provider_stats()
    for name, info in stats.items():
        print(f"\n   {name.upper()}:")
        print(f"      Models: {', '.join(info['models'][:3])}...")
        print(f"      Vision: {info['supports_vision']}")
        print(f"      Functions: {info['supports_function_calling']}")
    
    print("\n" + "=" * 60)
    print("Testing Conversation Task")
    print("=" * 60)
    
    try:
        response = await model_loader.generate(
            prompt="What is 2+2? Answer in one sentence.",
            task_type=TaskType.CONVERSATION,
            system_prompt="You are a helpful AI assistant.",
        )
        
        print(f"\n✓ Response: {response.content}")
        print(f"  Provider: {response.provider}")
        print(f"  Model: {response.model}")
        print(f"  Tokens: {response.tokens_used}")
        print(f"  Cost: ${response.cost_usd:.6f}")
        print(f"  Latency: {response.latency_ms:.0f}ms")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
    
    print("\n" + "=" * 60)
    print("Testing Code Task")
    print("=" * 60)
    
    try:
        response = await model_loader.generate(
            prompt="Write a Python function to calculate fibonacci numbers. Just the code, no explanation.",
            task_type=TaskType.CODE,
        )
        
        print(f"\n✓ Generated code:")
        print(response.content[:200] + "...")
        print(f"  Provider: {response.provider}")
        print(f"  Model: {response.model}")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
    
    print("\n" + "=" * 60)
    print("Cost Statistics (Last 24 hours)")
    print("=" * 60)
    
    cost_stats = model_loader.get_cost_stats(hours=24)
    print(f"\n  Total Cost: ${cost_stats['total_cost']:.4f}")
    print(f"  Total Requests: {cost_stats['total_requests']}")
    print(f"  Avg Cost/Request: ${cost_stats['avg_cost_per_request']:.6f}")
    print(f"  Avg Latency: {cost_stats['avg_latency_ms']:.0f}ms")
    
    if cost_stats['by_provider']:
        print(f"\n  Cost by Provider:")
        for provider, cost in cost_stats['by_provider'].items():
            print(f"     {provider}: ${cost:.6f}")
    
    print("\n" + "=" * 60)
    print("Test Complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_providers())
