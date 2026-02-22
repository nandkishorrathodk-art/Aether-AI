import pytest
import asyncio
from src.core.brain.reasoning import reasoning
from src.core.brain.cost_tracker import cost_tracker
from src.core.brain.memory import memory
from src.core.brain.context import ConversationContext
from src.core.brain.router import ModelRouter, RouterRequest

def test_reasoning_cot_prompt():
    prompt = "What is 2+2?"
    cot_prompt = reasoning.generate_cot_prompt(prompt)
    assert "think step-by-step" in cot_prompt
    assert prompt in cot_prompt

def test_reasoning_reflection_prompt():
    prompt = "What is 2+2?"
    draft = "It might be 4."
    reflection_prompt = reasoning.generate_reflection_prompt(prompt, draft)
    assert "expert reviewer" in reflection_prompt
    assert prompt in reflection_prompt
    assert draft in reflection_prompt

def test_cost_tracker_calculation():
    # Test Fireworks pricing
    usage = cost_tracker.calculate_cost("accounts/fireworks/models/deepseek-v3p1", 1000, 1000)
    assert usage.prompt_tokens == 1000
    assert usage.completion_tokens == 1000
    assert usage.total_tokens == 2000
    assert usage.estimated_cost_usd == 0.00042 # (0.00014 + 0.00028)

def test_context_window_trimming():
    ctx = ConversationContext(max_history_tokens=10) # tiny limit for testing
    # 20 chars = 5 tokens
    ctx.add_message("system", "You are an AI.") 
    ctx.add_message("user", "Hello there!") 
    assert len(ctx.messages) == 2
    
    # Adding more pushes it over 10 tokens. System msg should stay, user msg drops.
    ctx.add_message("user", "Another long message")
    assert len(ctx.messages) == 2
    assert ctx.messages[0].role == "system"

@pytest.mark.asyncio
async def test_semantic_memory_integration():
    # Store a mock memory
    success = await memory.store_memory("test_id", "This is a test summary")
    assert success is True
    
    # Retrieve it
    results = await memory.retrieve_relevant_context("test")
    # In Phase 3 mock mode, it returns everything it has up to limit
    assert len(results) > 0
    assert "payload" in results[0]

@pytest.mark.asyncio
async def test_router_integration():
    router = ModelRouter()
    req = RouterRequest(prompt="Test prompt", task_type="reasoning")
    
    result = await router.route_request(req)
    
    assert "response" in result
    assert "conversation_id" in result
    assert "usage" in result
    assert "cost_usd" in result["usage"] or "estimated_cost_usd" in result["usage"]
    assert result["provider"] == "fireworks"
