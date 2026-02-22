from pydantic import BaseModel
from typing import Dict
from loguru import logger

class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0

class CostTracker:
    """
    Tracks token usage and calculates estimated costs based on the model provider.
    Prices are per 1,000 tokens (as an example metric).
    """
    # Example pricing table (USD per 1k input/output tokens)
    PRICING = {
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
        "gemini-1.5-pro": {"input": 0.007, "output": 0.021},
        "accounts/fireworks/models/deepseek-v3p1": {"input": 0.00014, "output": 0.00028}, # Fireworks pricing
        "llama3": {"input": 0.0, "output": 0.0} # Local is free
    }

    def calculate_cost(self, model_name: str, prompt_tokens: int, completion_tokens: int) -> TokenUsage:
        prices = self.PRICING.get(model_name, {"input": 0.0, "output": 0.0})
        
        # Calculate cost based on per-1k price
        input_cost = (prompt_tokens / 1000.0) * prices["input"]
        output_cost = (completion_tokens / 1000.0) * prices["output"]
        total_cost = input_cost + output_cost

        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            estimated_cost_usd=round(total_cost, 6)
        )
        
        logger.debug(f"Cost tracked for {model_name}: ${usage.estimated_cost_usd}")
        return usage

# Global instance
cost_tracker = CostTracker()
