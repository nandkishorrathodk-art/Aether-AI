import time
from typing import List, Dict, Optional, Any
from openai import AsyncOpenAI
from .base import BaseAIProvider, AIResponse
from src.config import settings


class OpenRouterProvider(BaseAIProvider):
    PRICING = {
        "anthropic/claude-3-opus": {"input": 0.015, "output": 0.075},
        "anthropic/claude-3-sonnet": {"input": 0.003, "output": 0.015},
        "openai/gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "openai/gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        "meta-llama/llama-3-70b-instruct": {"input": 0.00059, "output": 0.00079},
        "google/gemini-pro-1.5": {"input": 0.00035, "output": 0.00105},
        "mistralai/mixtral-8x7b-instruct": {"input": 0.00024, "output": 0.00024},
        "minimax/minimax-m2.5": {"input": 0.001, "output": 0.001},  # Added Minimax Pricing
    }

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_key, **kwargs)
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1"
        )
        self.default_model = settings.default_model

    async def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs
    ) -> AIResponse:
        start_time = time.time()
        model = model or self.default_model

        response = await self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )

        latency_ms = (time.time() - start_time) * 1000
        tokens_used = response.usage.total_tokens if response.usage else 0
        cost = self.calculate_cost(tokens_used, model)

        return AIResponse(
            content=response.choices[0].message.content,
            model=model,
            provider=self.get_provider_name(),
            tokens_used=tokens_used,
            cost_usd=cost,
            latency_ms=latency_ms,
            metadata={
                "finish_reason": response.choices[0].finish_reason,
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
            }
        )

    async def stream_generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs
    ):
        model = model or self.default_model
        stream = await self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            **kwargs
        )

        async for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def get_available_models(self) -> List[str]:
        return list(self.PRICING.keys())

    def calculate_cost(self, tokens_used: int, model: str) -> float:
        if model not in self.PRICING:
            return 0.0
        avg_price = (self.PRICING[model]["input"] + self.PRICING[model]["output"]) / 2
        return (tokens_used / 1000) * avg_price

    def get_provider_name(self) -> str:
        return "openrouter"

    def supports_vision(self) -> bool:
        return True

    def supports_function_calling(self) -> bool:
        return True

    def get_max_context_length(self, model: str) -> int:
        return 128000
