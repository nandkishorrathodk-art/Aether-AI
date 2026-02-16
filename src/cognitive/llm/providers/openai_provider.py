import time
from typing import List, Dict, Optional, Any
from openai import AsyncOpenAI
import httpx
from .base import BaseAIProvider, AIResponse


class OpenAIProvider(BaseAIProvider):
    PRICING = {
        "gpt-4o": {"input": 0.0025, "output": 0.01},
        "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-32k": {"input": 0.06, "output": 0.12},
        "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        "gpt-3.5-turbo-16k": {"input": 0.001, "output": 0.002},
    }

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_key, **kwargs)
        self.client = AsyncOpenAI(
            api_key=api_key,
            http_client=httpx.AsyncClient()
        )
        self.default_model = "gpt-4o-mini"

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
        tokens_used = response.usage.total_tokens
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
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
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
        return "openai"

    def supports_vision(self) -> bool:
        return True

    def supports_function_calling(self) -> bool:
        return True

    def get_max_context_length(self, model: str) -> int:
        context_lengths = {
            "gpt-4o": 128000,
            "gpt-4o-mini": 128000,
            "gpt-4-turbo": 128000,
            "gpt-4": 8192,
            "gpt-4-32k": 32768,
            "gpt-3.5-turbo": 16385,
            "gpt-3.5-turbo-16k": 16385,
        }
        return context_lengths.get(model, 4096)
