import time
from typing import List, Dict, Optional, Any
from anthropic import AsyncAnthropic
import httpx
from .base import BaseAIProvider, AIResponse


class AnthropicProvider(BaseAIProvider):
    PRICING = {
        "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
        "claude-3-sonnet-20240229": {"input": 0.003, "output": 0.015},
        "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
        "claude-2.1": {"input": 0.008, "output": 0.024},
        "claude-2.0": {"input": 0.008, "output": 0.024},
    }

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_key, **kwargs)
        self.client = AsyncAnthropic(
            api_key=api_key,
            http_client=httpx.AsyncClient()
        )
        self.default_model = "claude-3-sonnet-20240229"

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

        system_msg = None
        formatted_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                formatted_messages.append(msg)

        response = await self.client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_msg,
            messages=formatted_messages,
            **kwargs
        )

        latency_ms = (time.time() - start_time) * 1000
        tokens_used = response.usage.input_tokens + response.usage.output_tokens
        cost = self.calculate_cost(tokens_used, model)

        return AIResponse(
            content=response.content[0].text,
            model=model,
            provider=self.get_provider_name(),
            tokens_used=tokens_used,
            cost_usd=cost,
            latency_ms=latency_ms,
            metadata={
                "stop_reason": response.stop_reason,
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
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

        system_msg = None
        formatted_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg["content"]
            else:
                formatted_messages.append(msg)

        async with self.client.messages.stream(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_msg,
            messages=formatted_messages,
            **kwargs
        ) as stream:
            async for text in stream.text_stream:
                yield text

    def get_available_models(self) -> List[str]:
        return list(self.PRICING.keys())

    def calculate_cost(self, tokens_used: int, model: str) -> float:
        if model not in self.PRICING:
            return 0.0
        avg_price = (self.PRICING[model]["input"] + self.PRICING[model]["output"]) / 2
        return (tokens_used / 1000) * avg_price

    def get_provider_name(self) -> str:
        return "anthropic"

    def supports_vision(self) -> bool:
        return True

    def supports_function_calling(self) -> bool:
        return True

    def get_max_context_length(self, model: str) -> int:
        return 200000
