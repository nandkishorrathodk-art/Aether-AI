import time
from typing import List, Dict, Optional, Any
from groq import AsyncGroq
from .base import BaseAIProvider, AIResponse


class GroqProvider(BaseAIProvider):
    PRICING = {
        "llama-3.3-70b-versatile": {"input": 0.00059, "output": 0.00079},
        "llama-3.1-8b-instant": {"input": 0.00005, "output": 0.00008},
        "mixtral-8x7b-32768": {"input": 0.00024, "output": 0.00024},
        "gemma2-9b-it": {"input": 0.00020, "output": 0.00020},
    }

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_key, **kwargs)
        self.client = AsyncGroq(api_key=api_key)
        self.default_model = "llama-3.3-70b-versatile"

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
        
        # Map legacy model names if passed in config
        if model == "llama3-70b-8192":
            model = "llama-3.3-70b-versatile"
        elif model == "llama3-8b-8192":
            model = "llama-3.1-8b-instant"

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
        
        # Map legacy model names if passed in config
        if model == "llama3-70b-8192":
            model = "llama-3.3-70b-versatile"
        elif model == "llama3-8b-8192":
            model = "llama-3.1-8b-instant"
            
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
        return "groq"

    def supports_vision(self) -> bool:
        return False

    def supports_function_calling(self) -> bool:
        return True

    def get_max_context_length(self, model: str) -> int:
        context_lengths = {
            "llama-3.3-70b-versatile": 128000,
            "llama-3.1-8b-instant": 128000,
            "mixtral-8x7b-32768": 32768,
            "gemma2-9b-it": 8192,
        }
        return context_lengths.get(model, 8192)
