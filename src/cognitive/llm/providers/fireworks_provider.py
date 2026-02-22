import time
from typing import List, Dict, Optional, Any
from openai import AsyncOpenAI
from .base import BaseAIProvider, AIResponse


class FireworksProvider(BaseAIProvider):
    PRICING = {
        "accounts/fireworks/models/deepseek-v3p1": {"input": 0.0009, "output": 0.0009},
        "accounts/fireworks/models/mixtral-8x22b-instruct": {"input": 0.0012, "output": 0.0012},
        "accounts/fireworks/models/llama-v3p3-70b-instruct": {"input": 0.0009, "output": 0.0009},
        "accounts/fireworks/models/glm-5": {"input": 0.0009, "output": 0.0009},
        "accounts/fireworks/models/kimi-k2p5": {"input": 0.0009, "output": 0.0009},
    }

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_key, **kwargs)
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://api.fireworks.ai/inference/v1"
        )
<<<<<<< Updated upstream
        self.default_model = "accounts/fireworks/models/llama-v3p3-70b-instruct"
=======
        self.default_model = "accounts/fireworks/models/deepseek-v3p1"
        self.default_vision_model = "accounts/fireworks/models/llama-v3p2-11b-vision-instruct"
>>>>>>> Stashed changes

    async def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs
    ) -> AIResponse:
        start_time = time.time()
        
        # Determine model
        if not model:
            # Check if messages contain images
            has_image = any(
                isinstance(msg.get("content"), list) and 
                any(isinstance(item, dict) and item.get("type") == "image_url" for item in msg["content"]) 
                for msg in messages
            )
            model = self.default_vision_model if has_image else self.default_model

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
    ):
        if not model:
            has_image = any(
                isinstance(msg.get("content"), list) and 
                any(isinstance(item, dict) and item.get("type") == "image_url" for item in msg["content"]) 
                for msg in messages
            )
            model = self.default_vision_model if has_image else self.default_model
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
        return "fireworks"

    def supports_vision(self) -> bool:
        return True

    def supports_function_calling(self) -> bool:
        return True

    def get_max_context_length(self, model: str) -> int:
        return 8192
