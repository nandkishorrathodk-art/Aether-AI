import time
import warnings
from typing import List, Dict, Optional, Any

with warnings.catch_warnings():
    warnings.simplefilter("ignore", category=FutureWarning)
    import google.generativeai as genai

from .base import BaseAIProvider, AIResponse


class GoogleProvider(BaseAIProvider):
    PRICING = {
        "gemini-pro": {"input": 0.000125, "output": 0.000375},
        "gemini-pro-vision": {"input": 0.000125, "output": 0.000375},
        "gemini-1.5-pro": {"input": 0.00035, "output": 0.00105},
        "gemini-1.5-flash": {"input": 0.000035, "output": 0.000105},
    }

    def __init__(self, api_key: str, **kwargs):
        super().__init__(api_key, **kwargs)
        genai.configure(api_key=api_key)
        self.default_model = "gemini-1.5-flash"

    async def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs
    ) -> AIResponse:
        start_time = time.time()
        model_name = model or self.default_model

        gemini_model = genai.GenerativeModel(model_name)

        formatted_messages = []
        for msg in messages:
            role = "user" if msg["role"] in ["user", "system"] else "model"
            formatted_messages.append({"role": role, "parts": [msg["content"]]})

        chat = gemini_model.start_chat(history=formatted_messages[:-1] if len(formatted_messages) > 1 else [])
        response = await chat.send_message_async(
            formatted_messages[-1]["parts"][0],
            generation_config=genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )
        )

        latency_ms = (time.time() - start_time) * 1000
        tokens_used = response.usage_metadata.total_token_count
        cost = self.calculate_cost(tokens_used, model_name)

        return AIResponse(
            content=response.text,
            model=model_name,
            provider=self.get_provider_name(),
            tokens_used=tokens_used,
            cost_usd=cost,
            latency_ms=latency_ms,
            metadata={
                "prompt_tokens": response.usage_metadata.prompt_token_count,
                "completion_tokens": response.usage_metadata.candidates_token_count,
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
        model_name = model or self.default_model
        gemini_model = genai.GenerativeModel(model_name)

        formatted_messages = []
        for msg in messages:
            role = "user" if msg["role"] in ["user", "system"] else "model"
            formatted_messages.append({"role": role, "parts": [msg["content"]]})

        chat = gemini_model.start_chat(history=formatted_messages[:-1] if len(formatted_messages) > 1 else [])
        response = await chat.send_message_async(
            formatted_messages[-1]["parts"][0],
            generation_config=genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            ),
            stream=True
        )

        async for chunk in response:
            if chunk.text:
                yield chunk.text

    def get_available_models(self) -> List[str]:
        return list(self.PRICING.keys())

    def calculate_cost(self, tokens_used: int, model: str) -> float:
        if model not in self.PRICING:
            return 0.0
        avg_price = (self.PRICING[model]["input"] + self.PRICING[model]["output"]) / 2
        return (tokens_used / 1000) * avg_price

    def get_provider_name(self) -> str:
        return "google"

    def supports_vision(self) -> bool:
        return True

    def supports_function_calling(self) -> bool:
        return True

    def get_max_context_length(self, model: str) -> int:
        if "1.5" in model:
            return 1000000
        return 32768
