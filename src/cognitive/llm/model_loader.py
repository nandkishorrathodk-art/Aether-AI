from typing import List, Dict, Optional, Any, AsyncGenerator
from .providers.base import TaskType, AIResponse
from .model_router import router
from .cost_tracker import cost_tracker
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ModelLoader:
    def __init__(self):
        self.router = router
        self.cost_tracker = cost_tracker
        logger.info("Model Loader initialized with multi-provider support")

    async def generate(
        self,
        prompt: str,
        task_type: TaskType = TaskType.CONVERSATION,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> AIResponse:
        messages = self._build_messages(
            prompt=prompt,
            system_prompt=system_prompt,
            conversation_history=conversation_history
        )

        temperature = temperature if temperature is not None else settings.llm_temperature
        max_tokens = max_tokens if max_tokens is not None else settings.llm_max_tokens

        try:
            response = await self.router.route_with_fallback(
                messages=messages,
                task_type=task_type,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs
            )

            if settings.enable_cost_tracking:
                self.cost_tracker.track_request(
                    provider=response.provider,
                    model=response.model,
                    tokens_used=response.tokens_used,
                    cost_usd=response.cost_usd,
                    task_type=task_type.value,
                    latency_ms=response.latency_ms
                )

            logger.info(
                f"Generated response: {response.provider}/{response.model}, "
                f"{response.tokens_used} tokens, ${response.cost_usd:.4f}, "
                f"{response.latency_ms:.0f}ms"
            )

            return response

        except Exception as e:
            logger.error(f"Failed to generate response: {e}")
            raise

    async def stream_generate(
        self,
        prompt: str,
        task_type: TaskType = TaskType.CONVERSATION,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        messages = self._build_messages(
            prompt=prompt,
            system_prompt=system_prompt,
            conversation_history=conversation_history
        )

        temperature = temperature if temperature is not None else settings.llm_temperature
        max_tokens = max_tokens if max_tokens is not None else settings.llm_max_tokens

        stream = await self.router.route_request(
            messages=messages,
            task_type=task_type,
            provider_override=provider,
            model_override=model,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
            **kwargs
        )

        async for chunk in stream:
            yield chunk

    def _build_messages(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None
    ) -> List[Dict[str, str]]:
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        if conversation_history:
            messages.extend(conversation_history)

        messages.append({"role": "user", "content": prompt})

        return messages

    def get_available_providers(self) -> List[str]:
        return self.router.get_available_providers()

    def get_provider_stats(self) -> Dict[str, Any]:
        return self.router.get_provider_stats()

    def get_cost_stats(self, hours: int = 24) -> Dict[str, Any]:
        return self.cost_tracker.get_stats(hours=hours)

    def get_recommended_provider(self, task_type: TaskType) -> str:
        cost_effective = self.cost_tracker.get_most_cost_effective_provider(task_type.value)
        if cost_effective:
            logger.info(f"Most cost-effective provider for {task_type.value}: {cost_effective}")
            return cost_effective
        
        provider = self.router.get_provider_for_task(task_type)
        return provider.get_provider_name() if provider else "unknown"


model_loader = ModelLoader()
