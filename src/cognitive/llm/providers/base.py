from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Dict, Any


class TaskType(Enum):
    CONVERSATION = "conversation"
    ANALYSIS = "analysis"
    CODE = "code"
    CREATIVE = "creative"
    FAST = "fast"
    VISION = "vision"
    REASONING = "reasoning"


@dataclass
class AIResponse:
    content: str
    model: str
    provider: str
    tokens_used: int
    cost_usd: float
    latency_ms: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseAIProvider(ABC):
    def __init__(self, api_key: str, **kwargs):
        self.api_key = api_key
        self.config = kwargs

    @abstractmethod
    async def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs
    ) -> AIResponse:
        pass

    @abstractmethod
    async def stream_generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2048,
        **kwargs
    ):
        pass

    @abstractmethod
    def get_available_models(self) -> List[str]:
        pass

    @abstractmethod
    def calculate_cost(self, tokens_used: int, model: str) -> float:
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        pass

    def supports_vision(self) -> bool:
        return False

    def supports_function_calling(self) -> bool:
        return False

    def get_max_context_length(self, model: str) -> int:
        return 4096
