from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum


class TaskTypeEnum(str, Enum):
    conversation = "conversation"
    analysis = "analysis"
    code = "code"
    creative = "creative"
    fast = "fast"
    vision = "vision"


class Message(BaseModel):
    role: str = Field(..., description="Role: system, user, or assistant")
    content: str = Field(..., description="Message content")


class ChatRequest(BaseModel):
    prompt: str = Field(..., description="User prompt/query")
    task_type: TaskTypeEnum = Field(TaskTypeEnum.conversation, description="Type of task")
    system_prompt: Optional[str] = Field(None, description="System prompt to set context")
    conversation_history: Optional[List[Message]] = Field(None, description="Previous messages")
    provider: Optional[str] = Field(None, description="Force specific provider (openai, claude, etc)")
    model: Optional[str] = Field(None, description="Force specific model")
    temperature: Optional[float] = Field(None, ge=0.0, le=2.0, description="Temperature (0-2)")
    max_tokens: Optional[int] = Field(None, ge=1, le=4096, description="Max tokens to generate")
    stream: bool = Field(False, description="Enable streaming response")


class ChatResponse(BaseModel):
    content: str
    model: str
    provider: str
    tokens_used: int
    cost_usd: float
    latency_ms: float
    metadata: Dict[str, Any] = {}


class ConversationHistoryResponse(BaseModel):
    conversations: List[Dict[str, Any]]
    total: int


class ProviderInfo(BaseModel):
    name: str
    models: List[str]
    supports_vision: bool
    supports_function_calling: bool


class ProvidersResponse(BaseModel):
    providers: Dict[str, ProviderInfo]


class CostStats(BaseModel):
    total_cost: float
    total_tokens: int
    total_requests: int
    avg_cost_per_request: float
    avg_latency_ms: float
    by_provider: Dict[str, float]
    by_model: Dict[str, float]
    by_task_type: Dict[str, float]
