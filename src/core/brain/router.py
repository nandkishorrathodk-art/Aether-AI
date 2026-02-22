from enum import Enum
from pydantic import BaseModel
from typing import Optional, Dict, Any
from loguru import logger
import uuid

# Import the new architectural elements from Phase 3
from src.core.brain.reasoning import reasoning
from src.core.brain.cost_tracker import cost_tracker
from src.core.brain.memory import memory
from src.core.brain.context import ConversationContext

class ModelProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    FIREWORKS = "fireworks"
    LOCAL = "local"

class RouterRequest(BaseModel):
    prompt: str
    provider: Optional[ModelProvider] = None
    task_type: Optional[str] = "general" # 'code', 'creative', 'reasoning', 'vision'
    conversation_id: Optional[str] = None

class ModelRouter:
    def __init__(self):
        self.providers = {
            ModelProvider.OPENAI: "gpt-4-turbo",
            ModelProvider.ANTHROPIC: "claude-3-opus-20240229",
            ModelProvider.GEMINI: "gemini-1.5-pro",
            ModelProvider.FIREWORKS: "accounts/fireworks/models/deepseek-v3p1",
            ModelProvider.LOCAL: "llama3"
        }
        # In-memory session manager for Phase 3 testing (Redis will replace this later)
        self.sessions: Dict[str, ConversationContext] = {}

    async def route_request(self, request: RouterRequest) -> Dict[str, Any]:
        """
        Intelligently routes a request to the best model, applying reasoning if needed,
        tracking conversation context, and calculating cost.
        """
        provider = request.provider

        if not provider:
            if request.task_type == "reasoning":
                provider = ModelProvider.FIREWORKS
            elif request.task_type == "code":
                provider = ModelProvider.ANTHROPIC
            elif request.task_type == "vision":
                provider = ModelProvider.OPENAI
            else:
                provider = ModelProvider.OPENAI

        model_name = self.providers.get(provider)
        logger.info(f"Routing task '{request.task_type}' to provider '{provider}' using model '{model_name}'")

        # Context Management
        conv_id = request.conversation_id or str(uuid.uuid4())
        if conv_id not in self.sessions:
            self.sessions[conv_id] = ConversationContext()
        ctx = self.sessions[conv_id]
        
        # Apply reasoning engine modifications to prompt if requested
        final_prompt = request.prompt
        if request.task_type == "reasoning":
            final_prompt = reasoning.generate_cot_prompt(request.prompt)
            
        ctx.add_message("user", final_prompt)

        # MOCK A REAL API CALL
        # Simulate generating a response from the model
        mock_response_text = f"Simulated {model_name} response to: {request.prompt[:15]}..."
        
        # In real implementation we'd get actual token counts from the API response
        mock_prompt_tokens = len(final_prompt) // 4
        mock_comp_tokens = len(mock_response_text) // 4
        
        # Calculate Costs
        tracked_usage = cost_tracker.calculate_cost(
            model_name=model_name,
            prompt_tokens=mock_prompt_tokens,
            completion_tokens=mock_comp_tokens
        )
        
        ctx.add_message("assistant", mock_response_text)
        
        # Store a semantic memory representing this interaction
        await memory.store_memory(
            memory_id=str(uuid.uuid4()),
            content=f"User asked: {request.prompt} | Assistant replied: {mock_response_text}",
            metadata={"conversation_id": conv_id, "task_type": request.task_type}
        )

        return {
            "conversation_id": conv_id,
            "response": mock_response_text,
            "model": model_name,
            "provider": provider,
            "usage": tracked_usage.model_dump(),
            "context_length": len(ctx.get_context())
        }

# Global instance
brain_router = ModelRouter()
