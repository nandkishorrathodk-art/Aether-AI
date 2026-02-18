"""
LLM Wrapper - Simple interface for autonomous components

This provides a simple get_completion() interface that wraps
the existing complex LLM infrastructure.
"""

import asyncio
from typing import Optional, Dict, Any

from src.cognitive.llm.model_loader import model_loader
from src.cognitive.llm.prompt_engine import prompt_engine
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class LLMInference:
    """
    Simple LLM inference wrapper for autonomous components.
    
    Wraps the existing complex LLM system with a simple interface.
    """
    
    def __init__(self):
        self.provider_name = settings.default_provider
        logger.info(f"LLMInference initialized with provider: {self.provider_name}")
    
    async def get_completion(
        self,
        prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Get LLM completion for a prompt
        
        Args:
            prompt: The prompt text
            temperature: Sampling temperature (0-2)
            max_tokens: Maximum tokens to generate
            system_prompt: System prompt (optional)
            
        Returns:
            Completion text
        """
        try:
            # Get the model provider
            provider = model_loader.get_provider(self.provider_name)
            
            if provider is None:
                logger.error(f"Provider {self.provider_name} not available")
                return self._get_fallback_response()
            
            # Prepare messages
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})
            
            # Use existing infrastructure
            response = await provider.generate_response(
                messages=messages,
                temperature=temperature or settings.temperature,
                max_tokens=max_tokens or settings.max_tokens
            )
            
            if response.success:
                return response.content
            else:
                logger.error(f"LLM generation failed: {response.error}")
                return self._get_fallback_response()
                
        except Exception as e:
            logger.error(f"LLM completion error: {e}")
            return self._get_fallback_response()
    
    def _get_fallback_response(self) -> str:
        """Fallback response when LLM fails"""
        return "Error: LLM completion failed. Using fallback response."
