from typing import List, Dict, Any
from pydantic import BaseModel
from loguru import logger

class Message(BaseModel):
    role: str # "user", "assistant", "system"
    content: str
    tokens_estimated: int = 0

class ConversationContext:
    """
    Manages the sliding window of conversational history to ensure
    the LLM has context without exceeding token window limits.
    """
    def __init__(self, max_history_tokens: int = 4000):
        self.max_history_tokens = max_history_tokens
        self.messages: List[Message] = []
        self._current_token_count = 0

    def add_message(self, role: str, content: str):
        # Rough token estimation for Phase 3: 1 token ~= 4 chars
        estimated_tokens = len(content) // 4
        msg = Message(role=role, content=content, tokens_estimated=estimated_tokens)
        self.messages.append(msg)
        self._current_token_count += estimated_tokens
        
        self._trim_window()

    def get_context(self) -> List[Dict[str, str]]:
        """Returns the conversation history formatted for LLM APIs."""
        return [{"role": msg.role, "content": msg.content} for msg in self.messages]

    def clear(self):
        self.messages = []
        self._current_token_count = 0
        logger.info("Cleared conversation context.")

    def _trim_window(self):
        """Removes oldest messages if the token context window is exceeded."""
        while self._current_token_count > self.max_history_tokens and len(self.messages) > 1:
            # Keep system prompt if it's the first message, otherwise drop oldest
            drop_idx = 1 if self.messages[0].role == "system" else 0
            
            dropped = self.messages.pop(drop_idx)
            self._current_token_count -= dropped.tokens_estimated
            logger.debug(f"Trimmed old {dropped.role} message to respect token limit.")
