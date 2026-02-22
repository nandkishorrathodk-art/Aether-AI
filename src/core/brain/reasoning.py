from typing import List, Dict, Any
from loguru import logger

class ReasoningEngine:
    """
    Handles advanced cognitive patterns like Chain-of-Thought (CoT) and Reflection
    to improve the quality of LLM responses before final generation.
    """
    
    def generate_cot_prompt(self, original_prompt: str) -> str:
        """
        Wraps the original prompt instructing the model to use Chain-of-Thought reasoning.
        """
        cot_instructions = (
            "Before providing the final answer, please think step-by-step. "
            "Break down the problem, outline your logic, and then conclude with the final result.\\n\\n"
            f"Original Request: {original_prompt}"
        )
        logger.debug("Applied Chain-of-Thought wrapping to prompt.")
        return cot_instructions

    def generate_reflection_prompt(self, original_prompt: str, draft_response: str) -> str:
        """
        Generates a prompt asking the model to review and critique its own draft response.
        """
        reflection_instructions = (
            "You are an expert reviewer. I will provide an original request and a draft response. "
            "Please analyze the draft for accuracy, completeness, and clarity. Then, provide an improved version of the response.\\n\\n"
            f"Original Request: {original_prompt}\\n\\n"
            f"Draft Response: {draft_response}\\n\\n"
            "Improved Response:"
        )
        logger.debug("Applied Reflection wrapping to draft response.")
        return reflection_instructions

# Global instance
reasoning = ReasoningEngine()
