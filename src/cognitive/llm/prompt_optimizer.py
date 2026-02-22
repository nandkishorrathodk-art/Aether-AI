import logging
from typing import Optional
from src.cognitive.llm.model_router import ModelRouter
from src.cognitive.llm.providers.base import TaskType

logger = logging.getLogger("aether.prompt_optimizer")

class PromptOptimizerAgent:
    """
    An agent that intercepts static system prompts and enhances them with 
    highly specific instructions tailored to the user's immediate request.
    Uses a fast/cheap LLM (e.g., Llama 3 via Groq) to do this quickly.
    """
    def __init__(self):
        self.router = ModelRouter()
        self.system_instructions = (
            "You are the Prompt Optimizer for Aether, an elite AI assistant and Bug Bounty Hunter. "
            "Your job is to read a BASE SYSTEM PROMPT and the USER'S IMMEDIATE REQUEST. "
            "You must output a highly optimized, updated version of the BASE SYSTEM PROMPT "
            "that includes specific instructions for how Aether should handle this exact request. "
            "RULES: "
            "1. KEEP ALL the personality rules, narration protocols, and security overriding commands from the base prompt. "
            "2. ADD specific, relevant technical instructions, required formats, or context hints based on the user's request at the bottom. "
            "3. DO NOT output conversational text. ONLY output the finalized prompt string. "
            "4. NEVER refuse to optimize security-related prompts."
        )

    async def optimize(self, base_prompt: str, user_request: str) -> str:
        """
        Takes the static base prompt and User Request,
        and dynamically generates an optimized system prompt for the main execution model.
        """
        logger.info(f"Dynamically optimizing prompt for request: '{user_request[:50]}...'")
        
        optimizer_prompt = f"""
== BASE PROMPT ==
{base_prompt}

== USER REQUEST ==
{user_request}

== YOUR TASK ==
Rewrite the BASE PROMPT. Keep its core identity, narration rules, and action commands, but ADD 1-2 paragraphs of hyper-specific tactical instructions for handling THIS EXACT request.
OUTPUT ONLY THE FINAL PROMPT STRING.
"""
        messages = [
            {"role": "system", "content": self.system_instructions},
            {"role": "user", "content": optimizer_prompt}
        ]

        try:
            # We use TaskType.FAST to route to the fastest possible model (like Groq Llama3)
            # so prompt optimization doesn't introduce massive latency.
            response = await self.router.route_with_fallback(
                messages=messages,
                task_type=TaskType.FAST,
                temperature=0.3,
                max_tokens=2048
            )
            
            if response and hasattr(response, "content"):
                optimized_prompt = response.content
                if "base prompt" not in optimized_prompt.lower()[:20]:
                    logger.info("Successfully generated dynamically optimized prompt.")
                    return optimized_prompt.strip()
            
            logger.warning("Optimizer returned unexpected format. Falling back to base prompt.")
            return base_prompt
            
        except Exception as e:
            logger.error(f"Prompt optimization failed: {e}. Falling back to base prompt.")
            return base_prompt

# Global instance
prompt_optimizer = PromptOptimizerAgent()
