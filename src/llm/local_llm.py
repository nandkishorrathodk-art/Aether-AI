import httpx
import logging
from typing import Dict, Any, Optional, List, AsyncGenerator
import asyncio

logger = logging.getLogger(__name__)


class OllamaProvider:
    """
    Ollama local LLM provider
    Supports: llama3, mistral, codellama, phi3, etc.
    Ultra-fast local inference without API costs!
    """
    
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=300.0)
        self.available = False
        self._check_availability()
    
    def _check_availability(self):
        """Check if Ollama is running"""
        try:
            response = httpx.get(f"{self.base_url}/api/tags", timeout=2.0)
            if response.status_code == 200:
                self.available = True
                models = response.json().get("models", [])
                logger.info(f"Ollama available with {len(models)} models")
            else:
                logger.warning("Ollama not available")
        except Exception as e:
            logger.warning(f"Ollama check failed: {e}")
    
    async def generate(
        self,
        prompt: str,
        model: str = "llama3",
        temperature: float = 0.7,
        max_tokens: int = 2048,
        stream: bool = False
    ) -> Dict[str, Any]:
        """Generate text with Ollama"""
        if not self.available:
            return {"error": "Ollama not available"}
        
        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": stream,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens
                }
            }
            
            if stream:
                return await self._generate_stream(payload)
            else:
                response = await self.client.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                )
                result = response.json()
                
                return {
                    "content": result.get("response", ""),
                    "model": model,
                    "provider": "ollama",
                    "tokens": {
                        "prompt": result.get("prompt_eval_count", 0),
                        "completion": result.get("eval_count", 0)
                    }
                }
        except Exception as e:
            logger.error(f"Ollama generation error: {e}")
            return {"error": str(e)}
    
    async def _generate_stream(self, payload: dict) -> AsyncGenerator[str, None]:
        """Stream generation"""
        async with self.client.stream(
            "POST",
            f"{self.base_url}/api/generate",
            json=payload
        ) as response:
            async for line in response.aiter_lines():
                if line:
                    import json
                    data = json.loads(line)
                    if "response" in data:
                        yield data["response"]
    
    async def list_models(self) -> List[str]:
        """List available Ollama models"""
        if not self.available:
            return []
        
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            data = response.json()
            return [model["name"] for model in data.get("models", [])]
        except Exception as e:
            logger.error(f"List models error: {e}")
            return []


class LMStudioProvider:
    """
    LM Studio local LLM provider
    Compatible with OpenAI API format
    """
    
    def __init__(self, base_url: str = "http://localhost:1234/v1"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=300.0)
        self.available = False
        self._check_availability()
    
    def _check_availability(self):
        """Check if LM Studio is running"""
        try:
            response = httpx.get(f"{self.base_url}/models", timeout=2.0)
            if response.status_code == 200:
                self.available = True
                models = response.json().get("data", [])
                logger.info(f"LM Studio available with {len(models)} models")
            else:
                logger.warning("LM Studio not available")
        except Exception as e:
            logger.warning(f"LM Studio check failed: {e}")
    
    async def generate(
        self,
        prompt: str,
        model: str = "local-model",
        temperature: float = 0.7,
        max_tokens: int = 2048
    ) -> Dict[str, Any]:
        """Generate text with LM Studio"""
        if not self.available:
            return {"error": "LM Studio not available"}
        
        try:
            payload = {
                "model": model,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            response = await self.client.post(
                f"{self.base_url}/chat/completions",
                json=payload
            )
            result = response.json()
            
            return {
                "content": result["choices"][0]["message"]["content"],
                "model": model,
                "provider": "lmstudio",
                "tokens": result.get("usage", {})
            }
        except Exception as e:
            logger.error(f"LM Studio generation error: {e}")
            return {"error": str(e)}


class LocalLLMRouter:
    """
    Smart router for local LLMs
    Automatically selects best available local model
    """
    
    def __init__(self):
        self.ollama = OllamaProvider()
        self.lmstudio = LMStudioProvider()
        
        self.providers = {
            "ollama": self.ollama,
            "lmstudio": self.lmstudio
        }
        
        logger.info("Local LLM router initialized")
    
    def get_available_providers(self) -> List[str]:
        """Get list of available local providers"""
        return [
            name for name, provider in self.providers.items()
            if provider.available
        ]
    
    async def generate(
        self,
        prompt: str,
        provider: str = "auto",
        model: str = "auto",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate text using best available local LLM
        
        Args:
            prompt: Text prompt
            provider: "auto", "ollama", "lmstudio"
            model: Model name or "auto"
            **kwargs: Additional generation parameters
        """
        # Auto-select provider
        if provider == "auto":
            available = self.get_available_providers()
            if not available:
                return {
                    "error": "No local LLM providers available",
                    "hint": "Install Ollama (https://ollama.ai) or LM Studio"
                }
            provider = available[0]  # Use first available
        
        # Get provider
        if provider not in self.providers:
            return {"error": f"Unknown provider: {provider}"}
        
        llm_provider = self.providers[provider]
        
        if not llm_provider.available:
            return {"error": f"{provider} not available"}
        
        # Auto-select model
        if model == "auto":
            if provider == "ollama":
                models = await llm_provider.list_models()
                # Prefer llama3, then mistral, then first available
                if "llama3" in models:
                    model = "llama3"
                elif "mistral" in models:
                    model = "mistral"
                elif models:
                    model = models[0]
                else:
                    return {"error": "No models available in Ollama"}
            else:
                model = "local-model"
        
        # Generate
        return await llm_provider.generate(prompt, model=model, **kwargs)
    
    async def benchmark(self) -> Dict[str, Any]:
        """Benchmark all available local LLMs"""
        results = {}
        test_prompt = "Write a haiku about AI."
        
        for name, provider in self.providers.items():
            if not provider.available:
                results[name] = {"available": False}
                continue
            
            import time
            start = time.time()
            
            try:
                result = await provider.generate(test_prompt, max_tokens=50)
                duration = time.time() - start
                
                results[name] = {
                    "available": True,
                    "response_time": round(duration, 2),
                    "tokens": result.get("tokens", {}),
                    "speed_rating": "fast" if duration < 5 else "medium" if duration < 15 else "slow"
                }
            except Exception as e:
                results[name] = {"available": True, "error": str(e)}
        
        return results


# Singleton instance
_router = None

def get_local_llm() -> LocalLLMRouter:
    """Get global local LLM router"""
    global _router
    if _router is None:
        _router = LocalLLMRouter()
    return _router
