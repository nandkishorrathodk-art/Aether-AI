from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict

class PluginConfig(BaseModel):
    """Configuration schema for a generic plugin."""
    name: str
    version: str
    description: str
    enabled: bool = True
    capabilities: List[str] = []
    
    model_config = ConfigDict(extra='allow')

class BasePlugin(ABC):
    """
    Abstract base class for all Ironclaw plugins.
    Enforces a standard interface for dynamic loading and execution.
    """
    
    @property
    @abstractmethod
    def config(self) -> PluginConfig:
        """Return the plugin's configuration."""
        pass

    @abstractmethod
    def get_schema(self) -> Dict[str, Any]:
        """
        Return the JSON schema representing the plugin's input requirements.
        This is used to map to LLM tool formats.
        """
        pass

    @abstractmethod
    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the plugin's primary capability with the given parameters.
        Must return a structured dictionary.
        """
        pass

    async def initialize(self) -> bool:
        """
        Optional step to initialize connections, verify API keys, etc.
        Returns True if successful, False otherwise.
        """
        return True

    async def cleanup(self) -> None:
        """
        Optional step to clean up resources when the plugin is unloaded.
        """
        pass
