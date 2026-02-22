from typing import Dict, List, Optional
from loguru import logger
from src.core.plugins.base import BasePlugin

class PluginRegistry:
    """
    Central repository for managing loaded plugins in Ironclaw.
    Handles registration, retrieval, and status tracking.
    """
    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin) -> bool:
        """Register a new plugin. Returns True if successful."""
        plugin_name = plugin.config.name
        if plugin_name in self._plugins:
            logger.warning(f"Plugin '{plugin_name}' is already registered. Overwriting.")
        
        self._plugins[plugin_name] = plugin
        logger.info(f"Registered plugin: {plugin_name} v{plugin.config.version}")
        return True

    def unregister(self, plugin_name: str) -> bool:
        """Remove a plugin from the registry."""
        if plugin_name in self._plugins:
            del self._plugins[plugin_name]
            logger.info(f"Unregistered plugin: {plugin_name}")
            return True
        return False

    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Retrieve a registered plugin by name."""
        return self._plugins.get(plugin_name)

    def get_all_plugins(self) -> List[BasePlugin]:
        """Return a list of all registered plugins."""
        return list(self._plugins.values())

    def get_enabled_plugins(self) -> List[BasePlugin]:
        """Return a list of all currently enabled plugins."""
        return [p for p in self._plugins.values() if p.config.enabled]

# Global registry instance
registry = PluginRegistry()
