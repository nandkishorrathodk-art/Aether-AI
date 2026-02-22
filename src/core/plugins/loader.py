import importlib.util
import os
import sys
from pathlib import Path
from loguru import logger
from src.core.plugins.base import BasePlugin
from src.core.plugins.registry import registry

class PluginLoader:
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)

    def load_all_plugins(self) -> int:
        """Dynamically loads all .py files in the plugin_dir and registers them."""
        if not self.plugin_dir.exists():
            logger.warning(f"Plugin directory '{self.plugin_dir}' does not exist. Creating it.")
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
            return 0

        loaded_count = 0
        for item in self.plugin_dir.iterdir():
            if item.is_file() and item.suffix == ".py" and not item.name.startswith("__"):
                if self._load_plugin_module(item):
                    loaded_count += 1
                    
        return loaded_count

    def _load_plugin_module(self, file_path: Path) -> bool:
        """Loads a single plugin module from a file path."""
        module_name = f"plugins.{file_path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                
                # Search for classes inheriting from BasePlugin
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BasePlugin) and attr is not BasePlugin:
                        # Instantiate and register the plugin
                        plugin_instance = attr()
                        registry.register(plugin_instance)
                        return True
                        
                logger.warning(f"No valid BasePlugin found in '{file_path.name}'")
        except Exception as e:
            logger.error(f"Failed to load plugin '{file_path.name}': {e}")
            
        return False

# Global loader instance
loader = PluginLoader()
