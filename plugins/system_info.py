import platform
import psutil
from typing import Any, Dict
from src.core.plugins.base import BasePlugin, PluginConfig

class SystemInfoPlugin(BasePlugin):
    @property
    def config(self) -> PluginConfig:
        return PluginConfig(
            name="system_info",
            version="1.0.0",
            description="Returns basic system diagnostic information.",
            capabilities=["diagnostics", "system"]
        )

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "get_system_info",
                "description": "Get current system statistics like CPU, memory, and OS version.",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }

    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return {
                "os": platform.system(),
                "os_release": platform.release(),
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
                "python_version": platform.python_version()
            }
        except Exception as e:
            return {"error": f"Failed to get system info: {e}"}
