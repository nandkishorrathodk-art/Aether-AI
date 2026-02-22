from typing import Any, Dict
from src.core.plugins.base import BasePlugin, PluginConfig

class CalculatorPlugin(BasePlugin):
    @property
    def config(self) -> PluginConfig:
        return PluginConfig(
            name="calculator",
            version="1.0.0",
            description="A simple calculator for basic arithmetic.",
            capabilities=["math", "calculation"]
        )

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "calculate",
                "description": "Evaluate a simple math expression.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "expression": {
                            "type": "string",
                            "description": "The math expression (e.g. '2 + 2 * 3')"
                        }
                    },
                    "required": ["expression"]
                }
            }
        }

    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        expression = params.get("expression")
        if not expression:
            return {"error": "Missing expression parameter."}
            
        try:
            # Safe evaluation for basic math
            allowed_names = {"__builtins__": None}
            result = eval(expression, allowed_names, {})
            return {"result": result, "expression": expression}
        except Exception as e:
            return {"error": f"Failed to evaluate expression: {e}"}
