import urllib.request
import urllib.parse
from typing import Any, Dict
from src.core.plugins.base import BasePlugin, PluginConfig

class WebSearchPlugin(BasePlugin):
    @property
    def config(self) -> PluginConfig:
        return PluginConfig(
            name="web_search",
            version="1.0.0",
            description="Performs simple basic web searches.",
            capabilities=["search", "information_retrieval"]
        )

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": "search_web",
                "description": "Search the web for a given query.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The search query."
                        }
                    },
                    "required": ["query"]
                }
            }
        }

    async def execute(self, params: Dict[str, Any]) -> Dict[str, Any]:
        query = params.get("query")
        if not query:
            return {"error": "Missing query parameter."}
            
        try:
            # A very simple mock search for Phase 2 demonstration
            # In a real scenario, this would call DuckDuckGo, Google API, or SERP API
            encoded_query = urllib.parse.quote(query)
            mock_results = [
                {"title": f"Result 1 for {query}", "link": f"https://example.com/search?q={encoded_query}"},
                {"title": f"Result 2 for {query}", "link": f"https://example.com/info"}
            ]
            return {"query": query, "results": mock_results}
        except Exception as e:
            return {"error": f"Search failed: {e}"}
