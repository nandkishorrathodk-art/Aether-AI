"""
Plugin Management API Routes
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from src.plugins.plugin_system import PluginManager, MCPIntegration
from src.plugins.marketplace import PluginMarketplace
from src.utils.logger import get_logger

router = APIRouter(prefix="/api/v1/plugins", tags=["plugins"])
logger = get_logger(__name__)

# Initialize plugin system
plugin_manager = PluginManager()
mcp_integration = MCPIntegration(plugin_manager)
marketplace = PluginMarketplace()


class PluginInstallRequest(BaseModel):
    source: str  # URL, git repo, or marketplace ID


class MCPServerRequest(BaseModel):
    name: str
    command: str
    args: List[str]
    env: Optional[Dict[str, str]] = None


class PluginCallRequest(BaseModel):
    plugin_name: str
    function_name: str
    args: List[Any] = []
    kwargs: Dict[str, Any] = {}


@router.get("/")
async def list_plugins():
    """List all loaded plugins"""
    return {
        "plugins": plugin_manager.list_plugins(),
        "statistics": plugin_manager.get_statistics()
    }


@router.get("/discover")
async def discover_plugins():
    """Discover available plugins"""
    discovered = plugin_manager.discover_plugins()
    return {
        "count": len(discovered),
        "plugins": [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "type": p.plugin_type.value,
                "capabilities": p.capabilities
            }
            for p in discovered
        ]
    }


@router.post("/install")
async def install_plugin(request: PluginInstallRequest):
    """Install plugin"""
    try:
        success = plugin_manager.install_plugin(request.source)
        if success:
            return {"message": "Plugin installed successfully", "success": True}
        else:
            raise HTTPException(status_code=400, detail="Installation failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/load/{plugin_name}")
async def load_plugin(plugin_name: str):
    """Load plugin"""
    success = plugin_manager.load_plugin(plugin_name)
    if success:
        return {"message": f"Plugin {plugin_name} loaded", "success": True}
    else:
        raise HTTPException(status_code=404, detail="Plugin not found")


@router.post("/unload/{plugin_name}")
async def unload_plugin(plugin_name: str):
    """Unload plugin"""
    plugin_manager.unload_plugin(plugin_name)
    return {"message": f"Plugin {plugin_name} unloaded", "success": True}


@router.post("/reload/{plugin_name}")
async def reload_plugin(plugin_name: str):
    """Hot reload plugin"""
    success = plugin_manager.reload_plugin(plugin_name)
    if success:
        return {"message": f"Plugin {plugin_name} reloaded", "success": True}
    else:
        raise HTTPException(status_code=404, detail="Plugin not found")


@router.get("/{plugin_name}")
async def get_plugin_info(plugin_name: str):
    """Get plugin information"""
    info = plugin_manager.get_plugin_info(plugin_name)
    if info:
        return info
    else:
        raise HTTPException(status_code=404, detail="Plugin not found")


@router.post("/call")
async def call_plugin(request: PluginCallRequest):
    """Call plugin function"""
    try:
        result = plugin_manager.call_plugin(
            request.plugin_name,
            request.function_name,
            *request.args,
            **request.kwargs
        )
        return {"result": result, "success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/recommend")
async def recommend_plugins(task: str):
    """Get AI-powered plugin recommendations"""
    recommendations = plugin_manager.recommend_plugins(task)
    return {"recommendations": recommendations}


# MCP Integration Routes

@router.post("/mcp/add-server")
async def add_mcp_server(request: MCPServerRequest):
    """Add MCP server (Anthropic Model Context Protocol)"""
    config = {
        "command": request.command,
        "args": request.args,
        "env": request.env or {}
    }
    
    success = mcp_integration.add_mcp_server(request.name, config)
    if success:
        return {"message": f"MCP server {request.name} added", "success": True}
    else:
        raise HTTPException(status_code=400, detail="Failed to add MCP server")


@router.post("/mcp/import-claude-config")
async def import_claude_config(config_path: str):
    """Import MCP servers from Claude Desktop config"""
    try:
        count = mcp_integration.import_claude_config(config_path)
        return {
            "message": f"Imported {count} MCP servers from Claude",
            "count": count,
            "success": True
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Marketplace Routes

@router.get("/marketplace/search")
async def search_marketplace(
    query: str,
    category: Optional[str] = None,
    min_rating: float = 0.0,
    verified_only: bool = False
):
    """Search plugin marketplace"""
    results = marketplace.search(query, category, min_rating, verified_only)
    return {
        "count": len(results),
        "results": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "rating": p.rating,
                "downloads": p.downloads,
                "verified": p.verified
            }
            for p in results
        ]
    }


@router.get("/marketplace/featured")
async def get_featured_plugins():
    """Get featured plugins"""
    featured = marketplace.get_featured()
    return {"featured": featured}


@router.get("/marketplace/trending")
async def get_trending_plugins():
    """Get trending plugins"""
    trending = marketplace.get_trending()
    return {"trending": trending}


@router.post("/marketplace/install/{plugin_id}")
async def install_from_marketplace(plugin_id: str):
    """Install plugin from marketplace"""
    success = marketplace.install(plugin_id)
    if success:
        return {"message": f"Installed {plugin_id}", "success": True}
    else:
        raise HTTPException(status_code=500, detail="Installation failed")


@router.get("/statistics")
async def get_statistics():
    """Get plugin usage statistics"""
    return plugin_manager.get_statistics()
