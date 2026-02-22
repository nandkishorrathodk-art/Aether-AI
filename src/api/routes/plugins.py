from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
from src.core.plugins.registry import registry
from src.core.plugins.sandbox import sandbox
from src.core.plugins.loader import loader

router = APIRouter(prefix="/api/v1/plugins", tags=["Plugins"])

class PluginExecuteRequest(BaseModel):
    action: str
    params: Dict[str, Any]

@router.get("/")
async def list_plugins():
    plugins = registry.get_all_plugins()
    return {
        "plugins": [
            {
                "id": p.config.name,
                "name": p.config.name,
                "version": p.config.version,
                "enabled": p.config.enabled,
                "capabilities": p.config.capabilities
            }
            for p in plugins
        ]
    }

@router.post("/reload")
async def reload_plugins():
    count = loader.load_all_plugins()
    return {"message": f"Successfully loaded {count} plugins."}

@router.post("/{plugin_id}/execute")
async def execute_plugin(plugin_id: str, request: PluginExecuteRequest):
    plugin = registry.get_plugin(plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
        
    if not plugin.config.enabled:
        raise HTTPException(status_code=400, detail="Plugin is disabled")

    # In Phase 2, we execute via sandbox
    # The sandbox takes the module name (plugins.plugin_id) and class name
    # We get class name dynamically:
    class_name = plugin.__class__.__name__
    module_name = f"plugins.{plugin_id}"

    result = await sandbox.execute_isolated(module_name, class_name, request.params)
    return {"result": result}
