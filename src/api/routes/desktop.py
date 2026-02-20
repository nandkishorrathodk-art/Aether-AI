from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from src.autonomous.desktop_agent import get_desktop_agent
from src.automation.desktop_automation import get_desktop_automation
from src.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/desktop", tags=["desktop"])

desktop_agent = get_desktop_agent()
desktop_automation = get_desktop_automation()


class DesktopCommandRequest(BaseModel):
    command: str = Field(..., description="Natural language command")


class DesktopActionRequest(BaseModel):
    action: str = Field(..., description="Desktop automation action")
    params: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")


class AgentControlRequest(BaseModel):
    action: str = Field(..., description="start or stop")


@router.post("/command")
async def execute_command(request: DesktopCommandRequest):
    """
    Execute natural language desktop command
    
    Examples:
    - "Open Google Chrome"
    - "Create a file called notes.txt"  
    - "Search for Python tutorial on Google"
    - "Take a screenshot"
    """
    try:
        result = await desktop_agent.execute_user_command(request.command)
        return result
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/action")
async def execute_action(request: DesktopActionRequest):
    """
    Execute desktop automation action directly
    
    Available actions:
    - File: create_file, read_file, write_file, delete_file, move_file, copy_file, list_files, search_files
    - Folder: create_folder, delete_folder, list_folders
    - App: launch_app, close_app, list_running_apps, switch_window
    - Browser: open_url, search_google, open_youtube
    - Input: click, type_text, press_key, screenshot
    - System: run_command, get_system_info, shutdown, restart
    - Clipboard: copy_to_clipboard, paste_from_clipboard
    """
    try:
        result = await desktop_automation.execute_command(request.action, request.params)
        return result
    except Exception as e:
        logger.error(f"Action execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agent/control")
async def control_agent(request: AgentControlRequest, background_tasks: BackgroundTasks):
    """
    Start or stop autonomous desktop agent
    
    When started, AI will:
    - Watch your screen
    - Understand what you're doing
    - Help automatically when needed
    - Execute tasks on desktop
    """
    try:
        if request.action == "start":
            if not desktop_agent.running:
                background_tasks.add_task(desktop_agent.start)
                return {"success": True, "status": "started", "message": "AI agent is now watching and helping"}
            else:
                return {"success": False, "message": "Agent already running"}
        
        elif request.action == "stop":
            desktop_agent.stop()
            return {"success": True, "status": "stopped", "message": "AI agent stopped"}
        
        else:
            raise ValueError(f"Invalid action: {request.action}")
    
    except Exception as e:
        logger.error(f"Agent control failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agent/status")
async def agent_status():
    """Get desktop agent status"""
    return {
        "running": desktop_agent.running,
        "tasks_executed": len(desktop_agent.task_history),
        "recent_tasks": await desktop_agent.get_task_history(limit=5)
    }


@router.get("/agent/history")
async def agent_history(limit: int = 10):
    """Get agent task history"""
    return {
        "tasks": await desktop_agent.get_task_history(limit=limit),
        "total": len(desktop_agent.task_history)
    }


@router.get("/agent/suggest")
async def agent_suggest():
    """Get AI suggestion for next action"""
    try:
        suggestion = await desktop_agent.suggest_next_action()
        return suggestion
    except Exception as e:
        logger.error(f"Suggestion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/actions/list")
async def list_actions():
    """List all available desktop actions"""
    return {
        "file_operations": [
            "create_file", "read_file", "write_file", "delete_file",
            "move_file", "copy_file", "list_files", "search_files"
        ],
        "folder_operations": [
            "create_folder", "delete_folder", "list_folders"
        ],
        "app_control": [
            "launch_app", "close_app", "list_running_apps", "switch_window"
        ],
        "browser": [
            "open_url", "search_google", "open_youtube"
        ],
        "input": [
            "click", "type_text", "press_key", "screenshot"
        ],
        "system": [
            "run_command", "get_system_info", "shutdown", "restart"
        ],
        "clipboard": [
            "copy_to_clipboard", "paste_from_clipboard"
        ]
    }


@router.get("/health")
async def health():
    """Health check"""
    return {
        "status": "healthy",
        "agent_running": desktop_agent.running,
        "automation_enabled": True
    }
