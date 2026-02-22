"""
Live Voice Assistant API
RESTful + WebSocket endpoints for voice-first interaction
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Optional, List
import asyncio

from src.core.live_assistant import get_live_assistant
from src.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/live", tags=["live_assistant"])


class VoiceCommandRequest(BaseModel):
    command: str = Field(..., description="Voice command text")
    user_id: Optional[str] = Field(None, description="User ID")


class VoiceCommandResponse(BaseModel):
    success: bool
    action: str
    message: Optional[str] = None
    data: Optional[Dict] = None


@router.post("/command", response_model=VoiceCommandResponse)
async def process_voice_command(request: VoiceCommandRequest):
    """
    Process voice command (can be called from voice UI or text)
    
    **Examples**:
    - "Open browser and search Python tutorial"
    - "Play Lofi hip hop on YouTube"
    - "Teach me Python functions"
    - "Scan apple.com for vulnerabilities"
    - "Pause that scan"
    - "What's the status?"
    
    **Returns**: Action result with live voice feedback
    """
    try:
        assistant = await get_live_assistant()
        result = await assistant.process_voice_command(request.command)
        
        return VoiceCommandResponse(
            success=result.get("success", False),
            action=result.get("action", "unknown"),
            message=result.get("message"),
            data=result
        )
    
    except Exception as e:
        logger.error(f"Voice command error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks")
async def get_active_tasks():
    """
    Get all active background tasks
    
    **Returns**: List of tasks with status and progress
    """
    try:
        assistant = await get_live_assistant()
        
        tasks = [task.to_dict() for task in assistant.active_tasks.values()]
        
        return {
            "success": True,
            "tasks": tasks,
            "count": len(tasks)
        }
    
    except Exception as e:
        logger.error(f"Get tasks error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/speak")
async def speak_text(text: str, interrupt: bool = False):
    """
    Make assistant speak (for testing or notifications)
    
    **Example**: `/api/v1/live/speak?text=Hello boss!`
    """
    try:
        assistant = await get_live_assistant()
        await assistant.speak(text, interrupt=interrupt)
        
        return {
            "success": True,
            "message": "Speaking..."
        }
    
    except Exception as e:
        logger.error(f"Speak error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/toggle-voice")
async def toggle_voice(enabled: bool):
    """
    Enable/disable voice output
    
    **Use case**: Silent mode during meetings
    """
    try:
        assistant = await get_live_assistant()
        assistant.voice_updates_enabled = enabled
        
        return {
            "success": True,
            "voice_enabled": enabled
        }
    
    except Exception as e:
        logger.error(f"Toggle voice error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ===== WebSocket for Real-time Voice Updates =====

class ConnectionManager:
    """Manage WebSocket connections for live updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict):
        """Broadcast message to all connected clients"""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Broadcast error: {e}")


manager = ConnectionManager()


@router.websocket("/ws/live-updates")
async def websocket_live_updates(websocket: WebSocket):
    """
    WebSocket endpoint for real-time voice updates
    
    **Use case**: Live progress during scans, teaching, etc.
    
    **Message format**:
    ```json
    {
        "type": "voice_update",
        "text": "Boss! Scan 50% complete...",
        "task_id": "scan_123",
        "progress": 0.5
    }
    ```
    """
    await manager.connect(websocket)
    
    try:
        assistant = await get_live_assistant()
        
        # Send initial status
        await websocket.send_json({
            "type": "connection",
            "message": "Connected to Live Assistant",
            "active_tasks": len(assistant.active_tasks)
        })
        
        # Listen for commands
        while True:
            data = await websocket.receive_text()
            
            # Process as voice command
            result = await assistant.process_voice_command(data)
            
            # Send result
            await websocket.send_json({
                "type": "command_result",
                "success": result.get("success"),
                "action": result.get("action"),
                "data": result
            })
            
            # Broadcast to all clients
            await manager.broadcast({
                "type": "activity",
                "command": data,
                "result": result
            })
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected")
    
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


@router.get("/health")
async def health_check():
    """Health check for live assistant"""
    try:
        assistant = await get_live_assistant()
        
        return {
            "status": "healthy",
            "voice_enabled": assistant.voice_updates_enabled,
            "active_tasks": len(assistant.active_tasks),
            "browser_running": assistant.browser.is_running
        }
    
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }
