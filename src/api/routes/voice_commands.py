"""Voice Commands API Routes"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from src.perception.voice.command_controller import VoiceCommandController
from src.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/voice-commands", tags=["voice-commands"])

# Global voice command controller instance
command_controller = VoiceCommandController()


class VoiceCommandRequest(BaseModel):
    """Voice command request"""
    text: str
    session_id: str = "default"


class VoiceCommandResponse(BaseModel):
    """Voice command response"""
    status: str
    intent: Optional[str] = None
    action: Optional[str] = None
    response: str
    data: Optional[Dict[str, Any]] = None
    confidence: Optional[float] = None
    error: Optional[str] = None


@router.post("/execute", response_model=VoiceCommandResponse)
async def execute_voice_command(request: VoiceCommandRequest):
    """
    Execute a voice command
    
    Processes natural language text and executes the appropriate action:
    - Open/close applications
    - File operations (create, read, list)
    - Memory operations (remember, recall)
    - Settings management (voice, volume)
    - Task management
    - General conversation
    
    Examples:
    - "Open Chrome"
    - "Create a file named test.txt"
    - "Remember to buy milk"
    - "What's the weather?"
    - "Change voice to male"
    """
    try:
        result = await command_controller.process_command(
            text=request.text,
            session_id=request.session_id
        )
        
        return VoiceCommandResponse(**result)
        
    except Exception as e:
        logger.error(f"Error executing voice command: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_command_stats():
    """Get voice command processing statistics"""
    return command_controller.get_stats()


@router.get("/supported")
async def get_supported_commands():
    """Get list of supported voice command types"""
    return {
        "commands": command_controller.get_supported_commands(),
        "total": len(command_controller.get_supported_commands())
    }


@router.get("/examples")
async def get_command_examples():
    """Get example voice commands"""
    return {
        "examples": [
            {"command": "Open Chrome", "intent": "open_application"},
            {"command": "Create a file named notes.txt", "intent": "create_file"},
            {"command": "What's the system status", "intent": "system_info"},
            {"command": "Remember to call John at 3 PM", "intent": "remember"},
            {"command": "Change voice to male", "intent": "change_voice"},
            {"command": "Set volume to 80", "intent": "adjust_volume"},
            {"command": "Create a task to backup files", "intent": "create_task"},
            {"command": "What are my tasks", "intent": "list_tasks"},
            {"command": "What's the weather today", "intent": "conversation"},
            {"command": "Tell me a joke", "intent": "conversation"},
        ]
    }
