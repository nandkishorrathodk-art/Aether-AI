from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

from src.cognitive.memory import MemoryManager, ConversationHistory, ProfileManager
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/memory", tags=["memory"])

memory_manager = MemoryManager()
conversation_history = ConversationHistory()
profile_manager = ProfileManager()


class MemoryRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Memory text content")
    memory_type: str = Field(default="user", description="Type: user, conversation, fact, task")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")


class MemorySearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Search query")
    memory_type: Optional[str] = Field(default=None, description="Filter by type")
    n_results: int = Field(default=5, ge=1, le=20, description="Number of results")


class MessageRequest(BaseModel):
    session_id: str = Field(..., description="Conversation session ID")
    role: str = Field(..., description="Message role (user/assistant/system)")
    content: str = Field(..., min_length=1, description="Message content")
    metadata: Optional[Dict[str, Any]] = Field(default=None)
    auto_embed: bool = Field(default=True, description="Auto-embed important messages")


class RAGContextRequest(BaseModel):
    session_id: str = Field(..., description="Session ID")
    query: str = Field(..., description="Current user query")
    max_recent: int = Field(default=5, ge=1, le=20)
    max_relevant: int = Field(default=3, ge=1, le=10)


class ProfileUpdateRequest(BaseModel):
    updates: Dict[str, Any] = Field(..., description="Profile updates")


class PreferenceRequest(BaseModel):
    key: str = Field(..., description="Preference key")
    value: Any = Field(..., description="Preference value")


@router.post("/remember")
async def remember(request: MemoryRequest):
    try:
        memory_id = memory_manager.remember(
            request.text,
            request.memory_type,
            request.metadata
        )
        
        return {
            "success": True,
            "memory_id": memory_id,
            "message": "Memory stored successfully"
        }
    except Exception as e:
        logger.error(f"Error storing memory: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store memory: {str(e)}"
        )


@router.post("/recall")
async def recall(request: MemorySearchRequest):
    try:
        memories = memory_manager.recall(
            request.query,
            request.memory_type,
            request.n_results
        )
        
        return {
            "success": True,
            "count": len(memories),
            "memories": memories
        }
    except Exception as e:
        logger.error(f"Error recalling memories: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to recall memories: {str(e)}"
        )


@router.delete("/forget/{memory_id}")
async def forget(memory_id: str, memory_type: str = "user"):
    try:
        success = memory_manager.forget(memory_id, memory_type)
        
        if success:
            return {
                "success": True,
                "message": f"Memory '{memory_id}' forgotten"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Memory '{memory_id}' not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error forgetting memory: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to forget memory: {str(e)}"
        )


@router.get("/stats")
async def get_memory_stats():
    try:
        stats = memory_manager.get_stats()
        return {
            "success": True,
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Error getting memory stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get memory stats: {str(e)}"
        )


@router.post("/conversation/message")
async def add_conversation_message(request: MessageRequest):
    try:
        message_id = conversation_history.add_message(
            request.session_id,
            request.role,
            request.content,
            request.metadata,
            request.auto_embed
        )
        
        return {
            "success": True,
            "message_id": message_id,
            "session_id": request.session_id
        }
    except Exception as e:
        logger.error(f"Error adding conversation message: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add message: {str(e)}"
        )


@router.get("/conversation/{session_id}/history")
async def get_conversation_history(
    session_id: str,
    limit: Optional[int] = None,
    include_metadata: bool = False
):
    try:
        messages = conversation_history.get_session_history(
            session_id,
            limit,
            include_metadata
        )
        
        return {
            "success": True,
            "session_id": session_id,
            "count": len(messages),
            "messages": messages
        }
    except Exception as e:
        logger.error(f"Error getting conversation history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get conversation history: {str(e)}"
        )


@router.post("/conversation/rag-context")
async def get_rag_context(request: RAGContextRequest):
    try:
        context = conversation_history.get_rag_context(
            request.session_id,
            request.query,
            request.max_recent,
            request.max_relevant
        )
        
        return {
            "success": True,
            "context": context
        }
    except Exception as e:
        logger.error(f"Error getting RAG context: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get RAG context: {str(e)}"
        )


@router.get("/conversation/sessions")
async def list_sessions(
    user_id: Optional[str] = None,
    active_only: bool = True,
    limit: int = 50
):
    try:
        sessions = conversation_history.list_sessions(user_id, active_only, limit)
        
        return {
            "success": True,
            "count": len(sessions),
            "sessions": sessions
        }
    except Exception as e:
        logger.error(f"Error listing sessions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list sessions: {str(e)}"
        )


@router.delete("/conversation/{session_id}")
async def delete_session(session_id: str):
    try:
        success = conversation_history.delete_session(session_id)
        
        if success:
            return {
                "success": True,
                "message": f"Session '{session_id}' deleted"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting session: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete session: {str(e)}"
        )


@router.get("/conversation/stats")
async def get_conversation_stats():
    try:
        stats = conversation_history.get_statistics()
        return {
            "success": True,
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Error getting conversation stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get conversation stats: {str(e)}"
        )


@router.get("/profile/{user_id}")
async def get_profile(user_id: str = "default"):
    try:
        profile = profile_manager.get_profile(user_id)
        return {
            "success": True,
            "profile": profile.export_profile()
        }
    except Exception as e:
        logger.error(f"Error getting profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get profile: {str(e)}"
        )


@router.put("/profile/{user_id}")
async def update_profile(user_id: str, request: ProfileUpdateRequest):
    try:
        profile = profile_manager.get_profile(user_id)
        success = profile.update(request.updates)
        
        if success:
            return {
                "success": True,
                "message": "Profile updated successfully",
                "profile": profile.export_profile()
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update profile"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update profile: {str(e)}"
        )


@router.post("/profile/{user_id}/preference")
async def set_preference(user_id: str, request: PreferenceRequest):
    try:
        profile = profile_manager.get_profile(user_id)
        success = profile.set_preference(request.key, request.value)
        
        if success:
            return {
                "success": True,
                "message": f"Preference '{request.key}' set to '{request.value}'"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to set preference"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting preference: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to set preference: {str(e)}"
        )


@router.get("/profile/{user_id}/preference/{key}")
async def get_preference(user_id: str, key: str):
    try:
        profile = profile_manager.get_profile(user_id)
        value = profile.get_preference(key)
        
        return {
            "success": True,
            "key": key,
            "value": value
        }
    except Exception as e:
        logger.error(f"Error getting preference: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get preference: {str(e)}"
        )


@router.get("/profile/{user_id}/personalization")
async def get_personalization_context(user_id: str = "default"):
    try:
        profile = profile_manager.get_profile(user_id)
        context = profile.get_personalization_context()
        
        return {
            "success": True,
            "context": context
        }
    except Exception as e:
        logger.error(f"Error getting personalization context: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get personalization context: {str(e)}"
        )


@router.delete("/profile/{user_id}")
async def delete_profile(user_id: str):
    try:
        success = profile_manager.delete_profile(user_id)
        
        if success:
            return {
                "success": True,
                "message": f"Profile '{user_id}' deleted"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Profile '{user_id}' not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete profile: {str(e)}"
        )


@router.get("/profiles")
async def list_profiles():
    try:
        profiles = profile_manager.list_profiles()
        return {
            "success": True,
            "count": len(profiles),
            "profiles": profiles
        }
    except Exception as e:
        logger.error(f"Error listing profiles: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list profiles: {str(e)}"
        )
