"""
Proactive AI API Routes
Endpoints for proactive suggestions, daily planning, and autonomous actions
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from src.proactive import get_proactive_brain, get_auto_executor
from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/proactive", tags=["proactive"])


class CheckNowRequest(BaseModel):
    context: Optional[Dict[str, Any]] = None


class ExecuteSuggestionRequest(BaseModel):
    suggestion_id: str
    auto_approve: bool = False


class DailyPlanRequest(BaseModel):
    goals: Optional[List[str]] = None
    preferences: Optional[Dict[str, Any]] = None


class ApprovalRequest(BaseModel):
    action_id: str
    approved: bool


@router.get("/suggestions")
async def get_suggestions(limit: int = 10):
    """Get recent proactive suggestions"""
    if not settings.enable_proactive_mode:
        raise HTTPException(
            status_code=403,
            detail="Proactive mode is disabled in settings"
        )
    
    try:
        brain = get_proactive_brain()
        suggestions = brain.suggestion_generator.get_recent_suggestions(limit)
        
        return {
            "status": "success",
            "count": len(suggestions),
            "suggestions": [s.to_dict() for s in suggestions]
        }
    except Exception as e:
        logger.error(f"Failed to get suggestions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/check-now")
async def check_now(request: CheckNowRequest = None):
    """Trigger proactive check immediately"""
    if not settings.enable_proactive_mode:
        raise HTTPException(
            status_code=403,
            detail="Proactive mode is disabled"
        )
    
    try:
        brain = get_proactive_brain()
        context = request.context if request else None
        
        result = await brain.check_and_suggest(current_context=context)
        
        return result
    except Exception as e:
        logger.error(f"Proactive check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute-suggestion")
async def execute_suggestion(request: ExecuteSuggestionRequest):
    """Execute a proactive suggestion"""
    if not settings.enable_proactive_mode:
        raise HTTPException(
            status_code=403,
            detail="Proactive mode is disabled"
        )
    
    try:
        brain = get_proactive_brain()
        executor = get_auto_executor()
        
        suggestion = brain.get_suggestion_by_id(request.suggestion_id)
        if not suggestion:
            raise HTTPException(status_code=404, detail="Suggestion not found")
        
        if not suggestion.action_command:
            raise HTTPException(
                status_code=400,
                detail="Suggestion has no executable action"
            )
        
        skip_approval = request.auto_approve and not suggestion.requires_approval
        
        result = await executor.execute_action(
            action_command=suggestion.action_command,
            action_id=request.suggestion_id,
            parameters=suggestion.metadata,
            skip_approval=skip_approval
        )
        
        return {
            "status": "success",
            "execution_result": result.to_dict()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to execute suggestion: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/daily-plan")
async def get_daily_plan(date: Optional[str] = None):
    """Get daily plan for specified date (or today)"""
    if not settings.proactive_daily_planning:
        raise HTTPException(
            status_code=403,
            detail="Daily planning is disabled"
        )
    
    try:
        brain = get_proactive_brain()
        plan = brain.daily_planner.load_plan(date)
        
        if not plan:
            plan = await brain.daily_planner.generate_daily_plan()
        
        return {
            "status": "success",
            "plan": plan.to_dict()
        }
    except Exception as e:
        logger.error(f"Failed to get daily plan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/daily-plan")
async def create_daily_plan(request: DailyPlanRequest):
    """Generate a new daily plan"""
    if not settings.proactive_daily_planning:
        raise HTTPException(
            status_code=403,
            detail="Daily planning is disabled"
        )
    
    try:
        brain = get_proactive_brain()
        result = await brain.generate_daily_plan(user_goals=request.goals)
        
        return result
    except Exception as e:
        logger.error(f"Failed to create daily plan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/greeting")
async def get_morning_greeting():
    """Get proactive morning greeting"""
    if not settings.proactive_morning_greeting:
        raise HTTPException(
            status_code=403,
            detail="Morning greetings are disabled"
        )
    
    try:
        brain = get_proactive_brain()
        greeting = await brain.proactive_greeting()
        
        return {
            "status": "success",
            "greeting": greeting
        }
    except Exception as e:
        logger.error(f"Failed to generate greeting: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/pending-approvals")
async def get_pending_approvals():
    """Get actions pending user approval"""
    try:
        executor = get_auto_executor()
        pending = executor.get_pending_approvals()
        
        return {
            "status": "success",
            "count": len(pending),
            "pending_approvals": pending
        }
    except Exception as e:
        logger.error(f"Failed to get pending approvals: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/approve-action")
async def approve_action(request: ApprovalRequest):
    """Approve or reject a pending action"""
    try:
        executor = get_auto_executor()
        
        if request.approved:
            result = await executor.approve_and_execute(request.action_id)
        else:
            success = executor.reject_action(request.action_id)
            if not success:
                raise HTTPException(status_code=404, detail="Action not found")
            
            return {
                "status": "success",
                "action": "rejected",
                "action_id": request.action_id
            }
        
        return {
            "status": "success",
            "action": "approved",
            "execution_result": result.to_dict()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process approval: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/execution-history")
async def get_execution_history(limit: int = 50):
    """Get history of executed actions"""
    try:
        executor = get_auto_executor()
        history = executor.get_execution_history(limit)
        
        return {
            "status": "success",
            "count": len(history),
            "history": [h.to_dict() for h in history]
        }
    except Exception as e:
        logger.error(f"Failed to get execution history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def get_statistics():
    """Get proactive system statistics"""
    try:
        brain = get_proactive_brain()
        stats = brain.get_statistics()
        
        executor = get_auto_executor()
        stats["total_executions"] = len(executor.execution_history)
        stats["pending_approvals"] = len(executor.pending_approvals)
        
        return {
            "status": "success",
            "statistics": stats
        }
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Check proactive system health"""
    try:
        brain = get_proactive_brain()
        enabled = settings.enable_proactive_mode
        
        return {
            "status": "healthy",
            "enabled": enabled,
            "morning_greeting": settings.proactive_morning_greeting,
            "daily_planning": settings.proactive_daily_planning,
            "check_interval": settings.proactive_check_interval
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }
