"""
Aether AI v3.0 API Routes

New endpoints for v3.0 god-tier features:
- OmniTask (universal task handler)
- Predictive Agent (need forecasting)
- Empathy Engine (human-like responses)
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from src.autonomous.omni_task import omni_task_handler
from src.autonomous.predictive_agent import predictive_agent
from src.personality.empathy_engine import empathy_engine
from src.api.middleware.security import validate_api_key, check_autonomous_enabled
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/v3", tags=["v3"])


class OmniTaskRequest(BaseModel):
    """Request for OmniTask handler"""
    request: Optional[str] = None  # Can be empty for proactive mode!
    context: Optional[Dict[str, Any]] = None


class PredictRequest(BaseModel):
    """Request for predictions"""
    context: Optional[Dict[str, Any]] = None
    min_confidence: float = 0.4


class FeedbackRequest(BaseModel):
    """Prediction feedback"""
    prediction: str
    was_accurate: bool
    user_action: Optional[str] = None


@router.post("/omni")
async def omni_task(request: OmniTaskRequest):
    """
    🌟 UNIVERSAL TASK HANDLER - Handles ANYTHING!
    
    Can be called with:
    - Specific task: {"request": "find bugs on example.com"}
    - Vague request: {"request": "help me be productive"}
    - NO request: {} - Goes into proactive mode!
    
    Examples:
    ```json
    // Explicit task
    {"request": "find me a remote job as security engineer"}
    
    // Vague request (AI figures it out)
    {"request": "make me money"}
    
    // No request (proactive mode)
    {}
    ```
    
    Returns complete autonomous execution plan + results.
    """
    try:
        result = await omni_task_handler.handle(
            request=request.request,
            context=request.context
        )
        
        return {
            "success": True,
            "result": result
        }
        
    except Exception as e:
        logger.error(f"OmniTask failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/predict")
async def predict_needs(
    context: Optional[str] = None,
    min_confidence: float = 0.4
):
    """
    🔮 PREDICT WHAT YOU NEED NEXT
    
    Uses ML on your usage patterns to forecast needs.
    
    Example:
    ```
    GET /api/v1/v3/predict?min_confidence=0.6
    ```
    
    Returns:
    ```json
    {
      "predictions": [
        {"task": "bug_bounty", "confidence": 0.85, "message": "..."},
        {"task": "job_search", "confidence": 0.62, "message": "..."}
      ]
    }
    ```
    """
    try:
        context_dict = {"time": "now"}
        if context:
            import json
            try:
                context_dict = json.loads(context)
            except:
                context_dict = {"note": context}
        
        predictions = await predictive_agent.predict_next_need(context_dict)
        suggestions = await predictive_agent.get_proactive_suggestions(
            context_dict,
            min_confidence
        )
        
        return {
            "success": True,
            "predictions": [
                {"task": task, "confidence": conf}
                for task, conf in predictions
            ],
            "suggestions": suggestions
        }
        
    except Exception as e:
        logger.error(f"Prediction failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict/feedback")
async def prediction_feedback(request: FeedbackRequest):
    """
    📊 SEND PREDICTION FEEDBACK
    
    Help Aether learn by providing feedback on predictions.
    
    Example:
    ```json
    {
      "prediction": "bug_bounty",
      "was_accurate": true,
      "user_action": "started_hunt"
    }
    ```
    """
    try:
        await predictive_agent.learn_from_feedback(
            prediction=request.prediction,
            was_accurate=request.was_accurate,
            user_action=request.user_action
        )
        
        return {
            "success": True,
            "message": "Feedback recorded - Aether is learning! 🧠"
        }
        
    except Exception as e:
        logger.error(f"Feedback failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/log-activity")
async def log_activity(
    activity_type: str,
    details: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None
):
    """
    📝 LOG USER ACTIVITY
    
    Log activities for pattern learning.
    
    Example:
    ```json
    {
      "activity_type": "bug_bounty",
      "details": {"target": "example.com", "bugs_found": 3},
      "context": {"time_spent_minutes": 120}
    }
    ```
    """
    try:
        predictive_agent.log_activity(activity_type, details, context)
        
        return {
            "success": True,
            "message": "Activity logged for learning"
        }
        
    except Exception as e:
        logger.error(f"Activity logging failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/mood")
async def detect_mood(message: str):
    """
    ❤️ DETECT EMOTIONAL MOOD
    
    Detect mood from a message for empathetic responses.
    
    Example:
    ```
    GET /api/v1/v3/mood?message=I'm so frustrated with these errors
    ```
    
    Returns:
    ```json
    {
      "mood": "frustrated",
      "empathy_response": "Ji boss, main samajh sakta hoon..."
    }
    ```
    """
    try:
        mood = await empathy_engine.detect_mood(message)
        trend = empathy_engine.get_mood_trend()
        
        # Check if proactive check-in needed
        checkin = await empathy_engine.generate_proactive_check_in()
        
        return {
            "success": True,
            "mood": mood.value,
            "trend": trend,
            "proactive_checkin": checkin
        }
        
    except Exception as e:
        logger.error(f"Mood detection failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def v3_status():
    """
    📊 V3.0 SYSTEM STATUS
    
    Get overall v3.0 system status and capabilities.
    """
    try:
        # Get prediction stats
        predictions_count = len(predictive_agent.patterns.get("hourly_tasks", {}))
        
        # Get empathy stats
        empathy_interactions = empathy_engine.interaction_count
        mood_trend = empathy_engine.get_mood_trend()
        
        # Get omni task history
        omni_history_count = len(omni_task_handler.task_history)
        
        return {
            "success": True,
            "version": "3.0.0",
            "status": "operational",
            "capabilities": {
                "omni_task": True,
                "predictive_agent": True,
                "empathy_engine": True,
                "npu_optimization": False,  # Check if NPU available
                "always_on": False  # Check if running as service
            },
            "stats": {
                "learned_patterns": predictions_count,
                "empathy_interactions": empathy_interactions,
                "mood_trend": mood_trend,
                "tasks_handled": omni_history_count
            },
            "message": "Aether AI v3.0 - God-tier autonomy operational! 🚀"
        }
        
    except Exception as e:
        logger.error(f"Status check failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
