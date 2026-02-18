"""
Evolution API Routes - Self-Improvement & Learning

API endpoints for the self-improvement engine and user learning system.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional

from src.evolution.self_improver import SelfImprover
from src.evolution.performance_monitor import performance_monitor
from src.intelligence.user_learning import UserLearningSystem
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/evolution", tags=["evolution"])

# Initialize components
self_improver = SelfImprover()
user_learning = UserLearningSystem()


class FeedbackRequest(BaseModel):
    """Feedback on a suggestion"""
    suggestion_id: str
    suggestion_type: str
    accepted: bool
    rating: Optional[int] = None  # 1-5
    context: Optional[Dict] = None


class InteractionRequest(BaseModel):
    """User interaction record"""
    action: str
    details: Dict
    success: bool = True


@router.post("/improve/run")
async def run_improvement_cycle():
    """
    Manually trigger daily improvement cycle.
    
    This analyzes performance, generates improvements, tests them,
    and applies successful changes.
    """
    try:
        result = await self_improver.daily_improvement_cycle()
        return result
    except Exception as e:
        logger.error(f"Improvement cycle failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/improve/opportunities")
async def get_improvement_opportunities():
    """
    Get current improvement opportunities without applying them.
    """
    try:
        opportunities = await self_improver.analyze_performance()
        return {
            "opportunities": [
                {
                    "id": opp.id,
                    "type": opp.type,
                    "description": opp.description,
                    "severity": opp.severity,
                    "impact_score": opp.impact_score,
                    "confidence": opp.confidence,
                    "detected_at": opp.detected_at.isoformat(),
                    "metrics": opp.metrics
                }
                for opp in opportunities
            ],
            "count": len(opportunities)
        }
    except Exception as e:
        logger.error(f"Failed to get opportunities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/improve/history")
async def get_improvement_history():
    """
    Get history of improvement cycles.
    """
    try:
        import json
        from pathlib import Path
        
        log_file = Path("data/improvement_log.json")
        if not log_file.exists():
            return {"history": [], "count": 0}
        
        history = json.loads(log_file.read_text())
        return {
            "history": history,
            "count": len(history)
        }
    except Exception as e:
        logger.error(f"Failed to get history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/current")
async def get_current_metrics():
    """
    Get current performance metrics.
    """
    try:
        metrics = performance_monitor.get_current_metrics()
        return metrics
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/daily")
async def get_daily_summary():
    """
    Get today's performance summary.
    """
    try:
        summary = performance_monitor.get_daily_summary()
        return summary
    except Exception as e:
        logger.error(f"Failed to get daily summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/weekly")
async def get_weekly_trend():
    """
    Get 7-day performance trend.
    """
    try:
        trend = performance_monitor.get_weekly_trend()
        return {
            "trend": trend,
            "days": len(trend)
        }
    except Exception as e:
        logger.error(f"Failed to get weekly trend: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/metrics/save")
async def save_metrics():
    """
    Manually save current metrics to file.
    """
    try:
        performance_monitor.save_metrics()
        return {"success": True, "message": "Metrics saved"}
    except Exception as e:
        logger.error(f"Failed to save metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/learn/feedback")
async def record_feedback(request: FeedbackRequest):
    """
    Record user feedback on a suggestion.
    
    This helps the system learn which suggestions are helpful.
    """
    try:
        user_learning.record_suggestion_feedback(
            suggestion_id=request.suggestion_id,
            suggestion_type=request.suggestion_type,
            accepted=request.accepted,
            feedback_rating=request.rating,
            context=request.context
        )
        return {"success": True, "message": "Feedback recorded"}
    except Exception as e:
        logger.error(f"Failed to record feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/learn/interaction")
async def record_interaction(request: InteractionRequest):
    """
    Record a user interaction.
    
    This helps track feature usage and task success rates.
    """
    try:
        user_learning.record_interaction(
            action=request.action,
            details=request.details,
            success=request.success
        )
        return {"success": True, "message": "Interaction recorded"}
    except Exception as e:
        logger.error(f"Failed to record interaction: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/learn/preferences")
async def get_user_preferences():
    """
    Get learned user preferences.
    """
    try:
        return {
            "time_of_day_preferences": user_learning.get_time_of_day_preferences(),
            "preferred_suggestion_types": user_learning.get_preferred_suggestion_types(),
            "task_success_rates": user_learning.get_task_success_rates()
        }
    except Exception as e:
        logger.error(f"Failed to get preferences: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/learn/insights")
async def get_learning_insights():
    """
    Get comprehensive learning insights.
    """
    try:
        insights = user_learning.get_learning_insights()
        return insights
    except Exception as e:
        logger.error(f"Failed to get insights: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/learn/should-suggest/{suggestion_type}")
async def should_suggest(suggestion_type: str, context: Optional[Dict] = None):
    """
    Check if a suggestion type should be shown based on learned preferences.
    """
    try:
        should_show = user_learning.should_suggest(
            suggestion_type=suggestion_type,
            context=context or {}
        )
        acceptance_rate = user_learning.get_suggestion_acceptance_rate(suggestion_type)
        
        return {
            "should_suggest": should_show,
            "acceptance_rate": acceptance_rate,
            "suggestion_type": suggestion_type
        }
    except Exception as e:
        logger.error(f"Failed to check suggestion: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_evolution_status():
    """
    Get overall status of evolution system.
    """
    try:
        metrics = performance_monitor.get_current_metrics()
        insights = user_learning.get_learning_insights()
        
        # Check if improvement needed
        opportunities = await self_improver.analyze_performance()
        
        return {
            "performance": {
                "avg_response_time": metrics.get("avg_response_time"),
                "error_rate": metrics.get("error_rate"),
                "memory_usage_mb": metrics.get("memory_usage_mb"),
                "cpu_percent": metrics.get("cpu_percent")
            },
            "learning": {
                "total_interactions": insights.get("total_interactions"),
                "total_feedback": insights.get("total_feedback"),
                "preferred_activities": insights.get("preferred_suggestion_types", [])
            },
            "improvement": {
                "opportunities_detected": len(opportunities),
                "needs_improvement": len(opportunities) > 0
            },
            "system_health": "optimal" if len(opportunities) == 0 else "needs_attention"
        }
    except Exception as e:
        logger.error(f"Failed to get status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
