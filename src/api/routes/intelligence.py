"""
Intelligence API Routes
Endpoints for daily reports, trend analysis, and earnings tracking
"""

from fastapi import APIRouter, HTTPException
from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime

from src.intelligence import (
    get_daily_reporter,
    get_trend_analyzer,
    get_wealth_tracker,
    get_intelligence_db
)
from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/intelligence", tags=["intelligence"])


class ActivityLogRequest(BaseModel):
    activity_type: str
    description: str
    duration_minutes: int = 0
    metadata: Optional[dict] = None
    success: bool = True


class EarningRequest(BaseModel):
    source: str
    amount_usd: float
    program_name: Optional[str] = None
    vulnerability_type: Optional[str] = None
    severity: Optional[str] = None
    status: str = "pending"
    report_url: Optional[str] = None
    metadata: Optional[dict] = None


class UpdateEarningStatusRequest(BaseModel):
    status: str
    paid_at: Optional[str] = None


class DailyPlanRequest(BaseModel):
    goals: Optional[List[str]] = None


@router.get("/daily-report")
async def get_daily_report(date: Optional[str] = None):
    """Get daily report for specified date (or today)"""
    if not settings.enable_daily_reports:
        raise HTTPException(
            status_code=403,
            detail="Daily reports are disabled in settings"
        )
    
    try:
        reporter = get_daily_reporter()
        
        if date:
            try:
                report_date = datetime.fromisoformat(date)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
        else:
            report_date = None
        
        report = reporter.generate_daily_report(report_date)
        
        return {
            "status": "success",
            "report": report.to_dict(),
            "report_text": report.to_text()
        }
    except Exception as e:
        logger.error(f"Failed to generate daily report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/daily-report/weekly")
async def get_weekly_summary():
    """Get weekly summary of activities and earnings"""
    try:
        reporter = get_daily_reporter()
        summary = reporter.get_weekly_summary()
        
        return {
            "status": "success",
            "summary": summary
        }
    except Exception as e:
        logger.error(f"Failed to get weekly summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/daily-report/monthly")
async def get_monthly_summary():
    """Get monthly summary of activities and earnings"""
    try:
        reporter = get_daily_reporter()
        summary = reporter.get_monthly_summary()
        
        return {
            "status": "success",
            "summary": summary
        }
    except Exception as e:
        logger.error(f"Failed to get monthly summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/trends")
async def get_trends(category: Optional[str] = None):
    """Get trend analysis (bug_bounty, youtube, tech_jobs, or all)"""
    if not settings.enable_trend_analysis:
        raise HTTPException(
            status_code=403,
            detail="Trend analysis is disabled in settings"
        )
    
    try:
        analyzer = get_trend_analyzer()
        
        if category == "bug_bounty":
            trends = await analyzer.analyze_bug_bounty_trends()
            return {
                "status": "success",
                "category": category,
                "data": trends.to_dict()
            }
        elif category == "youtube":
            trends = await analyzer.analyze_youtube_trends()
            return {
                "status": "success",
                "category": category,
                "data": trends.to_dict()
            }
        elif category == "tech_jobs":
            trends = await analyzer.analyze_tech_job_trends()
            return {
                "status": "success",
                "category": category,
                "data": trends.to_dict()
            }
        else:
            all_trends = await analyzer.get_all_trends()
            return {
                "status": "success",
                "data": all_trends
            }
    except Exception as e:
        logger.error(f"Failed to get trends: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/earnings")
async def get_earnings(
    source: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50
):
    """Get earnings history with optional filters"""
    if not settings.enable_wealth_tracking:
        raise HTTPException(
            status_code=403,
            detail="Wealth tracking is disabled in settings"
        )
    
    try:
        tracker = get_wealth_tracker()
        earnings = tracker.get_earnings_history(
            limit=limit,
            source=source,
            status=status
        )
        
        return {
            "status": "success",
            "count": len(earnings),
            "earnings": earnings
        }
    except Exception as e:
        logger.error(f"Failed to get earnings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/earnings/stats")
async def get_earnings_stats():
    """Get comprehensive earnings statistics"""
    if not settings.enable_wealth_tracking:
        raise HTTPException(
            status_code=403,
            detail="Wealth tracking is disabled"
        )
    
    try:
        tracker = get_wealth_tracker()
        stats = tracker.get_wealth_stats()
        
        return {
            "status": "success",
            "stats": stats.to_dict()
        }
    except Exception as e:
        logger.error(f"Failed to get earnings stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/earnings/monthly")
async def get_monthly_earnings():
    """Get monthly earnings breakdown"""
    if not settings.enable_wealth_tracking:
        raise HTTPException(
            status_code=403,
            detail="Wealth tracking is disabled"
        )
    
    try:
        tracker = get_wealth_tracker()
        breakdown = tracker.get_monthly_breakdown()
        
        return {
            "status": "success",
            "monthly_breakdown": breakdown
        }
    except Exception as e:
        logger.error(f"Failed to get monthly earnings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/earnings/yearly")
async def get_yearly_earnings():
    """Get yearly earnings summary"""
    if not settings.enable_wealth_tracking:
        raise HTTPException(
            status_code=403,
            detail="Wealth tracking is disabled"
        )
    
    try:
        tracker = get_wealth_tracker()
        summary = tracker.get_yearly_summary()
        
        return {
            "status": "success",
            "yearly_summary": summary
        }
    except Exception as e:
        logger.error(f"Failed to get yearly earnings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/earnings/prediction")
async def get_payout_prediction():
    """Get next payout prediction"""
    if not settings.enable_wealth_tracking:
        raise HTTPException(
            status_code=403,
            detail="Wealth tracking is disabled"
        )
    
    try:
        tracker = get_wealth_tracker()
        prediction = tracker.predict_next_payout()
        
        return {
            "status": "success",
            "prediction": prediction
        }
    except Exception as e:
        logger.error(f"Failed to predict payout: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/earnings")
async def add_earning(request: EarningRequest):
    """Add a new earning record"""
    if not settings.enable_wealth_tracking:
        raise HTTPException(
            status_code=403,
            detail="Wealth tracking is disabled"
        )
    
    try:
        tracker = get_wealth_tracker()
        
        earning_id = tracker.add_earning(
            source=request.source,
            amount_usd=request.amount_usd,
            program_name=request.program_name,
            vulnerability_type=request.vulnerability_type,
            severity=request.severity,
            status=request.status,
            report_url=request.report_url,
            metadata=request.metadata
        )
        
        return {
            "status": "success",
            "earning_id": earning_id,
            "message": f"Added earning of ${request.amount_usd}"
        }
    except Exception as e:
        logger.error(f"Failed to add earning: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/earnings/{earning_id}")
async def update_earning_status(earning_id: int, request: UpdateEarningStatusRequest):
    """Update earning status"""
    if not settings.enable_wealth_tracking:
        raise HTTPException(
            status_code=403,
            detail="Wealth tracking is disabled"
        )
    
    try:
        tracker = get_wealth_tracker()
        
        paid_at = None
        if request.paid_at:
            try:
                paid_at = datetime.fromisoformat(request.paid_at)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date format for paid_at")
        
        success = tracker.update_report_status(
            earning_id=earning_id,
            status=request.status,
            paid_at=paid_at
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Earning not found")
        
        return {
            "status": "success",
            "message": f"Updated earning {earning_id} to {request.status}"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update earning: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/activities")
async def log_activity(request: ActivityLogRequest):
    """Log an activity"""
    try:
        db = get_intelligence_db()
        
        activity_id = db.log_activity(
            activity_type=request.activity_type,
            description=request.description,
            duration_minutes=request.duration_minutes,
            metadata=request.metadata,
            success=request.success
        )
        
        return {
            "status": "success",
            "activity_id": activity_id,
            "message": "Activity logged successfully"
        }
    except Exception as e:
        logger.error(f"Failed to log activity: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/activities")
async def get_activities(
    activity_type: Optional[str] = None,
    limit: int = 100
):
    """Get activity logs with optional filter"""
    try:
        db = get_intelligence_db()
        
        activities = db.get_activities(
            activity_type=activity_type,
            limit=limit
        )
        
        return {
            "status": "success",
            "count": len(activities),
            "activities": activities
        }
    except Exception as e:
        logger.error(f"Failed to get activities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/plan-day")
async def plan_day(request: DailyPlanRequest):
    """Generate daily plan based on goals and trends"""
    try:
        analyzer = get_trend_analyzer()
        reporter = get_daily_reporter()
        
        trends = await analyzer.get_all_trends()
        
        yesterday = datetime.now()
        yesterday_report = reporter.generate_daily_report(yesterday)
        
        plan = {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "goals": request.goals or [],
            "suggested_activities": [],
            "time_blocks": [],
            "focus_areas": []
        }
        
        bug_bounty_trends = trends.get("bug_bounty", {}).get("trends", [])
        if bug_bounty_trends:
            plan["suggested_activities"].append({
                "type": "bug_bounty",
                "description": "Bug bounty hunting session",
                "duration_minutes": 120,
                "priority": "high",
                "programs": [t["program"] for t in bug_bounty_trends[:3]]
            })
        
        youtube_trends = trends.get("youtube", {}).get("trends", [])
        recommended_niches = [t for t in youtube_trends if t.get("recommended")]
        if recommended_niches:
            plan["suggested_activities"].append({
                "type": "youtube_content",
                "description": "YouTube content creation",
                "duration_minutes": 90,
                "priority": "medium",
                "niches": [t["niche"] for t in recommended_niches[:2]]
            })
        
        plan["suggested_activities"].append({
            "type": "learning",
            "description": "Skill development and learning",
            "duration_minutes": 60,
            "priority": "medium"
        })
        
        plan["time_blocks"] = [
            {"time": "09:00-11:00", "activity": "Bug bounty hunting"},
            {"time": "11:00-12:30", "activity": "YouTube content or learning"},
            {"time": "14:00-16:00", "activity": "Deep work / focused task"},
            {"time": "16:00-17:00", "activity": "Review and planning"}
        ]
        
        plan["focus_areas"] = [
            "High-value bug bounty programs",
            "High-CPM YouTube niches",
            "Security skill development"
        ]
        
        return {
            "status": "success",
            "plan": plan,
            "trends_summary": {
                "bug_bounty_programs": len(bug_bounty_trends),
                "youtube_niches": len(recommended_niches)
            }
        }
    except Exception as e:
        logger.error(f"Failed to generate daily plan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """Check intelligence system health"""
    try:
        db = get_intelligence_db()
        
        return {
            "status": "healthy",
            "daily_reports_enabled": settings.enable_daily_reports,
            "trend_analysis_enabled": settings.enable_trend_analysis,
            "wealth_tracking_enabled": settings.enable_wealth_tracking,
            "daily_report_time": settings.daily_report_time
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e)
        }
