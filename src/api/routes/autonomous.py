"""
Autonomous Agent API Routes

API to control fully autonomous bug hunting.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any
import asyncio

from src.autonomous.auto_executor import AutoExecutor
from src.autonomous.autonomous_brain import AutonomousBrain
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/autonomous", tags=["autonomous"])

auto_executor = AutoExecutor()
current_session = None


class StartHuntRequest(BaseModel):
    """Request to start autonomous hunt"""
    target: str
    platform: str = "hackerone"
    max_duration_hours: int = 4


class SimpleStartRequest(BaseModel):
    """Simplified start request - just target"""
    target: str


@router.post("/start")
async def start_autonomous_hunt(request: StartHuntRequest, background_tasks: BackgroundTasks):
    """
    🚀 START FULLY AUTONOMOUS BUG HUNT
    
    Just provide target - everything else is automatic!
    
    Example:
    ```json
    {
        "target": "apple.com",
        "platform": "hackerone",
        "max_duration_hours": 4
    }
    ```
    
    The system will:
    1. Open Burp Suite
    2. Configure proxy
    3. Scan target
    4. Find bugs
    5. Exploit them
    6. Generate reports
    7. Submit to platform
    
    ALL AUTOMATIC - NO COMMANDS NEEDED!
    """
    global current_session
    
    try:
        if current_session and current_session.get("status") == "running":
            raise HTTPException(
                status_code=400,
                detail="Autonomous hunt already running. Stop it first."
            )
        
        current_session = {
            "status": "running",
            "target": request.target,
            "platform": request.platform,
            "start_time": None,
            "bugs_found": 0,
            "reports_submitted": 0
        }
        
        logger.info(f"🚀 Starting autonomous hunt on {request.target}")
        
        async def run_hunt():
            global current_session
            try:
                result = await auto_executor.run_full_hunt(
                    target=request.target,
                    platform=request.platform,
                    max_duration_hours=request.max_duration_hours
                )
                
                if result["success"]:
                    session_data = result["session_data"]
                    current_session["status"] = "completed"
                    current_session["bugs_found"] = len(session_data.get("bugs_found", []))
                    current_session["reports_submitted"] = len(session_data.get("reports_submitted", []))
                    current_session["total_payout"] = session_data.get("total_potential_payout", 0)
                    current_session["result"] = session_data
                else:
                    current_session["status"] = "failed"
                    current_session["error"] = result.get("error")
                    
            except Exception as e:
                logger.error(f"Background hunt failed: {e}")
                current_session["status"] = "failed"
                current_session["error"] = str(e)
        
        background_tasks.add_task(run_hunt)
        
        return {
            "success": True,
            "message": f"🚀 Autonomous hunt started on {request.target}",
            "details": "System is working autonomously. Check /status for updates.",
            "estimated_duration_hours": request.max_duration_hours
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start autonomous hunt: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/simple-start")
async def simple_start(request: SimpleStartRequest, background_tasks: BackgroundTasks):
    """
    🎯 SIMPLEST START - JUST TARGET
    
    Example:
    ```json
    {
        "target": "apple.com"
    }
    ```
    
    That's it! Everything else is automatic with smart defaults.
    """
    return await start_autonomous_hunt(
        StartHuntRequest(
            target=request.target,
            platform="hackerone",
            max_duration_hours=4
        ),
        background_tasks
    )


@router.get("/status")
async def get_status():
    """
    Get current autonomous hunt status
    
    Returns real-time updates about what's happening.
    """
    global current_session
    
    if not current_session:
        return {
            "status": "idle",
            "message": "No autonomous hunt running"
        }
    
    return {
        "status": current_session.get("status"),
        "target": current_session.get("target"),
        "platform": current_session.get("platform"),
        "bugs_found": current_session.get("bugs_found", 0),
        "reports_submitted": current_session.get("reports_submitted", 0),
        "total_potential_payout": current_session.get("total_payout", 0)
    }


@router.post("/stop")
async def stop_autonomous_hunt():
    """
    Stop autonomous hunt gracefully
    """
    global current_session
    
    if not current_session or current_session.get("status") != "running":
        raise HTTPException(
            status_code=400,
            detail="No active hunt to stop"
        )
    
    logger.info("Stopping autonomous hunt...")
    
    current_session["status"] = "stopped"
    
    return {
        "success": True,
        "message": "Autonomous hunt stopped",
        "final_stats": {
            "bugs_found": current_session.get("bugs_found", 0),
            "reports_submitted": current_session.get("reports_submitted", 0)
        }
    }


@router.get("/results")
async def get_results():
    """
    Get final results of completed hunt
    """
    global current_session
    
    if not current_session:
        raise HTTPException(status_code=404, detail="No session found")
    
    if current_session.get("status") != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Hunt not completed yet. Current status: {current_session.get('status')}"
        )
    
    return {
        "success": True,
        "session": current_session.get("result", {})
    }


@router.get("/live-updates")
async def live_updates():
    """
    SSE endpoint for live updates (for future WebSocket implementation)
    """
    global current_session
    
    if not current_session:
        return {"updates": []}
    
    return {
        "status": current_session.get("status"),
        "latest_activity": "Scanning in progress...",
        "bugs_found_so_far": current_session.get("bugs_found", 0)
    }
