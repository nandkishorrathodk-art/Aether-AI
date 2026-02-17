"""
Monitoring API Routes
Lightweight orchestration for Go/Rust microservices
"""

from fastapi import APIRouter, HTTPException
from typing import Optional, List
from pydantic import BaseModel

from src.monitoring import get_monitoring_bridge, get_context_analyzer
from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/monitor", tags=["monitoring"])


class StartRequest(BaseModel):
    interval: Optional[int] = None
    save_screenshots: Optional[bool] = None


@router.post("/start")
async def start_monitoring(request: StartRequest = None):
    """Start screen monitoring service"""
    if not settings.enable_screen_monitoring:
        raise HTTPException(
            status_code=403,
            detail="Screen monitoring disabled in settings"
        )

    bridge = get_monitoring_bridge()
    result = await bridge.start_monitoring()

    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])

    return {"status": "started", "result": result}


@router.post("/stop")
async def stop_monitoring():
    """Stop screen monitoring service"""
    bridge = get_monitoring_bridge()
    result = await bridge.stop_monitoring()

    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])

    return {"status": "stopped", "result": result}


@router.get("/status")
async def get_monitor_status():
    """Get monitoring service status"""
    bridge = get_monitoring_bridge()
    status = await bridge.get_monitor_status()
    return status


@router.get("/screenshot")
async def capture_screenshot():
    """Capture current screenshot"""
    if not settings.enable_screen_monitoring:
        raise HTTPException(
            status_code=403,
            detail="Screen monitoring disabled"
        )

    bridge = get_monitoring_bridge()
    screenshot = await bridge.capture_screenshot()

    if "error" in screenshot:
        raise HTTPException(status_code=500, detail=screenshot["error"])

    return screenshot


@router.get("/current-context")
async def get_current_context(analyze: bool = True):
    """Get current application context with optional AI analysis"""
    bridge = get_monitoring_bridge()

    detection = await bridge.detect_apps()

    if "error" in detection:
        raise HTTPException(status_code=500, detail=detection["error"])

    response = {
        "apps": detection.get("apps", []),
        "active_window": detection.get("active_window"),
        "total_count": detection.get("total_count", 0),
        "detected_categories": detection.get("target_apps_detected", [])
    }

    if analyze and detection.get("target_apps_detected"):
        analyzer = get_context_analyzer()
        insight = await analyzer.analyze(detection)
        response["analysis"] = insight.to_dict()

    return response


@router.get("/check-app/{app_name}")
async def check_app_running(app_name: str):
    """Check if specific app is running"""
    bridge = get_monitoring_bridge()
    running = await bridge.check_app(app_name)

    response = {
        "app": app_name,
        "running": running
    }

    if running and app_name.lower() == "burpsuite":
        analyzer = get_context_analyzer()
        burp_context = await analyzer.analyze_burpsuite()
        response["context"] = burp_context

    return response


@router.get("/health")
async def health_check():
    """Check health of monitoring microservices"""
    bridge = get_monitoring_bridge()

    monitor_status = await bridge.get_monitor_status()
    detector_status = await bridge.detect_apps()

    return {
        "monitor_service": "error" not in monitor_status,
        "detector_service": "error" not in detector_status,
        "overall": "healthy" if "error" not in monitor_status and "error" not in detector_status else "degraded"
    }
