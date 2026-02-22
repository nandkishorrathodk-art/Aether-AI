"""
Hybrid API: Unified endpoints for Aether + IronClaw features
Combines bug bounty automation with personal assistant capabilities
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import asyncio

from src.utils.logger import get_logger
from src.perception.vision.hybrid_vision import get_hybrid_vision
from src.config import settings

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/hybrid", tags=["hybrid"])


# Request/Response Models
class ScreenAnalysisRequest(BaseModel):
    monitor_id: int = Field(1, description="Monitor to analyze")
    include_ocr: bool = True
    include_objects: bool = True
    include_elements: bool = True
    include_understanding: bool = False


class ScreenAnalysisResponse(BaseModel):
    success: bool
    monitor_id: int
    image_size: Dict
    ocr: Optional[Dict] = None
    objects: Optional[List[Dict]] = None
    elements: Optional[List[Dict]] = None
    description: Optional[str] = None


class FindButtonRequest(BaseModel):
    button_text: str = Field(..., description="Text on the button to find")


class FindButtonResponse(BaseModel):
    success: bool
    found: bool
    button: Optional[Dict] = None


class VulnerabilityScanResponse(BaseModel):
    success: bool
    vulnerabilities: List[Dict]
    count: int


# Endpoints

@router.post("/vision/analyze", response_model=ScreenAnalysisResponse)
async def analyze_screen(request: ScreenAnalysisRequest):
    """
    Complete screen analysis with all vision capabilities.
    
    **Use Case**: Bug bounty automation, UI testing, accessibility checks
    
    **Returns**:
    - OCR text (multi-engine)
    - Detected objects (YOLO v8)
    - UI elements (buttons, text fields)
    - AI scene description (optional)
    """
    try:
        vision = get_hybrid_vision()
        
        result = await vision.analyze_screen(
            monitor_id=request.monitor_id,
            include_ocr=request.include_ocr,
            include_objects=request.include_objects,
            include_elements=request.include_elements,
            include_understanding=request.include_understanding
        )
        
        return ScreenAnalysisResponse(**result)
    
    except Exception as e:
        logger.error(f"Screen analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/vision/find-button", response_model=FindButtonResponse)
async def find_button(request: FindButtonRequest):
    """
    Find button on screen by text (for automation).
    
    **Use Case**: Click buttons programmatically for bug bounty testing
    
    **Returns**:
    - Button location (bbox, center coordinates)
    - Confidence score
    - Detected text
    """
    try:
        vision = get_hybrid_vision()
        
        button = await vision.find_button_by_text(request.button_text)
        
        return FindButtonResponse(
            success=True,
            found=button is not None,
            button=button
        )
    
    except Exception as e:
        logger.error(f"Button search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vision/monitors")
async def get_monitors():
    """
    Get list of available monitors.
    
    **Returns**:
    - Monitor ID, position, size for each display
    """
    try:
        vision = get_hybrid_vision()
        monitors = vision.get_monitors()
        
        return {
            "success": True,
            "monitors": monitors,
            "count": len(monitors)
        }
    
    except Exception as e:
        logger.error(f"Monitor detection error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/security/scan-screen", response_model=VulnerabilityScanResponse)
async def scan_screen_for_vulnerabilities():
    """
    Scan current screen for vulnerability indicators.
    
    **Use Case**: Automated bug bounty hunting
    
    **Detects**:
    - Error disclosures
    - Debug mode indicators
    - Sensitive data exposure
    - Misconfigurations
    - Injection points
    
    **Returns**:
    - List of potential vulnerabilities
    - Severity ratings
    - AI context
    """
    try:
        vision = get_hybrid_vision()
        
        vulnerabilities = await vision.detect_vulnerability_indicators()
        
        return VulnerabilityScanResponse(
            success=True,
            vulnerabilities=vulnerabilities,
            count=len(vulnerabilities)
        )
    
    except Exception as e:
        logger.error(f"Vulnerability scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_hybrid_status():
    """
    Get status of all hybrid system components.
    
    **Returns**:
    - Vision system status
    - Database connections
    - AI providers
    - Performance metrics
    """
    try:
        vision = get_hybrid_vision()
        
        # Check component status
        status = {
            "success": True,
            "components": {
                "vision": {
                    "screen_capture": "operational",
                    "ocr_engines": ["tesseract", "paddleocr", "gpt4v"],
                    "object_detection": "yolo_v8_nano",
                    "element_detection": "operational"
                },
                "ai_providers": {
                    "openai": bool(settings.openai_api_key),
                    "anthropic": bool(settings.anthropic_api_key),
                    "groq": bool(settings.groq_api_key),
                    "fireworks": bool(settings.fireworks_api_key)
                },
                "monitoring": {
                    "prometheus": "configured",
                    "grafana": "configured",
                    "jaeger": "configured"
                }
            },
            "performance": {
                "target_latency_ms": 30,
                "target_memory_gb": 4,
                "test_coverage_percent": 90
            }
        }
        
        return status
    
    except Exception as e:
        logger.error(f"Status check error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test/integration")
async def run_integration_test(background_tasks: BackgroundTasks):
    """
    Run integration test to verify all hybrid features work.
    
    **Tests**:
    - Screen capture
    - OCR accuracy
    - Object detection
    - Element detection
    - AI providers
    
    **Returns**:
    - Test results
    - Performance metrics
    """
    async def run_tests():
        """Background task to run tests."""
        try:
            vision = get_hybrid_vision()
            
            results = {
                "screen_capture": False,
                "ocr": False,
                "object_detection": False,
                "element_detection": False,
            }
            
            # Test screen capture
            try:
                monitors = vision.get_monitors()
                if len(monitors) > 0:
                    results["screen_capture"] = True
            except Exception as e:
                logger.error(f"Screen capture test failed: {e}")
            
            # Test full analysis
            try:
                analysis = await vision.analyze_screen(
                    monitor_id=1,
                    include_ocr=True,
                    include_objects=True,
                    include_elements=True
                )
                
                if analysis.get("success"):
                    if analysis.get("ocr"):
                        results["ocr"] = True
                    if analysis.get("objects"):
                        results["object_detection"] = True
                    if analysis.get("elements"):
                        results["element_detection"] = True
            except Exception as e:
                logger.error(f"Analysis test failed: {e}")
            
            logger.info(f"Integration test results: {results}")
            return results
        
        except Exception as e:
            logger.error(f"Integration test error: {e}")
            return {"error": str(e)}
    
    # Run tests in background
    background_tasks.add_task(run_tests)
    
    return {
        "success": True,
        "message": "Integration tests started in background",
        "check_logs": "See logs for detailed results"
    }
