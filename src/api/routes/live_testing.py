"""
Live Testing API Routes
Real-time bug bounty testing with browser automation and crawling
"""

from fastapi import APIRouter, HTTPException
from typing import Optional, List
from pydantic import BaseModel

from src.automation.browser_controller import get_browser_controller
from src.bugbounty.live_crawler import get_live_crawler
from src.bugbounty.payload_engine import get_payload_engine, PayloadCategory
from src.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/live-testing", tags=["live-testing"])


class StartTestingRequest(BaseModel):
    url: str
    max_depth: Optional[int] = 2
    max_pages: Optional[int] = 20
    headless: Optional[bool] = False


class TestPayloadRequest(BaseModel):
    injection_point: dict
    payload: str
    category: str = "xss"


class NavigateRequest(BaseModel):
    url: str
    wait_until: Optional[str] = "networkidle"


_current_crawler = None
_current_browser = None
_test_results = []


@router.post("/start")
async def start_live_testing(request: StartTestingRequest):
    """
    Start live testing: browser + crawler
    """
    global _current_crawler, _current_browser
    
    try:
        logger.info(f"Starting live testing for: {request.url}")
        
        _current_browser = get_browser_controller()
        _current_browser.headless = request.headless
        await _current_browser.start()
        
        await _current_browser.navigate(request.url)
        
        _current_crawler = get_live_crawler(
            base_url=request.url,
            max_depth=request.max_depth,
            max_pages=request.max_pages
        )
        
        crawl_result = await _current_crawler.start()
        
        if crawl_result["status"] != "success":
            raise HTTPException(status_code=500, detail=crawl_result.get("error"))
        
        endpoints = _current_crawler.get_endpoints()
        forms = _current_crawler.get_forms()
        injection_points = _current_crawler.get_injection_points()
        
        logger.info(f"Crawl complete: {len(endpoints)} endpoints, "
                   f"{len(forms)} forms, {len(injection_points)} injection points")
        
        return {
            "status": "success",
            "stats": crawl_result["stats"],
            "endpoints": endpoints[:50],
            "forms": forms[:20],
            "injection_points": injection_points[:50],
            "browser_running": _current_browser.is_running,
        }
        
    except Exception as e:
        logger.error(f"Failed to start live testing: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_live_testing():
    """Stop live testing and cleanup"""
    global _current_crawler, _current_browser
    
    try:
        if _current_browser:
            await _current_browser.stop()
            _current_browser = None
        
        _current_crawler = None
        
        return {"status": "success"}
        
    except Exception as e:
        logger.error(f"Failed to stop live testing: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_live_testing_status():
    """Get current testing status"""
    global _current_crawler, _current_browser
    
    try:
        return {
            "status": "success",
            "browser_running": _current_browser.is_running if _current_browser else False,
            "crawler_running": _current_crawler.is_running if _current_crawler else False,
            "crawl_stats": _current_crawler.get_stats() if _current_crawler else None,
            "current_page": {
                "url": _current_browser.page.url if _current_browser and _current_browser.page else None,
                "title": await _current_browser.page.title() if _current_browser and _current_browser.page else None,
            } if _current_browser else None
        }
        
    except Exception as e:
        logger.error(f"Failed to get status: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-payload")
async def test_payload(request: TestPayloadRequest):
    """
    Test a payload at an injection point
    """
    global _current_browser, _test_results
    
    try:
        if not _current_browser or not _current_browser.is_running:
            raise HTTPException(status_code=400, detail="Browser not running")
        
        injection_point = request.injection_point
        payload = request.payload
        
        logger.info(f"Testing payload at {injection_point.get('url')}: {payload[:50]}")
        
        if injection_point.get("type") == "url_parameter":
            url = injection_point["url"]
            param = injection_point["parameter"]
            
            url_with_payload = url.replace(f"{param}=", f"{param}={payload}")
            await _current_browser.navigate(url_with_payload)
            
        elif injection_point.get("type") == "form_input":
            url = injection_point["url"]
            await _current_browser.navigate(url)
            
            input_selector = f"[name='{injection_point['input_name']}']"
            await _current_browser.inject_payload(input_selector, payload)
        
        xss_detected = await _current_browser.detect_xss()
        
        page_content_result = await _current_browser.get_page_content()
        page_content = page_content_result.get("content", "")
        
        payload_engine = get_payload_engine()
        reflection_analysis = payload_engine.analyze_reflection(payload, page_content)
        
        vulnerable = (
            xss_detected.get("alert_detected") or
            (reflection_analysis.get("reflected") and 
             "inside_script" in reflection_analysis.get("contexts", []))
        )
        
        result = {
            "status": "success",
            "vulnerable": vulnerable,
            "payload": payload,
            "injection_point": injection_point,
            "xss_detected": xss_detected.get("alert_detected"),
            "reflected": reflection_analysis.get("reflected"),
            "reflection_contexts": reflection_analysis.get("contexts", []),
            "current_url": _current_browser.page.url,
        }
        
        _test_results.append(result)
        
        logger.info(f"Test complete. Vulnerable: {vulnerable}")
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to test payload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/test-results")
async def get_test_results(limit: int = 50):
    """Get recent test results"""
    global _test_results
    return {"status": "success", "results": _test_results[-limit:]}


@router.post("/browser/navigate")
async def browser_navigate(request: NavigateRequest):
    """Navigate browser to URL"""
    global _current_browser
    
    try:
        if not _current_browser or not _current_browser.is_running:
            await _current_browser.start()
        
        result = await _current_browser.navigate(request.url, request.wait_until)
        
        if result["status"] != "success":
            raise HTTPException(status_code=500, detail=result.get("error"))
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to navigate: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/browser/inputs")
async def browser_get_inputs():
    """Get input fields on current page"""
    global _current_browser
    
    try:
        if not _current_browser or not _current_browser.is_running:
            raise HTTPException(status_code=400, detail="Browser not running")
        
        result = await _current_browser.find_inputs()
        
        if result["status"] != "success":
            raise HTTPException(status_code=500, detail=result.get("error"))
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to get inputs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/browser/screenshot")
async def browser_screenshot():
    """Take screenshot of current page"""
    global _current_browser
    
    try:
        if not _current_browser or not _current_browser.is_running:
            raise HTTPException(status_code=400, detail="Browser not running")
        
        result = await _current_browser.screenshot()
        
        if result["status"] != "success":
            raise HTTPException(status_code=500, detail=result.get("error"))
        
        return result
        
    except Exception as e:
        logger.error(f"Failed to take screenshot: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/payloads/{category}")
async def get_payloads(category: str, max_payloads: int = 20):
    """Get payloads for a category"""
    try:
        payload_engine = get_payload_engine()
        
        try:
            payload_cat = PayloadCategory(category.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid category: {category}")
        
        payloads = payload_engine.generate_payloads(
            payload_cat,
            include_encoded=True,
            max_payloads=max_payloads
        )
        
        return {
            "status": "success",
            "category": category,
            "payloads": payloads,
            "count": len(payloads)
        }
        
    except Exception as e:
        logger.error(f"Failed to get payloads: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/detect-waf")
async def detect_waf():
    """Detect WAF on current page"""
    global _current_browser
    
    try:
        if not _current_browser or not _current_browser.is_running:
            raise HTTPException(status_code=400, detail="Browser not running")
        
        page_content_result = await _current_browser.get_page_content()
        page_content = page_content_result.get("content", "")
        
        request_log = await _current_browser.get_response_log(limit=1)
        headers = request_log[0]["headers"] if request_log else {}
        
        payload_engine = get_payload_engine()
        waf_detection = payload_engine.detect_waf(headers, page_content)
        
        return {
            "status": "success",
            **waf_detection
        }
        
    except Exception as e:
        logger.error(f"Failed to detect WAF: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
