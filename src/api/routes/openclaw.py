"""
OpenClaw API Routes
Web scraping and browser automation endpoints
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio

from src.action.automation.openclaw import OpenClaw, is_valid_url
from src.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/openclaw", tags=["openclaw"])

# Global OpenClaw instance
claw = OpenClaw(headless=True, timeout=30)


# ==================== REQUEST MODELS ====================

class ScrapeRequest(BaseModel):
    url: str = Field(..., description="URL to scrape")
    extract_links: bool = Field(True, description="Extract links")
    extract_images: bool = Field(True, description="Extract images")
    extract_metadata: bool = Field(True, description="Extract metadata")


class NavigateRequest(BaseModel):
    url: str = Field(..., description="URL to navigate to")


class ClickRequest(BaseModel):
    selector: str = Field(..., description="Element selector")
    by: str = Field("css", description="Selection method: css, xpath, id, class")


class FillFormRequest(BaseModel):
    fields: Dict[str, str] = Field(..., description="Form fields to fill {selector: value}")


class SubmitFormRequest(BaseModel):
    selector: str = Field(..., description="Form selector to submit")


class ExtractRequest(BaseModel):
    selector: str = Field(..., description="CSS selector to extract")
    attribute: Optional[str] = Field(None, description="Attribute to extract (optional)")


class ScreenshotRequest(BaseModel):
    filename: Optional[str] = Field(None, description="Screenshot filename")


class ScriptRequest(BaseModel):
    script: str = Field(..., description="JavaScript code to execute")


class MultiScrapeRequest(BaseModel):
    urls: List[str] = Field(..., description="List of URLs to scrape")
    max_concurrent: int = Field(5, description="Max concurrent requests")


# ==================== ENDPOINTS ====================

@router.get("/status")
async def get_status():
    """Get OpenClaw status"""
    return {
        "status": "active",
        "driver_active": claw.driver is not None,
        "headless": claw.headless,
        "timeout": claw.timeout
    }


@router.post("/scrape")
async def scrape_url(request: ScrapeRequest):
    """
    Scrape a single URL (static content)
    
    Returns page text, links, images, and metadata
    """
    try:
        if not is_valid_url(request.url):
            raise HTTPException(status_code=400, detail="Invalid URL")
        
        result = claw.scrape_url(request.url)
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return {
            "success": True,
            "data": result
        }
        
    except Exception as e:
        logger.error(f"Scrape error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scrape/async")
async def scrape_url_async(request: ScrapeRequest):
    """Async version - scrape URL without blocking"""
    try:
        if not is_valid_url(request.url):
            raise HTTPException(status_code=400, detail="Invalid URL")
        
        result = await claw.scrape_url_async(request.url)
        
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        
        return {
            "success": True,
            "data": result
        }
        
    except Exception as e:
        logger.error(f"Async scrape error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scrape/multiple")
async def scrape_multiple_urls(request: MultiScrapeRequest):
    """
    Scrape multiple URLs concurrently
    
    Max concurrent requests can be configured
    """
    try:
        if not all(is_valid_url(url) for url in request.urls):
            raise HTTPException(status_code=400, detail="One or more invalid URLs")
        
        # Scrape URLs concurrently
        tasks = [claw.scrape_url_async(url) for url in request.urls]
        results = await asyncio.gather(*tasks)
        
        return {
            "success": True,
            "total": len(results),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Multi-scrape error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/navigate")
async def navigate(request: NavigateRequest):
    """Navigate to URL using browser automation"""
    try:
        if not is_valid_url(request.url):
            raise HTTPException(status_code=400, detail="Invalid URL")
        
        success = claw.navigate_to(request.url)
        
        if not success:
            raise HTTPException(status_code=500, detail="Navigation failed")
        
        return {
            "success": True,
            "current_url": claw.get_current_url(),
            "message": f"Navigated to {request.url}"
        }
        
    except Exception as e:
        logger.error(f"Navigation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/click")
async def click_element(request: ClickRequest):
    """Click element on current page"""
    try:
        success = claw.click_element(request.selector, request.by)
        
        if not success:
            raise HTTPException(status_code=500, detail="Click failed")
        
        return {
            "success": True,
            "message": f"Clicked element: {request.selector}"
        }
        
    except Exception as e:
        logger.error(f"Click error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/form/fill")
async def fill_form(request: FillFormRequest):
    """Fill form fields on current page"""
    try:
        success = claw.fill_form(request.fields)
        
        if not success:
            raise HTTPException(status_code=500, detail="Form fill failed")
        
        return {
            "success": True,
            "fields_filled": len(request.fields),
            "message": "Form filled successfully"
        }
        
    except Exception as e:
        logger.error(f"Form fill error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/form/submit")
async def submit_form(request: SubmitFormRequest):
    """Submit form on current page"""
    try:
        success = claw.submit_form(request.selector)
        
        if not success:
            raise HTTPException(status_code=500, detail="Form submission failed")
        
        return {
            "success": True,
            "message": "Form submitted successfully"
        }
        
    except Exception as e:
        logger.error(f"Form submit error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/page/source")
async def get_page_source():
    """Get HTML source of current page"""
    try:
        source = claw.get_page_source()
        
        if not source:
            raise HTTPException(status_code=404, detail="No page loaded")
        
        return {
            "success": True,
            "source": source,
            "length": len(source)
        }
        
    except Exception as e:
        logger.error(f"Get source error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/page/text")
async def get_page_text():
    """Get visible text from current page"""
    try:
        text = claw.get_page_text()
        
        if not text:
            raise HTTPException(status_code=404, detail="No page loaded or no text found")
        
        return {
            "success": True,
            "text": text,
            "length": len(text)
        }
        
    except Exception as e:
        logger.error(f"Get text error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/page/url")
async def get_current_url():
    """Get current page URL"""
    try:
        url = claw.get_current_url()
        
        if not url:
            raise HTTPException(status_code=404, detail="No page loaded")
        
        return {
            "success": True,
            "url": url
        }
        
    except Exception as e:
        logger.error(f"Get URL error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract")
async def extract_elements(request: ExtractRequest):
    """Extract elements by CSS selector"""
    try:
        elements = claw.extract_by_selector(request.selector, request.attribute)
        
        return {
            "success": True,
            "count": len(elements),
            "elements": elements
        }
        
    except Exception as e:
        logger.error(f"Extract error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/extract/table")
async def extract_table(selector: str = "table"):
    """Extract table data from current page"""
    try:
        rows = claw.extract_table(selector)
        
        if not rows:
            raise HTTPException(status_code=404, detail="No table found")
        
        return {
            "success": True,
            "rows": len(rows),
            "data": rows
        }
        
    except Exception as e:
        logger.error(f"Table extract error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/screenshot")
async def take_screenshot(request: ScreenshotRequest):
    """Take screenshot of current page"""
    try:
        filename = request.filename or f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        filepath = f"./data/screenshots/{filename}"
        
        # Create directory if not exists
        import os
        os.makedirs("./data/screenshots", exist_ok=True)
        
        success = claw.take_screenshot(filepath)
        
        if not success:
            raise HTTPException(status_code=500, detail="Screenshot failed")
        
        return {
            "success": True,
            "filepath": filepath,
            "message": "Screenshot captured"
        }
        
    except Exception as e:
        logger.error(f"Screenshot error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute/script")
async def execute_script(request: ScriptRequest):
    """Execute JavaScript on current page"""
    try:
        result = claw.execute_script(request.script)
        
        return {
            "success": True,
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Script execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/navigation/back")
async def go_back():
    """Navigate back"""
    try:
        claw.go_back()
        return {
            "success": True,
            "current_url": claw.get_current_url()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/navigation/forward")
async def go_forward():
    """Navigate forward"""
    try:
        claw.go_forward()
        return {
            "success": True,
            "current_url": claw.get_current_url()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/navigation/refresh")
async def refresh_page():
    """Refresh current page"""
    try:
        claw.refresh()
        return {
            "success": True,
            "message": "Page refreshed"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cookies")
async def get_cookies():
    """Get all cookies from current session"""
    try:
        cookies = claw.get_cookies()
        return {
            "success": True,
            "count": len(cookies),
            "cookies": cookies
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/close")
async def close_driver():
    """Close browser driver"""
    try:
        claw.close_driver()
        return {
            "success": True,
            "message": "Driver closed"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
