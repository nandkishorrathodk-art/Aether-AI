"""
Browser Controller - Playwright Integration for Live Testing
Enables real-time browser automation for bug bounty hunting
"""

import asyncio
from typing import Optional, Dict, List, Any
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright
import json
from datetime import datetime

from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)


class BrowserController:
    """
    High-level browser automation controller using Playwright
    Supports Chromium, Firefox, and WebKit browsers
    """
    
    def __init__(self, browser_type: str = "chromium", headless: bool = False):
        """
        Initialize browser controller
        
        Args:
            browser_type: Browser type (chromium, firefox, webkit)
            headless: Run browser in headless mode
        """
        self.browser_type = browser_type
        self.headless = headless
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.is_running = False
        
        self.request_log: List[Dict] = []
        self.response_log: List[Dict] = []
        self.console_log: List[Dict] = []
        
    async def start(self) -> Dict[str, Any]:
        """Start browser instance"""
        try:
            logger.info(f"Starting {self.browser_type} browser (headless={self.headless})")
            
            self.playwright = await async_playwright().start()
            
            if self.browser_type == "chromium":
                self.browser = await self.playwright.chromium.launch(
                    headless=self.headless,
                    args=['--disable-blink-features=AutomationControlled']
                )
            elif self.browser_type == "firefox":
                self.browser = await self.playwright.firefox.launch(headless=self.headless)
            elif self.browser_type == "webkit":
                self.browser = await self.playwright.webkit.launch(headless=self.headless)
            else:
                raise ValueError(f"Unsupported browser type: {self.browser_type}")
            
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            
            self.page = await self.context.new_page()
            
            self._setup_event_listeners()
            
            self.is_running = True
            logger.info("Browser started successfully")
            
            return {
                "status": "success",
                "browser_type": self.browser_type,
                "headless": self.headless,
                "is_running": self.is_running
            }
            
        except Exception as e:
            logger.error(f"Failed to start browser: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    def _setup_event_listeners(self):
        """Setup event listeners for requests, responses, and console"""
        if not self.page:
            return
        
        self.page.on("request", self._on_request)
        self.page.on("response", self._on_response)
        self.page.on("console", self._on_console)
    
    def _on_request(self, request):
        """Log all HTTP requests"""
        self.request_log.append({
            "timestamp": datetime.now().isoformat(),
            "method": request.method,
            "url": request.url,
            "headers": request.headers,
            "post_data": request.post_data
        })
    
    def _on_response(self, response):
        """Log all HTTP responses"""
        self.response_log.append({
            "timestamp": datetime.now().isoformat(),
            "status": response.status,
            "url": response.url,
            "headers": response.headers
        })
    
    def _on_console(self, msg):
        """Log console messages"""
        self.console_log.append({
            "timestamp": datetime.now().isoformat(),
            "type": msg.type,
            "text": msg.text
        })
    
    async def navigate(self, url: str, wait_until: str = "networkidle") -> Dict[str, Any]:
        """
        Navigate to URL
        
        Args:
            url: Target URL
            wait_until: Wait condition (load, domcontentloaded, networkidle)
        """
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            logger.info(f"Navigating to: {url}")
            response = await self.page.goto(url, wait_until=wait_until, timeout=30000)
            
            return {
                "status": "success",
                "url": self.page.url,
                "title": await self.page.title(),
                "status_code": response.status if response else None
            }
            
        except Exception as e:
            logger.error(f"Navigation failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def fill_form(self, selector: str, value: str) -> Dict[str, Any]:
        """
        Fill form input
        
        Args:
            selector: CSS selector
            value: Value to fill
        """
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            await self.page.fill(selector, value)
            logger.info(f"Filled form: {selector}")
            
            return {"status": "success", "selector": selector}
            
        except Exception as e:
            logger.error(f"Failed to fill form: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def click(self, selector: str) -> Dict[str, Any]:
        """
        Click element
        
        Args:
            selector: CSS selector
        """
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            await self.page.click(selector)
            logger.info(f"Clicked: {selector}")
            
            return {"status": "success", "selector": selector}
            
        except Exception as e:
            logger.error(f"Failed to click: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def inject_payload(self, selector: str, payload: str) -> Dict[str, Any]:
        """
        Inject XSS/injection payload into input
        
        Args:
            selector: CSS selector
            payload: Payload string
        """
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            await self.page.fill(selector, payload)
            
            await asyncio.sleep(0.5)
            
            alerts_triggered = await self.page.evaluate("""
                () => {
                    return window.__xss_triggered__ || false;
                }
            """)
            
            logger.info(f"Injected payload into {selector}: {payload[:50]}...")
            
            return {
                "status": "success",
                "selector": selector,
                "payload": payload,
                "alerts_triggered": alerts_triggered,
                "current_url": self.page.url
            }
            
        except Exception as e:
            logger.error(f"Failed to inject payload: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def detect_xss(self) -> Dict[str, Any]:
        """
        Detect if XSS payload executed
        """
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            alert_detected = await self.page.evaluate("""
                () => {
                    const originalAlert = window.alert;
                    window.__xss_triggered__ = false;
                    window.alert = function(...args) {
                        window.__xss_triggered__ = true;
                        return true;
                    };
                    return window.__xss_triggered__;
                }
            """)
            
            reflected_payload = await self.page.content()
            
            return {
                "status": "success",
                "alert_detected": alert_detected,
                "page_content_length": len(reflected_payload)
            }
            
        except Exception as e:
            logger.error(f"XSS detection failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def get_page_content(self) -> Dict[str, Any]:
        """Get current page HTML content"""
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            content = await self.page.content()
            
            return {
                "status": "success",
                "content": content,
                "url": self.page.url,
                "title": await self.page.title()
            }
            
        except Exception as e:
            logger.error(f"Failed to get page content: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def screenshot(self, path: Optional[str] = None) -> Dict[str, Any]:
        """
        Take screenshot
        
        Args:
            path: File path to save screenshot (optional)
        """
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            if not path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                path = f"data/screenshots/browser_{timestamp}.png"
            
            await self.page.screenshot(path=path, full_page=True)
            logger.info(f"Screenshot saved: {path}")
            
            return {"status": "success", "path": path}
            
        except Exception as e:
            logger.error(f"Screenshot failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def get_request_log(self, limit: int = 50) -> List[Dict]:
        """Get recent HTTP requests"""
        return self.request_log[-limit:]
    
    async def get_response_log(self, limit: int = 50) -> List[Dict]:
        """Get recent HTTP responses"""
        return self.response_log[-limit:]
    
    async def get_console_log(self, limit: int = 50) -> List[Dict]:
        """Get recent console messages"""
        return self.console_log[-limit:]
    
    async def execute_js(self, script: str) -> Dict[str, Any]:
        """
        Execute JavaScript in page context
        
        Args:
            script: JavaScript code to execute
        """
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            result = await self.page.evaluate(script)
            
            return {"status": "success", "result": result}
            
        except Exception as e:
            logger.error(f"JavaScript execution failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def find_inputs(self) -> Dict[str, Any]:
        """Find all input fields on current page"""
        try:
            if not self.page:
                return {"status": "error", "error": "Browser not started"}
            
            inputs = await self.page.evaluate("""
                () => {
                    const inputs = [];
                    document.querySelectorAll('input, textarea').forEach(el => {
                        inputs.push({
                            tag: el.tagName.toLowerCase(),
                            type: el.type || 'text',
                            name: el.name || '',
                            id: el.id || '',
                            placeholder: el.placeholder || '',
                            value: el.value || ''
                        });
                    });
                    return inputs;
                }
            """)
            
            logger.info(f"Found {len(inputs)} input fields")
            
            return {"status": "success", "inputs": inputs, "count": len(inputs)}
            
        except Exception as e:
            logger.error(f"Failed to find inputs: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def stop(self) -> Dict[str, Any]:
        """Stop browser and cleanup"""
        try:
            logger.info("Stopping browser")
            
            if self.context:
                await self.context.close()
            
            if self.browser:
                await self.browser.close()
            
            if self.playwright:
                await self.playwright.stop()
            
            self.is_running = False
            logger.info("Browser stopped")
            
            return {"status": "success", "is_running": self.is_running}
            
        except Exception as e:
            logger.error(f"Failed to stop browser: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()


_browser_instance: Optional[BrowserController] = None


def get_browser_controller() -> BrowserController:
    """Get or create browser controller singleton"""
    global _browser_instance
    if _browser_instance is None:
        _browser_instance = BrowserController(
            browser_type=getattr(settings, 'browser_type', 'chromium'),
            headless=getattr(settings, 'browser_headless', False)
        )
    return _browser_instance
