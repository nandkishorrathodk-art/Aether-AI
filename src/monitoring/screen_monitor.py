"""
Screen Monitor - Simple wrapper for autonomous mode

Provides a simplified interface to the existing monitoring infrastructure.
"""

import asyncio
from typing import Optional
from pathlib import Path
import time

from src.monitoring.bridge import get_monitoring_bridge
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ScreenMonitor:
    """
    Simplified screen monitoring interface for autonomous mode.
    
    Wraps the existing MonitoringBridge with a simpler API.
    """
    
    def __init__(self):
        try:
            self.bridge = get_monitoring_bridge()
            logger.info("Screen Monitor initialized")
        except Exception as e:
            logger.warning(f"Monitoring bridge not available: {e}")
            self.bridge = None
    
    async def capture_screenshot(self) -> Optional[str]:
        """
        Capture a screenshot
        
        Returns:
            Path to screenshot file, or None if capture fails
        """
        try:
            if self.bridge is None:
                logger.warning("Monitoring bridge not available, using fallback")
                return self._fallback_screenshot()
            
            # Use existing bridge to capture
            result = await self.bridge.capture_screenshot()
            
            if result and "path" in result:
                return result["path"]
            
            return self._fallback_screenshot()
            
        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
            return self._fallback_screenshot()
    
    def _fallback_screenshot(self) -> Optional[str]:
        """
        Fallback screenshot using mss directly
        """
        try:
            import mss
            from PIL import Image
            
            screenshots_dir = Path("data/screenshots")
            screenshots_dir.mkdir(parents=True, exist_ok=True)
            
            filename = f"screenshot_{int(time.time())}.png"
            filepath = screenshots_dir / filename
            
            with mss.mss() as sct:
                monitor = sct.monitors[1]  # Primary monitor
                screenshot = sct.grab(monitor)
                
                # Convert to PIL Image and save
                img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                img.save(str(filepath))
                
                logger.info(f"Screenshot saved: {filepath}")
                return str(filepath)
                
        except Exception as e:
            logger.error(f"Fallback screenshot failed: {e}")
            return None
    
    async def start_monitoring(self, interval: int = 30):
        """
        Start continuous monitoring
        
        Args:
            interval: Capture interval in seconds
        """
        if self.bridge:
            try:
                await self.bridge.start_monitoring(interval=interval)
            except Exception as e:
                logger.error(f"Failed to start monitoring: {e}")
    
    async def stop_monitoring(self):
        """Stop monitoring"""
        if self.bridge:
            try:
                await self.bridge.stop_monitoring()
            except Exception as e:
                logger.error(f"Failed to stop monitoring: {e}")
