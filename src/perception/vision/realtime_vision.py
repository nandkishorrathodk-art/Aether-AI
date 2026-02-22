"""
Aether Real-Time Vision Engine

Allows Aether to literally "see" your screen every 2 seconds.
Like a human pair-programmer or Jarvis looking over your shoulder.

Capabilities:
1. Takes a screenshot every `interval` seconds (default 2s)
2. Uses lightweight OCR/vision to detect context (errors, progress bars, new apps)
3. If it sees something important (like an error in terminal or BurpSuite bug),
   it INSTANTLY narrates and steps in without you asking.
"""

import asyncio
import logging
import threading
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

# Assume we have MSS or Pillow for fast screenshots, and easyocr/pytesseract for text
try:
    from mss import mss
    from PIL import Image
    import pytesseract  # Or easyocr if installed
    VISION_AVAILABLE = True
except ImportError:
    VISION_AVAILABLE = False


logger = logging.getLogger(__name__)


class RealTimeVision:
    """
    Continuous screen monitoring thread.
    """

    def __init__(self, interval_seconds: float = 5.0):
        self.interval = interval_seconds
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_context = ""
        self._consecutive_matches = 0
        self._active_window_title = ""
        
        # Keywords that trigger immediate Aether response
        self.trigger_keywords = [
            "error", "exception", "traceback", "failed", "denied",
            "vulnerability found", "critical", "bounty", "success",
            "completed", "finished"
        ]

        logger.info("👁️ Real-Time Vision initialized")

    def start(self):
        if not VISION_AVAILABLE:
            logger.warning("👁️ Vision libraries (mss, Pillow, pytesseract) not installed. Cannot start Live Vision.")
            return

        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._vision_loop, daemon=True, name="AetherVision")
        self._thread.start()
        logger.info(f"👁️ Real-Time Vision STARTED (Interval: {self.interval}s)")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("👁️ Real-Time Vision STOPPED")

    def get_active_window_context(self) -> str:
        """Returns the title of the currently active window"""
        try:
            import pygetwindow as gw
            active_window = gw.getActiveWindow()
            if active_window:
                self._active_window_title = active_window.title
                return self._active_window_title
        except Exception:
            pass
        return self._active_window_title

    def _vision_loop(self):
        """Background loop taking screenshots and running quick OCR"""
        with mss() as sct:
            monitor = sct.monitors[1]  # Primary monitor
            
            while not self._stop_event.is_set():
                try:
                    # 1. Track Active Window
                    app_context = self.get_active_window_context()
                    
                    # 2. Capture screen quickly
                    img = sct.grab(monitor)
                    pil_img = Image.frombytes("RGB", img.size, img.bgra, "raw", "BGRX")
                    
                    # 3. Fast OCR
                    text = pytesseract.image_to_string(pil_img).lower()
                    
                    # 4. Analyze text for triggers (including app context)
                    full_context = f"App: {app_context}\nText: {text}"
                    self._analyze_screen_text(full_context)

                except Exception as e:
                    logger.debug(f"Vision loop error: {e}")
                
                # Sleep until next frame
                time.sleep(self.interval)

    def _analyze_screen_text(self, context_text: str):
        """Look for important events on screen to react to"""
        if not context_text.strip():
            return

        found_triggers = [kw for kw in self.trigger_keywords if kw in context_text]

        if not found_triggers:
            # Nothing interesting on screen right now
            return

        # Simple deduplication
        current_context = " ".join(found_triggers)
        if current_context == self._last_context:
            self._consecutive_matches += 1
            if self._consecutive_matches > 10: # Spacing out reactions
                return
        else:
            self._last_context = current_context
            self._consecutive_matches = 1

        if self._consecutive_matches == 1:
            self._react_to_triggers(found_triggers, context_text)

    def _react_to_triggers(self, triggers: List[str], full_text: str):
        """Tell the proactive agent or voice pipeline to speak up!"""
        
        # Get pipelines
        try:
            from src.pipeline.voice_pipeline import get_pipeline
            pipe = get_pipeline()
            
            from src.monitoring.hud_broadcaster import get_hud_broadcaster
            hud = get_hud_broadcaster()
        except ImportError:
            return

        # Improved logic: Combine OCR triggers with Active Window context
        app_lower = self._active_window_title.lower()
        
        if "error" in triggers or "exception" in triggers or "traceback" in triggers:
            if "visual studio" in app_lower or "code" in app_lower or "terminal" in app_lower:
                msg = f"Sir, aapke {app_lower} mein error dikh raha hai. Check karun?"
            else:
                msg = "Sir, screen pe ek error dikh raha hai. Debug karun kya?"
            
            if pipe: pipe.narrate(msg)
            if hud: hud.update({"narration": msg, "status": "thinking"})
            
        elif "vulnerability found" in triggers or "critical" in triggers:
            msg = "BOSS! Screen pe critical vulnerability dikh rahi hai! Report generate kar raha hoon!"
            if pipe: pipe.narrate(msg)
            if hud: hud.bug_found("Screen Detected Vulnerability")
            
        elif "completed" in triggers or "success" in triggers:
            msg = f"Sir, {app_lower} ka process complete ho gaya hai."
            if pipe: pipe.narrate(msg)

# Global Instance
_vision_engine = None

def get_realtime_vision() -> RealTimeVision:
    global _vision_engine
    if _vision_engine is None:
        _vision_engine = RealTimeVision()
    return _vision_engine

def start_realtime_vision():
    engine = get_realtime_vision()
    engine.start()
    return engine
