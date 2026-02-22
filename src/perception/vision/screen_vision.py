"""
Screen Vision & OCR - See and understand everything on screen
Real-time screen analysis with element detection and auto-navigation

IRONCLAW ENHANCEMENT: Multi-monitor support with MSS (<100ms capture)
"""
import cv2
import numpy as np
from PIL import Image
import pytesseract
import mss
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import re
from pathlib import Path

@dataclass
class Monitor:
    """Monitor information for multi-monitor setups."""
    id: int
    left: int
    top: int
    width: int
    height: int
    is_primary: bool = False

    @property
    def bounds(self) -> Dict[str, int]:
        """Get monitor bounds for MSS."""
        return {"left": self.left, "top": self.top, "width": self.width, "height": self.height}

@dataclass
class ScreenElement:
    element_type: str
    text: str
    position: Tuple[int, int, int, int]
    confidence: float
    
@dataclass
class OCRResult:
    text: str
    confidence: float
    position: Tuple[int, int, int, int]
    language: str

@dataclass
class Screenshot:
    """Screenshot data with metadata."""
    image: Image.Image
    timestamp: datetime
    monitor_id: Optional[int] = None
    region: Optional[Dict[str, int]] = None
    capture_time_ms: float = 0.0

    @property
    def numpy_array(self) -> np.ndarray:
        """Convert to numpy array."""
        return np.array(self.image)

    def save(self, path: Path, format: str = "PNG") -> Path:
        """Save screenshot to file."""
        self.image.save(path, format=format)
        return path

class ScreenCapture:
    """
    IRONCLAW ENHANCEMENT: MSS-based screen capture with multi-monitor support.
    Target: <100ms capture time per monitor.
    """
    def __init__(self, screenshot_dir: Optional[Path] = None):
        self.screenshot_dir = screenshot_dir or Path("./data/screenshots")
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        
        self.last_screenshot = None
        self.screenshot_history = []
        
        self._sct: Optional[mss.mss] = None
        self._monitors: List[Monitor] = []
        self._monitor_cache_time: float = 0.0
        self._cache_ttl: float = 60.0  # Refresh monitors every 60 seconds
    
    def _get_sct(self) -> mss.mss:
        """Get or create MSS instance."""
        if self._sct is None:
            self._sct = mss.mss()
        return self._sct
    
    def _refresh_monitors(self) -> None:
        """Refresh monitor information (cached for performance)."""
        current_time = time.time()
        if current_time - self._monitor_cache_time < self._cache_ttl:
            return

        sct = self._get_sct()
        self._monitors = []

        # MSS monitor 0 is all monitors combined, skip it
        for i, monitor in enumerate(sct.monitors[1:], start=1):
            self._monitors.append(
                Monitor(
                    id=i,
                    left=monitor["left"],
                    top=monitor["top"],
                    width=monitor["width"],
                    height=monitor["height"],
                    is_primary=(i == 1),  # First monitor is usually primary
                )
            )

        self._monitor_cache_time = current_time
    
    def get_monitors(self) -> List[Monitor]:
        """Get list of available monitors."""
        self._refresh_monitors()
        return self._monitors.copy()
    
    def capture_screen(self, region: Optional[Tuple[int, int, int, int]] = None, 
                      monitor_id: Optional[int] = None) -> np.ndarray:
        """
        Capture screen using MSS (backward compatible with existing code).
        
        Args:
            region: Optional region (left, top, right, bottom)
            monitor_id: Optional monitor ID (1-indexed)
        
        Returns:
            Screenshot as numpy array
        """
        start_time = time.time()
        sct = self._get_sct()
        
        if region:
            # Convert (left, top, right, bottom) to MSS format
            capture_region = {
                "left": region[0],
                "top": region[1],
                "width": region[2] - region[0],
                "height": region[3] - region[1]
            }
            sct_img = sct.grab(capture_region)
        elif monitor_id:
            sct_img = sct.grab(sct.monitors[monitor_id])
        else:
            # Capture primary monitor
            sct_img = sct.grab(sct.monitors[1])
        
        # Convert to PIL Image then numpy
        img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
        numpy_img = np.array(img)
        
        # Update history
        self.last_screenshot = img
        self.screenshot_history.append({
            'image': img,
            'timestamp': datetime.now(),
            'capture_time_ms': (time.time() - start_time) * 1000
        })
        
        if len(self.screenshot_history) > 10:
            self.screenshot_history.pop(0)
        
        return numpy_img
    
    def capture_all_monitors(self) -> List[Screenshot]:
        """Capture screenshots of all monitors."""
        start_time = time.time()
        self._refresh_monitors()
        sct = self._get_sct()

        screenshots = []
        for monitor in self._monitors:
            monitor_data = sct.monitors[monitor.id]
            sct_img = sct.grab(monitor_data)
            img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")

            screenshot = Screenshot(
                image=img,
                timestamp=datetime.now(),
                monitor_id=monitor.id,
                region=monitor.bounds,
                capture_time_ms=(time.time() - start_time) * 1000,
            )
            screenshots.append(screenshot)

        return screenshots
    
    def capture_window(self, window_title: str) -> Optional[np.ndarray]:
        """Capture specific window by title (backward compatible)."""
        try:
            import pygetwindow as gw
            windows = gw.getWindowsWithTitle(window_title)
            
            if windows:
                window = windows[0]
                region = (window.left, window.top, window.right, window.bottom)
                return self.capture_screen(region=region)
        except Exception:
            pass
        
        return None
    
    def cleanup(self) -> None:
        """Clean up MSS resources."""
        if self._sct is not None:
            self._sct.close()
            self._sct = None

class OCREngine:
    def __init__(self, tesseract_cmd: str = None):
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
        
        self.supported_languages = ['eng', 'fra', 'deu', 'spa', 'ita', 'por', 'rus', 'ara', 'hin', 'chi_sim', 'jpn', 'kor']
    
    def extract_text(self, image: np.ndarray, language: str = 'eng') -> OCRResult:
        pil_image = Image.fromarray(image)
        
        data = pytesseract.image_to_data(pil_image, lang=language, output_type=pytesseract.Output.DICT)
        
        all_text = []
        confidences = []
        boxes = []
        
        n_boxes = len(data['text'])
        for i in range(n_boxes):
            if int(data['conf'][i]) > 0:
                text = data['text'][i].strip()
                if text:
                    all_text.append(text)
                    confidences.append(float(data['conf'][i]))
                    
                    x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                    boxes.append((x, y, x + w, y + h))
        
        full_text = ' '.join(all_text)
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        overall_box = (0, 0, 0, 0)
        if boxes:
            xs = [b[0] for b in boxes] + [b[2] for b in boxes]
            ys = [b[1] for b in boxes] + [b[3] for b in boxes]
            overall_box = (min(xs), min(ys), max(xs), max(ys))
        
        return OCRResult(
            text=full_text,
            confidence=avg_confidence / 100.0,
            position=overall_box,
            language=language
        )
    
    def extract_text_with_positions(self, image: np.ndarray, language: str = 'eng') -> List[OCRResult]:
        pil_image = Image.fromarray(image)
        
        data = pytesseract.image_to_data(pil_image, lang=language, output_type=pytesseract.Output.DICT)
        
        results = []
        n_boxes = len(data['text'])
        
        for i in range(n_boxes):
            if int(data['conf'][i]) > 60:
                text = data['text'][i].strip()
                if text:
                    x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                    
                    results.append(OCRResult(
                        text=text,
                        confidence=float(data['conf'][i]) / 100.0,
                        position=(x, y, x + w, y + h),
                        language=language
                    ))
        
        return results

class UIElementDetector:
    def __init__(self):
        self.button_cascade = None
        self.textbox_cascade = None
    
    def detect_buttons(self, image: np.ndarray) -> List[ScreenElement]:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        edges = cv2.Canny(gray, 50, 150)
        
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        buttons = []
        for contour in contours:
            x, y, w, h = cv2.boundingRect(contour)
            
            aspect_ratio = w / h if h > 0 else 0
            area = w * h
            
            if 1.5 < aspect_ratio < 6 and 1000 < area < 50000:
                buttons.append(ScreenElement(
                    element_type='button',
                    text='',
                    position=(x, y, x + w, y + h),
                    confidence=0.7
                ))
        
        return buttons
    
    def detect_text_fields(self, image: np.ndarray) -> List[ScreenElement]:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        edges = cv2.Canny(gray, 30, 100)
        
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        text_fields = []
        for contour in contours:
            x, y, w, h = cv2.boundingRect(contour)
            
            aspect_ratio = w / h if h > 0 else 0
            area = w * h
            
            if aspect_ratio > 3 and 500 < area < 100000 and h < 50:
                text_fields.append(ScreenElement(
                    element_type='textbox',
                    text='',
                    position=(x, y, x + w, y + h),
                    confidence=0.6
                ))
        
        return text_fields
    
    def detect_all_elements(self, image: np.ndarray) -> List[ScreenElement]:
        buttons = self.detect_buttons(image)
        text_fields = self.detect_text_fields(image)
        
        return buttons + text_fields

class ScreenNavigator:
    def __init__(self):
        self.element_cache = {}
    
    def find_element_by_text(self, screen_image: np.ndarray, target_text: str, 
                            ocr_results: List[OCRResult]) -> Optional[Tuple[int, int]]:
        target_lower = target_text.lower()
        
        for result in ocr_results:
            if target_lower in result.text.lower():
                x1, y1, x2, y2 = result.position
                center_x = (x1 + x2) // 2
                center_y = (y1 + y2) // 2
                return (center_x, center_y)
        
        return None
    
    def find_clickable_element(self, description: str, screen_image: np.ndarray, 
                               ocr_results: List[OCRResult], 
                               ui_elements: List[ScreenElement]) -> Optional[Tuple[int, int]]:
        position = self.find_element_by_text(screen_image, description, ocr_results)
        
        if position:
            return position
        
        keywords = description.lower().split()
        for result in ocr_results:
            result_words = result.text.lower().split()
            overlap = set(keywords) & set(result_words)
            
            if len(overlap) >= len(keywords) * 0.5:
                x1, y1, x2, y2 = result.position
                return ((x1 + x2) // 2, (y1 + y2) // 2)
        
        if ui_elements:
            return self._get_element_center(ui_elements[0])
        
        return None
    
    def _get_element_center(self, element: ScreenElement) -> Tuple[int, int]:
        x1, y1, x2, y2 = element.position
        return ((x1 + x2) // 2, (y1 + y2) // 2)

class ScreenVision:
    def __init__(self, tesseract_cmd: str = None):
        self.capture = ScreenCapture()
        self.ocr = OCREngine(tesseract_cmd)
        self.ui_detector = UIElementDetector()
        self.navigator = ScreenNavigator()
    
    def analyze_screen(self, region: Optional[Tuple[int, int, int, int]] = None, 
                      language: str = 'eng') -> Dict[str, Any]:
        screen_image = self.capture.capture_screen(region)
        
        ocr_result = self.ocr.extract_text(screen_image, language)
        
        ocr_detailed = self.ocr.extract_text_with_positions(screen_image, language)
        
        ui_elements = self.ui_detector.detect_all_elements(screen_image)
        
        return {
            'full_text': ocr_result.text,
            'text_confidence': ocr_result.confidence,
            'text_elements': ocr_detailed,
            'ui_elements': ui_elements,
            'screenshot': screen_image,
            'timestamp': datetime.now().isoformat()
        }
    
    def find_and_locate(self, description: str, language: str = 'eng') -> Optional[Tuple[int, int]]:
        analysis = self.analyze_screen(language=language)
        
        position = self.navigator.find_clickable_element(
            description,
            analysis['screenshot'],
            analysis['text_elements'],
            analysis['ui_elements']
        )
        
        return position
    
    def read_screen_text(self, region: Optional[Tuple[int, int, int, int]] = None, 
                        language: str = 'eng') -> str:
        screen_image = self.capture.capture_screen(region)
        ocr_result = self.ocr.extract_text(screen_image, language)
        return ocr_result.text
    
    def extract_structured_data(self, pattern: str, language: str = 'eng') -> List[str]:
        text = self.read_screen_text(language=language)
        
        matches = re.findall(pattern, text)
        return matches
    
    def get_screen_diff(self) -> Optional[np.ndarray]:
        if len(self.capture.screenshot_history) < 2:
            return None
        
        current = np.array(self.capture.screenshot_history[-1]['image'])
        previous = np.array(self.capture.screenshot_history[-2]['image'])
        
        diff = cv2.absdiff(current, previous)
        
        return diff

screen_vision = ScreenVision()

def analyze_screen(region: Optional[Tuple[int, int, int, int]] = None, 
                  language: str = 'eng') -> Dict[str, Any]:
    return screen_vision.analyze_screen(region, language)

def find_element(description: str, language: str = 'eng') -> Optional[Tuple[int, int]]:
    return screen_vision.find_and_locate(description, language)

def read_screen(region: Optional[Tuple[int, int, int, int]] = None, 
               language: str = 'eng') -> str:
    return screen_vision.read_screen_text(region, language)

def extract_data(pattern: str, language: str = 'eng') -> List[str]:
    return screen_vision.extract_structured_data(pattern, language)
