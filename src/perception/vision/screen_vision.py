"""
Screen Vision & OCR - See and understand everything on screen
Real-time screen analysis with element detection and auto-navigation
"""
import cv2
import numpy as np
from PIL import ImageGrab, Image
import pytesseract
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import re

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

class ScreenCapture:
    def __init__(self):
        self.last_screenshot = None
        self.screenshot_history = []
    
    def capture_screen(self, region: Optional[Tuple[int, int, int, int]] = None) -> np.ndarray:
        if region:
            screenshot = ImageGrab.grab(bbox=region)
        else:
            screenshot = ImageGrab.grab()
        
        self.last_screenshot = screenshot
        self.screenshot_history.append({
            'image': screenshot,
            'timestamp': datetime.now()
        })
        
        if len(self.screenshot_history) > 10:
            self.screenshot_history.pop(0)
        
        return np.array(screenshot)
    
    def capture_window(self, window_title: str) -> Optional[np.ndarray]:
        try:
            import pygetwindow as gw
            windows = gw.getWindowsWithTitle(window_title)
            
            if windows:
                window = windows[0]
                bbox = (window.left, window.top, window.right, window.bottom)
                return self.capture_screen(region=bbox)
        except:
            pass
        
        return None

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
