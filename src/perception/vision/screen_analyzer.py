"""
Screen Understanding - OCR, GUI detection, and visual AI analysis.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from PIL import Image
import numpy as np
import re


@dataclass
class OCRResult:
    """OCR text extraction result."""
    text: str
    confidence: float
    bounding_boxes: List[Dict[str, Any]]
    language: str


@dataclass
class GUIElement:
    """GUI element detection result."""
    element_type: str
    text: Optional[str]
    bounds: Tuple[int, int, int, int]
    confidence: float
    clickable: bool


class ScreenAnalyzer:
    """
    Screen understanding with OCR, GUI detection, and visual AI.
    
    Analyzes screenshots, extracts text, detects UI elements.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize screen analyzer.
        
        Args:
            llm_provider: LLM for image understanding
        """
        self.llm_provider = llm_provider
        self.ocr_available = self._check_ocr_availability()
    
    def _check_ocr_availability(self) -> bool:
        """Check if OCR libraries are available."""
        try:
            import pytesseract
            return True
        except ImportError:
            return False
    
    def extract_text(self, image_path: str, language: str = 'eng') -> OCRResult:
        """
        Extract text from image using OCR.
        
        Args:
            image_path: Path to image file
            language: OCR language (default: English)
            
        Returns:
            OCRResult with extracted text
        """
        if not self.ocr_available:
            return self._fallback_text_extraction(image_path)
        
        try:
            import pytesseract
            from PIL import Image
            
            img = Image.open(image_path)
            
            text = pytesseract.image_to_string(img, lang=language)
            
            data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT, lang=language)
            
            bounding_boxes = []
            n_boxes = len(data['text'])
            
            for i in range(n_boxes):
                if int(data['conf'][i]) > 0:
                    bounding_boxes.append({
                        'text': data['text'][i],
                        'x': data['left'][i],
                        'y': data['top'][i],
                        'width': data['width'][i],
                        'height': data['height'][i],
                        'confidence': float(data['conf'][i]) / 100
                    })
            
            avg_confidence = np.mean([box['confidence'] for box in bounding_boxes]) if bounding_boxes else 0.0
            
            return OCRResult(
                text=text.strip(),
                confidence=float(avg_confidence),
                bounding_boxes=bounding_boxes,
                language=language
            )
            
        except Exception as e:
            print(f"OCR error: {e}")
            return self._fallback_text_extraction(image_path)
    
    def _fallback_text_extraction(self, image_path: str) -> OCRResult:
        """Fallback when OCR not available."""
        return OCRResult(
            text="OCR not available. Install: pip install pytesseract",
            confidence=0.0,
            bounding_boxes=[],
            language='eng'
        )
    
    def detect_gui_elements(self, image_path: str) -> List[GUIElement]:
        """
        Detect GUI elements (buttons, textboxes, etc).
        
        Args:
            image_path: Path to screenshot
            
        Returns:
            List of detected GUIElement objects
        """
        try:
            import cv2
            
            img = cv2.imread(image_path)
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            edges = cv2.Canny(gray, 50, 150)
            
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            elements = []
            
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                
                if w > 50 and h > 20 and w < 500 and h < 200:
                    aspect_ratio = w / h
                    
                    if 2 < aspect_ratio < 8 and 30 < h < 60:
                        element_type = "button"
                        clickable = True
                    elif w > 150 and 20 < h < 40:
                        element_type = "textbox"
                        clickable = True
                    else:
                        element_type = "container"
                        clickable = False
                    
                    ocr_result = self.extract_text(image_path)
                    element_text = self._find_text_in_region(ocr_result, x, y, w, h)
                    
                    elements.append(GUIElement(
                        element_type=element_type,
                        text=element_text,
                        bounds=(x, y, w, h),
                        confidence=0.7,
                        clickable=clickable
                    ))
            
            return elements[:50]
            
        except ImportError:
            return [GUIElement(
                element_type="unknown",
                text="GUI detection requires OpenCV",
                bounds=(0, 0, 0, 0),
                confidence=0.0,
                clickable=False
            )]
        except Exception as e:
            print(f"GUI detection error: {e}")
            return []
    
    def _find_text_in_region(self, ocr_result: OCRResult, x: int, y: int, w: int, h: int) -> Optional[str]:
        """Find text within bounding box region."""
        texts = []
        
        for box in ocr_result.bounding_boxes:
            box_x = box['x']
            box_y = box['y']
            
            if x <= box_x <= x + w and y <= box_y <= y + h:
                texts.append(box['text'])
        
        return ' '.join(texts).strip() if texts else None
    
    def analyze_screenshot(self, image_path: str) -> Dict[str, Any]:
        """
        Comprehensive screenshot analysis.
        
        Args:
            image_path: Path to screenshot
            
        Returns:
            Complete analysis with text, elements, and insights
        """
        ocr_result = self.extract_text(image_path)
        
        gui_elements = self.detect_gui_elements(image_path)
        
        insights = self._generate_insights(ocr_result, gui_elements)
        
        return {
            'text_content': ocr_result.text,
            'text_confidence': ocr_result.confidence,
            'gui_elements': [
                {
                    'type': elem.element_type,
                    'text': elem.text,
                    'bounds': elem.bounds,
                    'clickable': elem.clickable
                }
                for elem in gui_elements
            ],
            'insights': insights,
            'total_elements': len(gui_elements),
            'clickable_elements': sum(1 for e in gui_elements if e.clickable)
        }
    
    def _generate_insights(self, ocr: OCRResult, elements: List[GUIElement]) -> List[str]:
        """Generate insights from screen analysis."""
        insights = []
        
        if ocr.confidence > 0.8:
            insights.append("High-quality text extraction achieved")
        
        button_count = sum(1 for e in elements if e.element_type == "button")
        if button_count > 5:
            insights.append(f"Screen has {button_count} buttons - interactive interface")
        
        if any('error' in ocr.text.lower() or 'warning' in ocr.text.lower()):
            insights.append("Error or warning message detected on screen")
        
        if len(ocr.text) < 50:
            insights.append("Minimal text content - may be graphical interface")
        
        return insights
    
    def find_element_by_text(self, image_path: str, target_text: str) -> Optional[Tuple[int, int]]:
        """
        Find GUI element by text and return click coordinates.
        
        Args:
            image_path: Path to screenshot
            target_text: Text to search for
            
        Returns:
            (x, y) coordinates of element center, or None
        """
        ocr_result = self.extract_text(image_path)
        
        target_lower = target_text.lower()
        
        for box in ocr_result.bounding_boxes:
            if target_lower in box['text'].lower():
                x = box['x'] + box['width'] // 2
                y = box['y'] + box['height'] // 2
                return (x, y)
        
        return None
    
    def extract_form_fields(self, image_path: str) -> List[Dict[str, Any]]:
        """Extract form fields from screenshot."""
        ocr_result = self.extract_text(image_path)
        gui_elements = self.detect_gui_elements(image_path)
        
        form_fields = []
        
        textboxes = [e for e in gui_elements if e.element_type == "textbox"]
        
        for textbox in textboxes:
            x, y, w, h = textbox.bounds
            
            label = self._find_text_in_region(ocr_result, x - 150, y - 30, 150, 60)
            
            form_fields.append({
                'type': 'input',
                'label': label or 'Unlabeled field',
                'bounds': textbox.bounds,
                'current_value': textbox.text
            })
        
        return form_fields
    
    def compare_screenshots(self, image1_path: str, image2_path: str) -> Dict[str, Any]:
        """Compare two screenshots for differences."""
        try:
            import cv2
            
            img1 = cv2.imread(image1_path)
            img2 = cv2.imread(image2_path)
            
            if img1.shape != img2.shape:
                return {
                    'different': True,
                    'reason': 'Images have different dimensions',
                    'similarity': 0.0
                }
            
            difference = cv2.absdiff(img1, img2)
            
            gray_diff = cv2.cvtColor(difference, cv2.COLOR_BGR2GRAY)
            
            diff_percentage = (np.count_nonzero(gray_diff) / gray_diff.size) * 100
            
            similarity = 100 - diff_percentage
            
            return {
                'different': diff_percentage > 5,
                'similarity': round(similarity, 2),
                'diff_percentage': round(diff_percentage, 2),
                'changed_regions': int(diff_percentage * 10)
            }
            
        except Exception as e:
            return {
                'different': False,
                'error': str(e)
            }
