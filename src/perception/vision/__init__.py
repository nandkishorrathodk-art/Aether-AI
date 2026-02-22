"""
Vision module for screen understanding and visual AI.

IRONCLAW ENHANCEMENTS:
- Multi-monitor support with MSS (<100ms capture)
- Multi-engine OCR (Tesseract + PaddleOCR + GPT-4V)
- Real YOLO v8 with Intel NPU acceleration
- Professional screenshot annotation
"""

# Original Aether components
from .screen_analyzer import ScreenAnalyzer, OCRResult, GUIElement

# IRONCLAW: Enhanced screen capture
from .screen_vision import (
    ScreenCapture,
    Monitor,
    Screenshot,
    ScreenElement,
    ScreenVision,
    analyze_screen,
    find_element,
    read_screen
)

# IRONCLAW: Multi-engine OCR
from .ocr_engine import (
    MultiEngineOCR,
    TesseractOCR,
    PaddleOCR,
    GPT4VOCR,
    OCREngine,
    OCRResult as EnhancedOCRResult,
    ImagePreprocessor,
    get_ocr_engine
)

# IRONCLAW: Object detection with YOLO v8
from .object_detector import (
    YOLODetector,
    FaceRecognizer,
    SceneUnderstanding,
    DetectedObject,
    detect_objects,
    detect_faces,
    analyze_scene
)

# IRONCLAW: Screenshot annotation
from .annotation import (
    ImageAnnotator,
    Annotation,
    get_annotator
)

__all__ = [
    # Original Aether
    'ScreenAnalyzer', 'OCRResult', 'GUIElement',
    
    # IRONCLAW: Screen capture
    'ScreenCapture', 'Monitor', 'Screenshot', 'ScreenElement', 'ScreenVision',
    'analyze_screen', 'find_element', 'read_screen',
    
    # IRONCLAW: OCR
    'MultiEngineOCR', 'TesseractOCR', 'PaddleOCR', 'GPT4VOCR', 'OCREngine',
    'EnhancedOCRResult', 'ImagePreprocessor', 'get_ocr_engine',
    
    # IRONCLAW: Object detection
    'YOLODetector', 'FaceRecognizer', 'SceneUnderstanding', 'DetectedObject',
    'detect_objects', 'detect_faces', 'analyze_scene',
    
    # IRONCLAW: Annotation
    'ImageAnnotator', 'Annotation', 'get_annotator'
]
