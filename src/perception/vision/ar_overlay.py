"""
Augmented Reality Overlay - AR Annotations on Real World
Real-time AR overlays through webcam with object labeling and translations
"""

import cv2
import numpy as np
from typing import Optional, List, Dict, Tuple, Any
import pytesseract
from datetime import datetime
import math

try:
    from deep_translator import GoogleTranslator
    TRANSLATOR_AVAILABLE = True
except ImportError:
    TRANSLATOR_AVAILABLE = False


class AROverlay:
    """
    Augmented Reality overlay system
    
    Features:
    - Real-time AR annotations
    - Object detection and labeling
    - Text translation overlay
    - Distance/size measurement
    - Navigation arrows
    """
    
    def __init__(self, object_detector=None, screen_vision=None):
        """
        Initialize AR Overlay
        
        Args:
            object_detector: ObjectDetector instance for object recognition
            screen_vision: ScreenVision instance for OCR
        """
        self.object_detector = object_detector
        self.screen_vision = screen_vision
        
        # AR state
        self.ar_enabled = True
        self.show_labels = True
        self.show_bboxes = True
        self.show_measurements = False
        
        # Translation settings
        self.translation_enabled = False
        self.target_language = 'en'
        self.translator = None
        
        if TRANSLATOR_AVAILABLE:
            try:
                self.translator = GoogleTranslator(source='auto', target=self.target_language)
            except:
                self.translator = None
        
        # Reference object for measurements (in pixels)
        self.reference_object = None
        self.reference_size_cm = None
        
        # Navigation
        self.navigation_enabled = False
        self.navigation_target = None
    
    def annotate_reality(self, frame: np.ndarray, detect_objects: bool = True) -> np.ndarray:
        """
        Add AR annotations to video frame
        
        Args:
            frame: Input video frame (BGR)
            detect_objects: Whether to run object detection
            
        Returns:
            Annotated frame with AR overlays
        """
        if not self.ar_enabled:
            return frame
        
        annotated = frame.copy()
        
        # Detect and label objects
        if detect_objects and self.object_detector:
            detections = self.object_detector.detect_objects(frame)
            
            for det in detections:
                bbox = det['bbox']
                label = f"{det['class']} ({det['confidence']:.2f})"
                
                # Draw bounding box
                if self.show_bboxes:
                    cv2.rectangle(
                        annotated,
                        (bbox['x1'], bbox['y1']),
                        (bbox['x2'], bbox['y2']),
                        (0, 255, 0),
                        2
                    )
                
                # Draw label
                if self.show_labels:
                    self._draw_label(annotated, label, (bbox['x1'], bbox['y1'] - 10))
                
                # Draw measurements
                if self.show_measurements and self.reference_object:
                    size_cm = self._estimate_size(bbox)
                    size_label = f"{size_cm:.1f} cm"
                    self._draw_label(annotated, size_label, (bbox['x1'], bbox['y2'] + 20))
        
        # Add navigation arrows
        if self.navigation_enabled and self.navigation_target:
            self._draw_navigation_arrow(annotated, self.navigation_target)
        
        # Add info overlay
        self._draw_info_overlay(annotated)
        
        return annotated
    
    def translate_text_overlay(self, frame: np.ndarray) -> np.ndarray:
        """
        Detect text in frame and overlay translations
        
        Args:
            frame: Input video frame
            
        Returns:
            Frame with translation overlays
        """
        if not self.translation_enabled or not self.screen_vision:
            return frame
        
        annotated = frame.copy()
        
        try:
            # Extract text using OCR
            ocr_result = self.screen_vision.extract_text_ocr(frame)
            data = ocr_result['data']
            
            # Process each detected word
            n_boxes = len(data['text'])
            for i in range(n_boxes):
                if int(data['conf'][i]) > 60:  # Confidence threshold
                    text = data['text'][i].strip()
                    
                    if not text:
                        continue
                    
                    # Get bounding box
                    x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                    
                    # Translate text
                    translated = self._translate_text(text)
                    
                    if translated and translated != text:
                        # Draw semi-transparent overlay
                        overlay = annotated.copy()
                        cv2.rectangle(overlay, (x, y), (x + w, y + h), (0, 255, 255), -1)
                        cv2.addWeighted(overlay, 0.3, annotated, 0.7, 0, annotated)
                        
                        # Draw translated text
                        cv2.putText(
                            annotated,
                            translated,
                            (x, y - 5),
                            cv2.FONT_HERSHEY_SIMPLEX,
                            0.5,
                            (0, 0, 255),
                            2
                        )
        
        except Exception as e:
            print(f"Translation error: {e}")
        
        return annotated
    
    def _translate_text(self, text: str) -> Optional[str]:
        """Translate text using Google Translate"""
        if not self.translator:
            return None
        
        try:
            return self.translator.translate(text)
        except:
            return None
    
    def measure_distance(self, frame: np.ndarray, point1: Tuple[int, int], point2: Tuple[int, int]) -> Dict[str, Any]:
        """
        Measure distance between two points
        
        Args:
            frame: Input frame
            point1: First point (x, y)
            point2: Second point (x, y)
            
        Returns:
            Dict with pixel distance and estimated real-world distance
        """
        # Calculate pixel distance
        pixel_distance = math.sqrt((point2[0] - point1[0])**2 + (point2[1] - point1[1])**2)
        
        # Estimate real-world distance (if reference available)
        real_distance_cm = None
        if self.reference_object and self.reference_size_cm:
            ref_pixel_size = math.sqrt(
                (self.reference_object['x2'] - self.reference_object['x1'])**2 +
                (self.reference_object['y2'] - self.reference_object['y1'])**2
            )
            
            # Calculate scale (cm per pixel)
            scale = self.reference_size_cm / ref_pixel_size
            real_distance_cm = pixel_distance * scale
        
        return {
            'pixel_distance': pixel_distance,
            'real_distance_cm': real_distance_cm,
            'point1': point1,
            'point2': point2
        }
    
    def _estimate_size(self, bbox: Dict[str, int]) -> float:
        """
        Estimate object size in cm using reference object
        
        Args:
            bbox: Object bounding box
            
        Returns:
            Estimated size in cm
        """
        if not self.reference_object or not self.reference_size_cm:
            return 0.0
        
        # Calculate object diagonal
        obj_diagonal = math.sqrt(bbox['width']**2 + bbox['height']**2)
        
        # Calculate reference diagonal
        ref_diagonal = math.sqrt(
            (self.reference_object['x2'] - self.reference_object['x1'])**2 +
            (self.reference_object['y2'] - self.reference_object['y1'])**2
        )
        
        # Calculate scale and estimate size
        scale = self.reference_size_cm / ref_diagonal
        return obj_diagonal * scale
    
    def set_reference_object(self, bbox: Dict[str, int], size_cm: float):
        """
        Set reference object for measurements
        
        Args:
            bbox: Reference object bounding box
            size_cm: Known size in centimeters
        """
        self.reference_object = bbox
        self.reference_size_cm = size_cm
        print(f"Reference set: {size_cm} cm object")
    
    def _draw_label(self, frame: np.ndarray, text: str, position: Tuple[int, int], 
                    bg_color: Tuple[int, int, int] = (0, 255, 0)):
        """Draw label with background"""
        font = cv2.FONT_HERSHEY_SIMPLEX
        font_scale = 0.6
        thickness = 2
        
        # Get text size
        (text_width, text_height), baseline = cv2.getTextSize(text, font, font_scale, thickness)
        
        # Draw background
        cv2.rectangle(
            frame,
            (position[0], position[1] - text_height - 5),
            (position[0] + text_width, position[1] + 5),
            bg_color,
            -1
        )
        
        # Draw text
        cv2.putText(
            frame,
            text,
            position,
            font,
            font_scale,
            (255, 255, 255),
            thickness
        )
    
    def _draw_navigation_arrow(self, frame: np.ndarray, target: Tuple[int, int]):
        """Draw navigation arrow pointing to target"""
        h, w = frame.shape[:2]
        center = (w // 2, h // 2)
        
        # Calculate arrow direction
        dx = target[0] - center[0]
        dy = target[1] - center[1]
        
        # Normalize
        length = math.sqrt(dx**2 + dy**2)
        if length > 0:
            dx /= length
            dy /= length
        
        # Draw arrow
        arrow_length = 100
        arrow_end = (
            int(center[0] + dx * arrow_length),
            int(center[1] + dy * arrow_length)
        )
        
        cv2.arrowedLine(frame, center, arrow_end, (0, 0, 255), 5, tipLength=0.3)
        
        # Draw distance
        distance = f"{length:.0f} px"
        self._draw_label(frame, distance, (center[0] - 30, center[1] - 120), (0, 0, 255))
    
    def _draw_info_overlay(self, frame: np.ndarray):
        """Draw informational overlay"""
        h, w = frame.shape[:2]
        
        # Draw status bar
        overlay = frame.copy()
        cv2.rectangle(overlay, (0, 0), (w, 30), (0, 0, 0), -1)
        cv2.addWeighted(overlay, 0.5, frame, 0.5, 0, frame)
        
        # Status text
        status_parts = []
        
        if self.ar_enabled:
            status_parts.append("AR: ON")
        
        if self.translation_enabled:
            status_parts.append(f"Translation: {self.target_language.upper()}")
        
        if self.show_measurements:
            status_parts.append("Measurements: ON")
        
        if self.navigation_enabled:
            status_parts.append("Navigation: ON")
        
        status = " | ".join(status_parts) if status_parts else "AR Overlay"
        
        cv2.putText(
            frame,
            status,
            (10, 20),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.5,
            (255, 255, 255),
            1
        )
        
        # Draw timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        cv2.putText(
            frame,
            timestamp,
            (w - 100, 20),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.5,
            (255, 255, 255),
            1
        )
    
    def enable_translation(self, enabled: bool = True, target_lang: str = 'en'):
        """
        Enable/disable text translation overlay
        
        Args:
            enabled: Enable translation
            target_lang: Target language code (e.g., 'en', 'es', 'fr')
        """
        self.translation_enabled = enabled
        self.target_language = target_lang
        
        if enabled and TRANSLATOR_AVAILABLE:
            self.translator = GoogleTranslator(source='auto', target=target_lang)
    
    def enable_navigation(self, enabled: bool = True, target: Optional[Tuple[int, int]] = None):
        """
        Enable/disable navigation arrows
        
        Args:
            enabled: Enable navigation
            target: Target position (x, y)
        """
        self.navigation_enabled = enabled
        self.navigation_target = target
    
    def toggle_measurements(self):
        """Toggle measurement display"""
        self.show_measurements = not self.show_measurements
    
    def run_interactive(self, camera_index: int = 0):
        """
        Run interactive AR overlay with webcam
        
        Args:
            camera_index: Webcam index
        """
        cap = cv2.VideoCapture(camera_index)
        
        print("AR Overlay Started")
        print("Controls:")
        print("  'a' - Toggle AR")
        print("  't' - Toggle translation")
        print("  'm' - Toggle measurements")
        print("  'n' - Toggle navigation")
        print("  'r' - Set reference object (click two corners)")
        print("  'q' - Quit")
        
        # For reference object selection
        selecting_reference = False
        ref_points = []
        
        def mouse_callback(event, x, y, flags, param):
            nonlocal ref_points, selecting_reference
            
            if event == cv2.EVENT_LBUTTONDOWN and selecting_reference:
                ref_points.append((x, y))
                
                if len(ref_points) == 2:
                    # Create bbox from two points
                    x1 = min(ref_points[0][0], ref_points[1][0])
                    y1 = min(ref_points[0][1], ref_points[1][1])
                    x2 = max(ref_points[0][0], ref_points[1][0])
                    y2 = max(ref_points[0][1], ref_points[1][1])
                    
                    bbox = {'x1': x1, 'y1': y1, 'x2': x2, 'y2': y2}
                    
                    # Ask for size
                    print("\nEnter object size in cm:")
                    try:
                        size = float(input("> "))
                        self.set_reference_object(bbox, size)
                        print("Reference object set!")
                    except:
                        print("Invalid size")
                    
                    selecting_reference = False
                    ref_points = []
        
        cv2.namedWindow('AR Overlay')
        cv2.setMouseCallback('AR Overlay', mouse_callback)
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Flip for mirror effect
            frame = cv2.flip(frame, 1)
            
            # Apply AR overlay
            annotated = self.annotate_reality(frame)
            
            # Apply translation overlay if enabled
            if self.translation_enabled:
                annotated = self.translate_text_overlay(annotated)
            
            # Draw reference selection
            if selecting_reference:
                for point in ref_points:
                    cv2.circle(annotated, point, 5, (0, 0, 255), -1)
                
                if len(ref_points) == 1:
                    cv2.putText(annotated, "Click second corner", (10, 60),
                              cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
            
            cv2.imshow('AR Overlay', annotated)
            
            key = cv2.waitKey(1) & 0xFF
            if key == ord('q'):
                break
            elif key == ord('a'):
                self.ar_enabled = not self.ar_enabled
                print(f"AR: {'ON' if self.ar_enabled else 'OFF'}")
            elif key == ord('t'):
                self.enable_translation(not self.translation_enabled)
                print(f"Translation: {'ON' if self.translation_enabled else 'OFF'}")
            elif key == ord('m'):
                self.toggle_measurements()
                print(f"Measurements: {'ON' if self.show_measurements else 'OFF'}")
            elif key == ord('n'):
                self.enable_navigation(not self.navigation_enabled, (320, 240))
                print(f"Navigation: {'ON' if self.navigation_enabled else 'OFF'}")
            elif key == ord('r'):
                print("\nClick two corners of reference object")
                selecting_reference = True
                ref_points = []
        
        cap.release()
        cv2.destroyAllWindows()


# Example usage
if __name__ == "__main__":
    # Import required modules
    from object_detector import ObjectDetector
    from screen_vision import ScreenVision
    
    # Initialize components
    detector = ObjectDetector(model_size='n')
    vision = ScreenVision()
    
    # Create AR overlay
    ar = AROverlay(object_detector=detector, screen_vision=vision)
    
    # Enable features
    ar.enable_translation(True, target_lang='es')
    ar.toggle_measurements()
    
    # Run interactive mode
    ar.run_interactive()
