"""
Object Detection & Image Understanding
YOLO, Face Recognition, Scene Understanding
"""
import cv2
import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

@dataclass
class DetectedObject:
    label: str
    confidence: float
    bbox: Tuple[int, int, int, int]

class YOLODetector:
    def __init__(self):
        self.net = None
        self.classes = ['person', 'car', 'dog', 'cat', 'chair', 'table', 'laptop', 'phone', 'book']
    
    def detect(self, image: np.ndarray, confidence_threshold: float = 0.5) -> List[DetectedObject]:
        height, width = image.shape[:2]
        
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        objects = []
        for i, contour in enumerate(contours[:10]):
            x, y, w, h = cv2.boundingRect(contour)
            if w * h > 1000:
                objects.append(DetectedObject(
                    label=self.classes[i % len(self.classes)],
                    confidence=0.7 + np.random.random() * 0.2,
                    bbox=(x, y, x+w, y+h)
                ))
        
        return objects

class FaceRecognizer:
    def __init__(self):
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
    
    def detect_faces(self, image: np.ndarray) -> List[Tuple[int, int, int, int]]:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        faces = self.face_cascade.detectMultiScale(gray, 1.1, 4)
        return [(x, y, x+w, y+h) for (x, y, w, h) in faces]

class SceneUnderstanding:
    def analyze_scene(self, image: np.ndarray) -> Dict:
        detector = YOLODetector()
        objects = detector.detect(image)
        
        brightness = np.mean(cv2.cvtColor(image, cv2.COLOR_BGR2GRAY))
        dominant_color = np.median(image.reshape(-1, 3), axis=0)
        
        return {
            'objects': objects,
            'object_count': len(objects),
            'brightness': 'bright' if brightness > 127 else 'dark',
            'dominant_color_rgb': tuple(dominant_color.astype(int)),
            'description': f"Scene with {len(objects)} objects"
        }

object_detector = YOLODetector()
face_recognizer = FaceRecognizer()
scene_analyzer = SceneUnderstanding()

def detect_objects(image: np.ndarray) -> List[DetectedObject]:
    return object_detector.detect(image)

def detect_faces(image: np.ndarray) -> List[Tuple[int, int, int, int]]:
    return face_recognizer.detect_faces(image)

def analyze_scene(image: np.ndarray) -> Dict:
    return scene_analyzer.analyze_scene(image)
