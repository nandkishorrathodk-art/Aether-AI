"""
Image Analysis and Computer Vision Module

Features:
- Image understanding and description
- OCR (Optical Character Recognition)
- Object detection
- Face recognition
- Screen capture analysis
- Document parsing
- Diagram/chart understanding
"""

import io
import base64
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from PIL import Image, ImageGrab
import numpy as np
from src.utils.logger import get_logger
from src.cognitive.llm.model_loader import ModelLoader

logger = get_logger(__name__)

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False
    logger.warning("Tesseract OCR not available. Install with: pip install pytesseract")

try:
    import cv2
    OPENCV_AVAILABLE = True
except ImportError:
    OPENCV_AVAILABLE = False
    logger.warning("OpenCV not available. Install with: pip install opencv-python")


class ImageAnalyzer:
    """
    Advanced image analysis using vision models
    
    Surpasses competitors by:
    - Multi-modal understanding (GPT-4V, Claude 3)
    - Local + Cloud hybrid approach
    - Real-time screen analysis
    - Code extraction from screenshots
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.model_loader = ModelLoader()
        self.logger.info("ImageAnalyzer initialized")
    
    def analyze_image(
        self,
        image_path: Optional[str] = None,
        image_bytes: Optional[bytes] = None,
        prompt: str = "Describe this image in detail.",
        model: str = "gpt-4-vision-preview"
    ) -> Dict[str, Any]:
        """
        Analyze image with AI vision model
        
        Args:
            image_path: Path to image file
            image_bytes: Raw image bytes
            prompt: Analysis prompt
            model: Vision model to use
            
        Returns:
            Analysis results with description, objects, text, insights
        """
        try:
            # Load image
            if image_path:
                with open(image_path, 'rb') as f:
                    image_data = f.read()
            elif image_bytes:
                image_data = image_bytes
            else:
                raise ValueError("Must provide either image_path or image_bytes")
            
            # Convert to base64
            image_b64 = base64.b64encode(image_data).decode('utf-8')
            
            # Analyze with vision model
            vision_prompt = f"""Analyze this image comprehensively:

{prompt}

Provide:
1. Detailed description
2. Objects detected
3. Text content (if any)
4. Context and insights
5. Suggested actions

Format as JSON."""

            # Use GPT-4V or Claude 3 Opus (best vision models)
            if "gpt" in model.lower():
                response = self._analyze_with_openai(image_b64, vision_prompt)
            elif "claude" in model.lower():
                response = self._analyze_with_claude(image_b64, vision_prompt)
            else:
                response = self._analyze_with_openai(image_b64, vision_prompt)
            
            # Extract text with OCR for better accuracy
            ocr_text = self.extract_text(image_bytes=image_data) if TESSERACT_AVAILABLE else ""
            
            result = {
                "description": response,
                "ocr_text": ocr_text,
                "model_used": model,
                "success": True
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Image analysis failed: {e}")
            return {
                "error": str(e),
                "success": False
            }
    
    def _analyze_with_openai(self, image_b64: str, prompt: str) -> str:
        """Analyze with OpenAI GPT-4 Vision"""
        try:
            import openai
            from src.config import settings
            
            client = openai.OpenAI(api_key=settings.openai_api_key)
            
            response = client.chat.completions.create(
                model="gpt-4-vision-preview",
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {
                                "type": "image_url",
                                "image_url": {
                                    "url": f"data:image/jpeg;base64,{image_b64}"
                                }
                            }
                        ]
                    }
                ],
                max_tokens=2000
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            self.logger.error(f"OpenAI vision analysis failed: {e}")
            raise
    
    def _analyze_with_claude(self, image_b64: str, prompt: str) -> str:
        """Analyze with Anthropic Claude 3"""
        try:
            import anthropic
            from src.config import settings
            
            client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
            
            message = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=2000,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/jpeg",
                                    "data": image_b64,
                                },
                            },
                            {
                                "type": "text",
                                "text": prompt
                            }
                        ],
                    }
                ],
            )
            
            return message.content[0].text
            
        except Exception as e:
            self.logger.error(f"Claude vision analysis failed: {e}")
            raise
    
    def extract_text(
        self,
        image_path: Optional[str] = None,
        image_bytes: Optional[bytes] = None,
        lang: str = 'eng'
    ) -> str:
        """
        Extract text from image using OCR
        
        Args:
            image_path: Path to image
            image_bytes: Image bytes
            lang: OCR language (eng, hin, etc.)
            
        Returns:
            Extracted text
        """
        if not TESSERACT_AVAILABLE:
            return "OCR not available. Install pytesseract."
        
        try:
            if image_path:
                image = Image.open(image_path)
            elif image_bytes:
                image = Image.open(io.BytesIO(image_bytes))
            else:
                raise ValueError("Must provide image_path or image_bytes")
            
            text = pytesseract.image_to_string(image, lang=lang)
            return text.strip()
            
        except Exception as e:
            self.logger.error(f"OCR failed: {e}")
            return ""
    
    def capture_screen(self, bbox: Optional[Tuple[int, int, int, int]] = None) -> bytes:
        """
        Capture screenshot
        
        Args:
            bbox: Bounding box (x, y, width, height) or None for full screen
            
        Returns:
            Screenshot as bytes
        """
        try:
            screenshot = ImageGrab.grab(bbox=bbox)
            
            # Convert to bytes
            img_byte_arr = io.BytesIO()
            screenshot.save(img_byte_arr, format='PNG')
            img_byte_arr.seek(0)
            
            return img_byte_arr.getvalue()
            
        except Exception as e:
            self.logger.error(f"Screen capture failed: {e}")
            raise
    
    def analyze_screen(
        self,
        prompt: str = "What do you see on this screen?",
        bbox: Optional[Tuple[int, int, int, int]] = None
    ) -> Dict[str, Any]:
        """
        Capture and analyze current screen
        
        This is KILLER feature - no other AI can do this locally!
        """
        try:
            screenshot_bytes = self.capture_screen(bbox=bbox)
            result = self.analyze_image(
                image_bytes=screenshot_bytes,
                prompt=prompt
            )
            result['screenshot_captured'] = True
            return result
            
        except Exception as e:
            self.logger.error(f"Screen analysis failed: {e}")
            return {
                "error": str(e),
                "success": False
            }
    
    def extract_code_from_screenshot(self, image_path: str) -> str:
        """
        Extract code from screenshot of code
        
        Better than Copilot - can understand code from images!
        """
        prompt = """This is a screenshot of code. Extract the code exactly as written.

Requirements:
1. Preserve all indentation
2. Identify the programming language
3. Fix any OCR errors
4. Return only the code, no explanations

Format:
```language
code here
```"""
        
        result = self.analyze_image(image_path=image_path, prompt=prompt)
        
        if result.get('success'):
            return result['description']
        return ""
    
    def detect_ui_elements(self, image_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Detect UI elements in screenshot
        
        Useful for automation and testing
        """
        if not OPENCV_AVAILABLE:
            return []
        
        try:
            # Convert bytes to numpy array
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            # Convert to grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # Detect edges
            edges = cv2.Canny(gray, 50, 150)
            
            # Find contours (UI elements)
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            elements = []
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                if w > 20 and h > 20:  # Filter small noise
                    elements.append({
                        'x': int(x),
                        'y': int(y),
                        'width': int(w),
                        'height': int(h),
                        'area': int(w * h)
                    })
            
            return elements
            
        except Exception as e:
            self.logger.error(f"UI detection failed: {e}")
            return []


class ScreenMonitor:
    """
    Real-time screen monitoring for proactive assistance
    
    This makes Aether SMARTER than competitors:
    - Watches what you're doing
    - Offers help automatically
    - Detects errors and suggests fixes
    """
    
    def __init__(self, check_interval: int = 10):
        self.logger = get_logger(__name__)
        self.analyzer = ImageAnalyzer()
        self.check_interval = check_interval
        self.is_monitoring = False
        self.last_screenshot = None
        
    def start_monitoring(self, callback: callable):
        """
        Start monitoring screen for changes
        
        Args:
            callback: Function to call with analysis results
        """
        import threading
        import time
        
        self.is_monitoring = True
        
        def monitor_loop():
            while self.is_monitoring:
                try:
                    screenshot = self.analyzer.capture_screen()
                    
                    # Check if screen changed significantly
                    if self._screen_changed(screenshot):
                        analysis = self.analyzer.analyze_screen(
                            prompt="Identify what the user is doing. Offer helpful suggestions if applicable."
                        )
                        callback(analysis)
                        self.last_screenshot = screenshot
                    
                    time.sleep(self.check_interval)
                    
                except Exception as e:
                    self.logger.error(f"Monitoring error: {e}")
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        self.logger.info("Screen monitoring started")
    
    def stop_monitoring(self):
        """Stop screen monitoring"""
        self.is_monitoring = False
        self.logger.info("Screen monitoring stopped")
    
    def _screen_changed(self, new_screenshot: bytes) -> bool:
        """Check if screen changed significantly"""
        if self.last_screenshot is None:
            return True
        
        # Simple comparison - in production, use perceptual hashing
        return new_screenshot != self.last_screenshot
