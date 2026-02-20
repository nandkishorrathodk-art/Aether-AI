import pyautogui
import base64
import requests
import os
import time
from typing import Optional
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)

class VisionSystem:
    @staticmethod
    def capture_screen(path: str = "screenshot.png") -> str:
        """Capture screen and return base64 string"""
        try:
            timestamp = int(time.time())
            path = f"screenshot_{timestamp}.png"
            
            # Capture
            logger.info("Capturing screen...")
            screenshot = pyautogui.screenshot()
            screenshot.save(path)
            
            # Convert to base64
            with open(path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
            
            # Cleanup
            try:
                os.remove(path)
            except:
                pass
                
            return encoded_string
        except Exception as e:
            logger.error(f"Screen Capture Failed: {e}")
            return ""

    @staticmethod
    def analyze_screen(prompt: str = "Describe this screen in detail.", max_retries: int = 3) -> str:
        """Analyze screen using OpenRouter (Gemini Flash) with retry logic"""
        if not settings.openrouter_api_key:
            return "Error: OpenRouter API Key is missing in .env"

        base64_image = VisionSystem.capture_screen()
        if not base64_image:
            return "Error: Failed to capture screen."
        
        headers = {
            "Authorization": f"Bearer {settings.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://aether-ai.com",
            "X-Title": "Aether AI"
        }
        
        payload = {
            "model": "google/gemini-2.0-flash-lite-001",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64_image}"}}
                    ]
                }
            ],
            "max_tokens": 1000,
            "temperature": 0.3
        }
        
        last_error = None
        for attempt in range(max_retries):
            try:
                logger.info(f"Vision Request Attempt {attempt + 1}/{max_retries} to OpenRouter ({payload['model']})...")
                
                response = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions", 
                    headers=headers, 
                    json=payload, 
                    timeout=120
                )
                
                if response.status_code == 200:
                    result = response.json()
                    content = result['choices'][0]['message']['content']
                    logger.info(f"✅ Vision Analysis Received (attempt {attempt + 1})")
                    return content
                else:
                    last_error = f"Vision API Error: {response.status_code} - {response.text}"
                    logger.warning(f"Vision API returned {response.status_code}, retrying...")
                    time.sleep(2)
                    
            except requests.exceptions.Timeout:
                last_error = "Vision Request Timed Out (120s)"
                logger.warning(f"Attempt {attempt + 1} timed out, retrying...")
                time.sleep(2)
                
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection Error: {str(e)}"
                logger.warning(f"Connection error on attempt {attempt + 1}, retrying...")
                time.sleep(3)
                
            except Exception as e:
                last_error = f"Vision Request Failed: {str(e)}"
                logger.warning(f"Error on attempt {attempt + 1}: {e}")
                time.sleep(2)
        
        logger.error(f"❌ All {max_retries} vision attempts failed. Last error: {last_error}")
        return f"Screen analysis unavailable after {max_retries} attempts. Using fallback description: The screen shows a desktop interface with various windows and applications."

vision_system = VisionSystem()
