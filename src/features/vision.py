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
    def analyze_screen(prompt: str = "Describe this screen in detail.") -> str:
        """Analyze screen using OpenRouter (Gemini Flash)"""
        if not settings.openrouter_api_key:
            return "Error: OpenRouter API Key is missing in .env"

        base64_image = VisionSystem.capture_screen()
        if not base64_image:
            return "Error: Failed to capture screen."
        
        headers = {
            "Authorization": f"Bearer {settings.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://aether-ai.com", # Required by OpenRouter
            "X-Title": "Aether AI"
        }
        
        payload = {
            "model": "google/gemini-2.0-flash-exp:free", # Using Free/Fast model
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{base64_image}"}}
                    ]
                }
            ]
        }
        
        try:
            logger.info(f"Sending Vision Request to OpenRouter ({payload['model']})...")
            response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=15)
            
            if response.status_code == 200:
                result = response.json()
                content = result['choices'][0]['message']['content']
                logger.info("Vision Analysis Received.")
                return content
            else:
                logger.error(f"Vision API Error: {response.text}")
                return f"Vision Error: {response.status_code} - {response.text}"
        except Exception as e:
            logger.error(f"Vision Request Failed: {e}")
            return f"Vision Request Failed: {str(e)}"

vision_system = VisionSystem()
