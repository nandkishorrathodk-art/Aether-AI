"""
Vision System - AI Eyes

Reads screen, understands Burp Suite, detects bugs visually.
"""

import asyncio
from typing import Dict, List, Optional, Any
from PIL import Image
import pytesseract
import io

from src.cognitive.llm.inference import LLMInference
from src.utils.logger import get_logger

logger = get_logger(__name__)


class VisionSystem:
    """
    AI vision system that sees and understands what's on screen.
    
    Can read Burp Suite intercept, identify bugs, understand UI.
    """
    
    def __init__(self):
        self.llm = LLMInference()
        logger.info("👁️ Vision System initialized")
    
    async def analyze_screen(self, screenshot_path: str) -> Dict[str, Any]:
        """
        Analyze entire screen
        
        Args:
            screenshot_path: Path to screenshot
            
        Returns:
            Analysis including detected apps, text, potential bugs
        """
        try:
            text = self._extract_text(screenshot_path)
            
            apps_detected = self._detect_applications_in_text(text)
            
            analysis_prompt = f"""Analyze this screen content:

TEXT EXTRACTED FROM SCREEN:
{text[:2000]}

Identify:
1. What application is open?
2. What is the user doing?
3. Are there any security issues visible?
4. Any error messages or warnings?
5. Suggested next actions

Respond in JSON format:
{{
  "application": "...",
  "activity": "...",
  "security_issues": [],
  "errors": [],
  "next_actions": []
}}
"""
            
            response = await self.llm.get_completion(analysis_prompt)
            
            import json
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group(0))
            else:
                analysis = {"application": "unknown"}
            
            return {
                "success": True,
                "detected_apps": apps_detected,
                "text_length": len(text),
                "analysis": analysis
            }
            
        except Exception as e:
            logger.error(f"Screen analysis failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def detect_application(self, screenshot_path: str, app_name: str) -> bool:
        """
        Detect if specific application is running
        
        Args:
            screenshot_path: Path to screenshot
            app_name: Application to detect (e.g., "Burp Suite")
            
        Returns:
            True if detected
        """
        try:
            text = self._extract_text(screenshot_path)
            
            app_keywords = {
                "Burp Suite": ["burp", "intruder", "repeater", "proxy", "target", "scanner"],
                "Chrome": ["google chrome", "address bar", "new tab"],
                "Firefox": ["mozilla firefox", "address bar"],
                "VS Code": ["visual studio code", "explorer", "terminal"]
            }
            
            keywords = app_keywords.get(app_name, [app_name.lower()])
            
            text_lower = text.lower()
            matches = sum(1 for kw in keywords if kw in text_lower)
            
            is_detected = matches >= 2
            
            logger.info(f"Application '{app_name}' detected: {is_detected} ({matches} keyword matches)")
            
            return is_detected
            
        except Exception as e:
            logger.error(f"App detection failed: {e}")
            return False
    
    async def analyze_burp_findings(self, screenshot_path: str) -> Dict[str, Any]:
        """
        Analyze Burp Suite screen for security findings
        
        Args:
            screenshot_path: Path to Burp Suite screenshot
            
        Returns:
            Detected vulnerabilities
        """
        try:
            text = self._extract_text(screenshot_path)
            
            vuln_keywords = {
                "SQL Injection": ["sql", "injection", "query", "database", "syntax error"],
                "XSS": ["xss", "cross-site scripting", "script", "alert"],
                "IDOR": ["insecure direct object", "idor", "authorization"],
                "SSRF": ["ssrf", "server-side request"],
                "XXE": ["xxe", "xml external entity"],
                "RCE": ["remote code execution", "rce", "command injection"]
            }
            
            detected_bugs = []
            text_lower = text.lower()
            
            for vuln_type, keywords in vuln_keywords.items():
                if any(kw in text_lower for kw in keywords):
                    detected_bugs.append({
                        "type": vuln_type,
                        "confidence": "medium",
                        "source": "keyword_match"
                    })
            
            analysis_prompt = f"""You are analyzing Burp Suite screen content. Identify vulnerabilities:

BURP SUITE TEXT:
{text[:3000]}

Look for:
- HTTP requests/responses with security issues
- Error messages indicating vulnerabilities
- Suspicious parameters
- Authentication/authorization issues

List all potential vulnerabilities found.

Format:
{{
  "bugs_found": [
    {{
      "type": "SQL Injection",
      "location": "/api/user?id=1",
      "evidence": "SQL syntax error",
      "severity": "high",
      "confidence": 0.8
    }}
  ]
}}
"""
            
            response = await self.llm.get_completion(analysis_prompt)
            
            import json
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                llm_analysis = json.loads(json_match.group(0))
                llm_bugs = llm_analysis.get("bugs_found", [])
                detected_bugs.extend(llm_bugs)
            
            logger.info(f"Burp analysis complete: {len(detected_bugs)} potential bugs found")
            
            return {
                "success": True,
                "bugs_found": detected_bugs,
                "total_count": len(detected_bugs)
            }
            
        except Exception as e:
            logger.error(f"Burp findings analysis failed: {e}")
            return {"success": False, "error": str(e), "bugs_found": []}
    
    async def read_intercept_request(self, screenshot_path: str) -> Optional[Dict]:
        """
        Read HTTP request from Burp Intercept tab
        
        Args:
            screenshot_path: Screenshot of Burp Intercept
            
        Returns:
            Parsed HTTP request
        """
        try:
            text = self._extract_text(screenshot_path)
            
            http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
            
            lines = text.split("\n")
            request_line = None
            for line in lines:
                if any(method in line.upper() for method in http_methods):
                    request_line = line
                    break
            
            if not request_line:
                return None
            
            headers = []
            body = ""
            in_headers = True
            
            for line in lines[lines.index(request_line)+1:]:
                if not line.strip() and in_headers:
                    in_headers = False
                    continue
                
                if in_headers and ":" in line:
                    headers.append(line)
                elif not in_headers:
                    body += line + "\n"
            
            return {
                "request_line": request_line,
                "headers": headers,
                "body": body.strip(),
                "full_text": text
            }
            
        except Exception as e:
            logger.error(f"Failed to read intercept request: {e}")
            return None
    
    def _extract_text(self, image_path: str) -> str:
        """
        Extract text from image using OCR
        
        Args:
            image_path: Path to image file
            
        Returns:
            Extracted text
        """
        try:
            if isinstance(image_path, bytes):
                image = Image.open(io.BytesIO(image_path))
            else:
                image = Image.open(image_path)
            
            text = pytesseract.image_to_string(image)
            
            return text
            
        except Exception as e:
            logger.error(f"OCR text extraction failed: {e}")
            return ""
    
    def _detect_applications_in_text(self, text: str) -> List[str]:
        """Detect applications from extracted text"""
        detected = []
        
        app_indicators = {
            "Burp Suite": ["burp suite", "portswigger", "intruder", "repeater"],
            "Chrome": ["google chrome", "chromium"],
            "Firefox": ["mozilla firefox"],
            "VS Code": ["visual studio code", "vscode"],
            "Terminal": ["cmd.exe", "powershell", "terminal"],
            "Postman": ["postman"]
        }
        
        text_lower = text.lower()
        
        for app, keywords in app_indicators.items():
            if any(kw in text_lower for kw in keywords):
                detected.append(app)
        
        return detected
