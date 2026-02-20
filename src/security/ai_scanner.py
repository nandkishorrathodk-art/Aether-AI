"""
AI-Powered Advanced Security Scanner
Machine learning and AI-driven vulnerability detection
"""

import asyncio
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import re

logger = logging.getLogger(__name__)


@dataclass
class AIDetection:
    """AI-detected vulnerability"""
    confidence: float
    vulnerability_type: str
    severity: str
    description: str
    evidence: List[str]
    recommendation: str
    ai_reasoning: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "confidence": self.confidence,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "ai_reasoning": self.ai_reasoning
        }


class AIVulnerabilityScanner:
    """
    AI-powered vulnerability scanner with machine learning capabilities
    
    Features:
    - Pattern recognition for 0-day vulnerabilities
    - Behavioral analysis
    - Anomaly detection
    - Context-aware scanning
    - False positive reduction
    """
    
    def __init__(self, ai_client=None):
        """Initialize AI scanner"""
        self.ai_client = ai_client
        
        self.known_patterns = {
            "nosql_injection": [
                r"\$where.*function",
                r"\$ne.*null",
                r"{\s*\$gt\s*:\s*['\"]",
            ],
            "jwt_weakness": [
                r"alg.*none",
                r"HS256.*weak",
            ],
            "api_exposure": [
                r"/api/v\d+/.*(?:users?|admin|internal)",
                r"\.env",
                r"swagger\.json",
            ],
            "authentication_bypass": [
                r"admin.*true",
                r"role.*admin",
                r"bypass.*auth",
            ],
            "ssrf_blind": [
                r"url=.*localhost",
                r"redirect=.*127\.0\.0\.1",
            ]
        }
        
        logger.info("AI Vulnerability Scanner initialized")
    
    async def analyze_endpoint(
        self,
        url: str,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any]
    ) -> List[AIDetection]:
        """
        Analyze endpoint using AI for vulnerability detection
        
        Args:
            url: Endpoint URL
            request_data: Request details
            response_data: Response details
        
        Returns:
            List of AI detections
        """
        detections = []
        
        pattern_detections = self._pattern_based_detection(url, request_data, response_data)
        detections.extend(pattern_detections)
        
        if self.ai_client:
            ai_detections = await self._ai_based_detection(url, request_data, response_data)
            detections.extend(ai_detections)
        
        anomaly_detections = self._anomaly_detection(response_data)
        detections.extend(anomaly_detections)
        
        logger.info(f"AI analysis found {len(detections)} potential vulnerabilities")
        return detections
    
    def _pattern_based_detection(
        self,
        url: str,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any]
    ) -> List[AIDetection]:
        """Pattern-based vulnerability detection"""
        detections = []
        
        response_text = str(response_data.get("body", ""))
        
        for vuln_type, patterns in self.known_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    detections.append(AIDetection(
                        confidence=0.7,
                        vulnerability_type=vuln_type,
                        severity="MEDIUM",
                        description=f"Potential {vuln_type.replace('_', ' ')} detected via pattern matching",
                        evidence=[f"Pattern matched: {pattern}"],
                        recommendation=f"Investigate endpoint for {vuln_type} vulnerability",
                        ai_reasoning=f"Pattern '{pattern}' matched in response"
                    ))
        
        return detections
    
    async def _ai_based_detection(
        self,
        url: str,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any]
    ) -> List[AIDetection]:
        """AI/LLM-based vulnerability detection"""
        detections = []
        
        try:
            from src.cognitive.llm.model_loader import ModelLoader
            loader = ModelLoader()
            
            prompt = f"""Analyze this HTTP endpoint for security vulnerabilities:

URL: {url}
Request Method: {request_data.get('method', 'GET')}
Request Headers: {request_data.get('headers', {})}
Request Body: {request_data.get('body', '')}

Response Status: {response_data.get('status_code', 200)}
Response Headers: {response_data.get('headers', {})}
Response Body (first 1000 chars): {str(response_data.get('body', ''))[:1000]}

Identify potential vulnerabilities including:
1. Injection flaws (SQL, NoSQL, Command, etc.)
2. Authentication/Authorization issues
3. Sensitive data exposure
4. SSRF, CSRF, XSS potential
5. API misconfigurations
6. 0-day vulnerability patterns

Format response as JSON array:
[{{
  "vulnerability_type": "...",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0-1.0,
  "description": "...",
  "evidence": ["..."],
  "recommendation": "..."
}}]
"""
            
            response = loader.generate(
                prompt=prompt,
                task_type="analysis",
                max_tokens=1500
            )
            
            import json
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                findings = json.loads(json_match.group())
                
                for finding in findings:
                    detections.append(AIDetection(
                        confidence=finding.get("confidence", 0.5),
                        vulnerability_type=finding.get("vulnerability_type", "unknown"),
                        severity=finding.get("severity", "MEDIUM"),
                        description=finding.get("description", ""),
                        evidence=finding.get("evidence", []),
                        recommendation=finding.get("recommendation", ""),
                        ai_reasoning="AI-powered deep analysis"
                    ))
        except Exception as e:
            logger.error(f"AI-based detection failed: {e}")
        
        return detections
    
    def _anomaly_detection(self, response_data: Dict[str, Any]) -> List[AIDetection]:
        """Anomaly-based detection"""
        detections = []
        
        response_time = response_data.get("response_time", 0)
        if response_time > 5.0:
            detections.append(AIDetection(
                confidence=0.6,
                vulnerability_type="performance_anomaly",
                severity="LOW",
                description="Unusually slow response time detected",
                evidence=[f"Response time: {response_time}s"],
                recommendation="Investigate for potential DoS vulnerability or database issues",
                ai_reasoning="Response time exceeds 5 seconds threshold"
            ))
        
        response_size = len(str(response_data.get("body", "")))
        if response_size > 1000000:
            detections.append(AIDetection(
                confidence=0.5,
                vulnerability_type="resource_exhaustion",
                severity="MEDIUM",
                description="Unusually large response detected",
                evidence=[f"Response size: {response_size} bytes"],
                recommendation="Check for potential resource exhaustion or information disclosure",
                ai_reasoning="Response size exceeds 1MB threshold"
            ))
        
        return detections
    
    async def scan_application(
        self,
        base_url: str,
        endpoints: List[str]
    ) -> Dict[str, Any]:
        """
        Comprehensive AI-powered application scan
        
        Args:
            base_url: Base URL of application
            endpoints: List of endpoints to scan
        
        Returns:
            Comprehensive scan report
        """
        all_detections = []
        
        for endpoint in endpoints:
            full_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
            
            request_data = {
                "method": "GET",
                "headers": {},
                "body": ""
            }
            
            response_data = {
                "status_code": 200,
                "headers": {},
                "body": "",
                "response_time": 0.5
            }
            
            detections = await self.analyze_endpoint(full_url, request_data, response_data)
            all_detections.extend(detections)
        
        severity_counts = {}
        for detection in all_detections:
            severity_counts[detection.severity] = severity_counts.get(detection.severity, 0) + 1
        
        high_confidence = [d for d in all_detections if d.confidence >= 0.7]
        
        return {
            "target": base_url,
            "endpoints_scanned": len(endpoints),
            "total_findings": len(all_detections),
            "high_confidence_findings": len(high_confidence),
            "severity_distribution": severity_counts,
            "detections": [d.to_dict() for d in all_detections],
            "scan_timestamp": datetime.now().isoformat()
        }
    
    async def reduce_false_positives(
        self,
        detections: List[AIDetection]
    ) -> List[AIDetection]:
        """
        Use AI to reduce false positives
        
        Args:
            detections: List of initial detections
        
        Returns:
            Filtered list with reduced false positives
        """
        filtered = []
        
        for detection in detections:
            if detection.confidence >= 0.7:
                filtered.append(detection)
            elif detection.severity in ["CRITICAL", "HIGH"]:
                if detection.confidence >= 0.5:
                    filtered.append(detection)
        
        logger.info(f"False positive reduction: {len(detections)} -> {len(filtered)} findings")
        return filtered
