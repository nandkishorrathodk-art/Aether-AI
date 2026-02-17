"""
Context Analyzer - Simple LLM integration for context insights
"""

import asyncio
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime

from src.cognitive.llm.model_loader import model_loader
from src.cognitive.llm.providers.base import TaskType
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ContextInsight:
    timestamp: str
    active_app: str
    detected_apps: List[str]
    analysis: str
    suggestions: List[str]
    activity_type: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ContextAnalyzer:
    def __init__(self):
        logger.info("ContextAnalyzer initialized")

    async def analyze(
        self,
        detection_result: Dict[str, Any]
    ) -> ContextInsight:
        apps = detection_result.get("target_apps_detected", [])
        active_app = detection_result.get("active_window", {}).get("name", "Unknown") if detection_result.get("active_window") else "Unknown"

        if not apps:
            return ContextInsight(
                timestamp=datetime.now().isoformat(),
                active_app=active_app,
                detected_apps=[],
                analysis="No monitored applications detected",
                suggestions=[],
                activity_type="unknown",
                confidence=0.5
            )

        prompt = f"""Detected apps: {', '.join(apps)}. Active: {active_app}
Provide JSON:
{{"analysis": "brief activity description", "activity_type": "coding|security_testing|browsing|work|unknown", "suggestions": ["tip1", "tip2"], "confidence": 0.8}}"""

        try:
            response = await model_loader.generate(
                prompt=prompt,
                task_type=TaskType.FAST,
                system_prompt="You analyze user activity. Respond with valid JSON only.",
                temperature=0.3,
                max_tokens=200
            )

            import json, re
            match = re.search(r'\{.*\}', response.content, re.DOTALL)
            result = json.loads(match.group(0)) if match else {}

            return ContextInsight(
                timestamp=datetime.now().isoformat(),
                active_app=active_app,
                detected_apps=apps,
                analysis=result.get('analysis', f'Working with {active_app}'),
                suggestions=result.get('suggestions', [])[:3],
                activity_type=result.get('activity_type', 'unknown'),
                confidence=result.get('confidence', 0.6)
            )

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return ContextInsight(
                timestamp=datetime.now().isoformat(),
                active_app=active_app,
                detected_apps=apps,
                analysis=f"Active: {active_app}, Detected: {', '.join(apps)}",
                suggestions=[],
                activity_type='unknown',
                confidence=0.3
            )

    async def analyze_burpsuite(self) -> Dict[str, Any]:
        return {
            'burpsuite_detected': True,
            'suggestions': [
                "Configure browser proxy to 127.0.0.1:8080",
                "Start passive scan on target",
                "Check for common vulnerabilities (SQLi, XSS, IDOR)"
            ]
        }


_analyzer: Optional[ContextAnalyzer] = None


def get_context_analyzer() -> ContextAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = ContextAnalyzer()
    return _analyzer
