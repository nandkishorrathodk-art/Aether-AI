"""
AI Bias Detection and Mitigation
Ensures fair, unbiased AI responses
"""
from typing import List, Dict, Any
from enum import Enum
from dataclasses import dataclass
import re
from src.utils.logger import get_logger

logger = get_logger(__name__)


class BiasType(Enum):
    GENDER = "gender"
    RACIAL = "racial"
    AGE = "age"
    RELIGIOUS = "religious"
    POLITICAL = "political"
    SOCIOECONOMIC = "socioeconomic"
    DISABILITY = "disability"


@dataclass
class BiasDetection:
    bias_type: BiasType
    confidence: float
    evidence: List[str]
    severity: str
    recommendation: str


class BiasDetector:
    """
    Detects and flags potential biases in AI responses
    Ensures ethical, fair AI behavior
    """
    
    def __init__(self):
        self.bias_patterns = self._load_bias_patterns()
        self.detection_count = 0
        logger.info("Bias Detector initialized")
        
    def _load_bias_patterns(self) -> Dict[BiasType, List[str]]:
        """Load known bias indicators"""
        return {
            BiasType.GENDER: [
                r"\b(men|male) are (better|superior|stronger)\b",
                r"\b(women|female) should (stay|remain|be)\b",
                r"\b(his|her) job as a (nurse|engineer|CEO)\b"
            ],
            BiasType.RACIAL: [
                r"\b(race|ethnicity) (determines|defines|indicates)\b",
                r"\b(white|black|asian) people are\b"
            ],
            BiasType.AGE: [
                r"\b(old|young) people (can't|cannot|shouldn't)\b",
                r"\btoo (old|young) to\b"
            ],
            BiasType.RELIGIOUS: [
                r"\b(religion|faith) makes (them|people)\b"
            ],
            BiasType.POLITICAL: [
                r"\b(liberal|conservative)s are (stupid|wrong|bad)\b"
            ]
        }
        
    def detect_bias(self, text: str) -> List[BiasDetection]:
        """Scan text for potential biases"""
        detections = []
        
        for bias_type, patterns in self.bias_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detections.append(BiasDetection(
                        bias_type=bias_type,
                        confidence=0.75,
                        evidence=[pattern],
                        severity="medium",
                        recommendation=f"Review {bias_type.value} language for potential bias"
                    ))
                    self.detection_count += 1
                    
        return detections
        
    def audit_response(self, response: str) -> Dict[str, Any]:
        """Comprehensive bias audit of AI response"""
        biases = self.detect_bias(response)
        
        return {
            "bias_detected": len(biases) > 0,
            "bias_count": len(biases),
            "bias_types": [b.bias_type.value for b in biases],
            "severity": "high" if len(biases) > 2 else "medium" if len(biases) > 0 else "none",
            "is_safe_to_use": len(biases) == 0,
            "details": [
                {
                    "type": b.bias_type.value,
                    "confidence": b.confidence,
                    "recommendation": b.recommendation
                }
                for b in biases
            ]
        }
        
    def get_stats(self) -> Dict[str, Any]:
        """Get bias detection statistics"""
        return {
            "total_detections": self.detection_count,
            "patterns_monitored": sum(len(patterns) for patterns in self.bias_patterns.values()),
            "bias_types_tracked": len(self.bias_patterns)
        }
