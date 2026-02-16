"""
Real-time Threat Detection System
Uses ML-based anomaly detection to identify security threats
"""
import hashlib
import re
from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
import numpy as np
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    SUSPICIOUS_PROCESS = "suspicious_process"


@dataclass
class ThreatDetection:
    threat_type: ThreatType
    threat_level: ThreatLevel
    description: str
    timestamp: datetime
    indicators: List[str]
    recommended_action: str
    confidence: float
    metadata: Dict[str, Any]


class ThreatDetector:
    """
    AI-powered threat detection system
    Monitors system activity, network traffic, and user behavior
    """
    
    def __init__(self):
        self.baseline_established = False
        self.activity_baseline: List[float] = []
        self.threat_patterns = self._load_threat_patterns()
        self.detection_history: List[ThreatDetection] = []
        logger.info("Threat Detector initialized")
        
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load known threat patterns"""
        return {
            "sql_injection": [
                r"(?i)(\bunion\b.*\bselect\b)",
                r"(?i)(\bor\b\s+1\s*=\s*1)",
                r"(?i)(\bdrop\b.*\btable\b)",
                r"(?i)(\bexec\b.*\bxp_)"
            ],
            "xss": [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"<iframe"
            ],
            "suspicious_commands": [
                r"(?i)(rm\s+-rf\s+/)",
                r"(?i)(format\s+c:)",
                r"(?i)(del\s+/f\s+/s\s+/q)",
                r"(?i)(wget.*\|\s*bash)",
                r"(?i)(curl.*\|\s*sh)"
            ],
            "malware_signatures": [
                r"(?i)(ransomware|cryptolocker|wannacry)",
                r"(?i)(keylogger|trojan|backdoor)",
                r"(?i)(botnet|c2\s+server)"
            ]
        }
        
    def detect_sql_injection(self, input_string: str) -> Optional[ThreatDetection]:
        """Detect SQL injection attempts"""
        for pattern in self.threat_patterns["sql_injection"]:
            if re.search(pattern, input_string):
                return ThreatDetection(
                    threat_type=ThreatType.SQL_INJECTION,
                    threat_level=ThreatLevel.HIGH,
                    description="Potential SQL injection detected",
                    timestamp=datetime.now(),
                    indicators=[pattern],
                    recommended_action="Block input, sanitize user input, use parameterized queries",
                    confidence=0.85,
                    metadata={"input": input_string[:100]}
                )
        return None
        
    def detect_xss(self, input_string: str) -> Optional[ThreatDetection]:
        """Detect cross-site scripting attempts"""
        for pattern in self.threat_patterns["xss"]:
            if re.search(pattern, input_string, re.IGNORECASE):
                return ThreatDetection(
                    threat_type=ThreatType.XSS,
                    threat_level=ThreatLevel.HIGH,
                    description="Potential XSS attack detected",
                    timestamp=datetime.now(),
                    indicators=[pattern],
                    recommended_action="Sanitize HTML, encode output, implement CSP headers",
                    confidence=0.82,
                    metadata={"input": input_string[:100]}
                )
        return None
        
    def detect_suspicious_command(self, command: str) -> Optional[ThreatDetection]:
        """Detect dangerous system commands"""
        for pattern in self.threat_patterns["suspicious_commands"]:
            if re.search(pattern, command):
                return ThreatDetection(
                    threat_type=ThreatType.SUSPICIOUS_PROCESS,
                    threat_level=ThreatLevel.CRITICAL,
                    description="Dangerous command detected",
                    timestamp=datetime.now(),
                    indicators=[pattern],
                    recommended_action="BLOCK IMMEDIATELY - Potential system damage or data loss",
                    confidence=0.95,
                    metadata={"command": command}
                )
        return None
        
    def detect_malware_signature(self, text: str) -> Optional[ThreatDetection]:
        """Detect malware-related keywords"""
        for pattern in self.threat_patterns["malware_signatures"]:
            if re.search(pattern, text):
                return ThreatDetection(
                    threat_type=ThreatType.MALWARE,
                    threat_level=ThreatLevel.CRITICAL,
                    description="Malware signature detected",
                    timestamp=datetime.now(),
                    indicators=[pattern],
                    recommended_action="Isolate system, run full antivirus scan, investigate source",
                    confidence=0.75,
                    metadata={"text": text[:100]}
                )
        return None
        
    def detect_anomalous_behavior(self, data_points: List[float]) -> Optional[ThreatDetection]:
        """
        Detect anomalous behavior using statistical analysis
        Uses Isolation Forest algorithm (simplified version)
        """
        if not self.baseline_established:
            if len(data_points) > 100:
                self.activity_baseline = data_points
                self.baseline_established = True
                logger.info("Activity baseline established")
            return None
            
        if len(data_points) < 10:
            return None
            
        baseline_mean = np.mean(self.activity_baseline)
        baseline_std = np.std(self.activity_baseline)
        current_mean = np.mean(data_points)
        
        z_score = abs((current_mean - baseline_mean) / baseline_std) if baseline_std > 0 else 0
        
        if z_score > 3:
            threat_level = ThreatLevel.HIGH if z_score > 5 else ThreatLevel.MEDIUM
            return ThreatDetection(
                threat_type=ThreatType.ANOMALOUS_BEHAVIOR,
                threat_level=threat_level,
                description=f"Anomalous activity detected (Z-score: {z_score:.2f})",
                timestamp=datetime.now(),
                indicators=[f"Activity deviation: {z_score:.2f} standard deviations"],
                recommended_action="Investigate activity logs, check for unauthorized access",
                confidence=min(0.95, z_score / 10),
                metadata={
                    "z_score": z_score,
                    "baseline_mean": baseline_mean,
                    "current_mean": current_mean
                }
            )
        return None
        
    def scan_input(self, input_data: str) -> List[ThreatDetection]:
        """Comprehensive scan of user input"""
        threats = []
        
        sql_threat = self.detect_sql_injection(input_data)
        if sql_threat:
            threats.append(sql_threat)
            
        xss_threat = self.detect_xss(input_data)
        if xss_threat:
            threats.append(xss_threat)
            
        command_threat = self.detect_suspicious_command(input_data)
        if command_threat:
            threats.append(command_threat)
            
        malware_threat = self.detect_malware_signature(input_data)
        if malware_threat:
            threats.append(malware_threat)
            
        if threats:
            self.detection_history.extend(threats)
            logger.warning(f"Detected {len(threats)} threat(s) in input")
            
        return threats
        
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats"""
        if not self.detection_history:
            return {"total_threats": 0, "status": "secure"}
            
        return {
            "total_threats": len(self.detection_history),
            "by_level": {
                level.value: sum(1 for t in self.detection_history if t.threat_level == level)
                for level in ThreatLevel
            },
            "by_type": {
                threat_type.value: sum(1 for t in self.detection_history if t.threat_type == threat_type)
                for threat_type in ThreatType
            },
            "recent_threats": [
                {
                    "type": t.threat_type.value,
                    "level": t.threat_level.value,
                    "description": t.description,
                    "timestamp": t.timestamp.isoformat()
                }
                for t in self.detection_history[-10:]
            ]
        }
        
    def clear_history(self):
        """Clear threat detection history"""
        self.detection_history.clear()
        logger.info("Threat history cleared")
