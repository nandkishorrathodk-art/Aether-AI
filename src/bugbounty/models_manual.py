"""
Manual Testing Agent - Data Models

Models for AI-powered manual testing that replicates expert security researchers.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class RequestType(Enum):
    """Type of HTTP request"""
    API = "api"
    WEB = "web"
    AUTH = "authentication"
    FILE_UPLOAD = "file_upload"
    WEBSOCKET = "websocket"
    GRAPHQL = "graphql"
    UNKNOWN = "unknown"


class ParameterType(Enum):
    """Types of parameters in requests"""
    ID = "id"  # user_id, order_id, etc.
    AUTH_TOKEN = "auth_token"  # JWT, session tokens
    FILE = "file"
    EMAIL = "email"
    USERNAME = "username"
    PASSWORD = "password"
    AMOUNT = "amount"  # monetary values
    BOOLEAN = "boolean"
    JSON = "json"
    XML = "xml"
    GENERIC = "generic"


class VulnerabilityType(Enum):
    """Vulnerability types to test"""
    IDOR = "idor"
    XSS = "xss"
    SQLi = "sqli"
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SSRF = "ssrf"
    XXE = "xxe"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    BUSINESS_LOGIC = "business_logic"
    RACE_CONDITION = "race_condition"
    UNKNOWN = "unknown"


class TestAction(Enum):
    """Actions to take with intercepted requests"""
    FORWARD = "forward"
    DROP = "drop"
    MODIFY_AND_FORWARD = "modify_and_forward"
    REPEAT = "repeat"
    CHAIN = "chain"  # Chain with another exploit


class AnomalyType(Enum):
    """Types of response anomalies"""
    STATUS_CODE_CHANGE = "status_code_change"
    LENGTH_CHANGE = "length_change"
    ERROR_MESSAGE = "error_message"
    DATA_LEAKAGE = "data_leakage"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    TIMING_DIFFERENCE = "timing_difference"
    HEADER_CHANGE = "header_change"
    NONE = "none"


@dataclass
class InterceptedRequest:
    """Represents a request captured from Burp Intercept"""
    request_id: str
    timestamp: datetime
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    raw_request: str
    
    # Analysis results (filled by analyzer)
    request_type: RequestType = RequestType.UNKNOWN
    parameters: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    interesting_score: float = 0.0  # 0.0-1.0, how interesting for testing
    
    # Metadata
    protocol: str = "HTTP/1.1"
    host: str = ""
    path: str = ""
    

@dataclass
class ParameterAnalysis:
    """Analysis of a specific parameter"""
    name: str
    value: Any
    location: str  # query, body, header, cookie
    param_type: ParameterType
    
    # Test recommendations
    suggested_vulns: List[VulnerabilityType]
    test_priority: float  # 0.0-1.0
    
    # Context
    appears_to_be: str  # AI description: "user identifier", "JWT token", etc.
    sensitive: bool = False
    predictable: bool = False  # sequential IDs, etc.


@dataclass
class RequestAnalysis:
    """AI analysis of intercepted request"""
    request_id: str
    timestamp: datetime
    
    # High-level understanding
    request_type: RequestType
    business_purpose: str  # "User profile fetch", "Order creation", etc.
    authentication_present: bool
    authorization_present: bool
    
    # Parameters
    parameters: List[ParameterAnalysis]
    interesting_params: List[str]  # Param names worth testing
    
    # Recommendations
    recommended_tests: List[VulnerabilityType]
    test_priority: float  # Overall priority 0.0-1.0
    reasoning: str  # AI explanation
    
    # Context
    similar_to_previous: Optional[str] = None  # ID of similar request
    application_insights: List[str] = field(default_factory=list)  # "Uses JWT", "Sequential IDs", etc.


@dataclass
class TestPayload:
    """A payload to test against a parameter"""
    payload_id: str
    vuln_type: VulnerabilityType
    payload_value: Any
    description: str
    
    # Context-aware
    parameter_name: str
    original_value: Any
    context_specific: bool  # True if crafted for this specific request
    
    # Metadata
    waf_bypass_technique: Optional[str] = None
    expected_behavior: str = ""  # What to look for in response
    risk_level: str = "safe"  # safe, medium, dangerous


@dataclass
class ModifiedRequest:
    """Request after intelligent modification"""
    original_request_id: str
    modified_request_id: str
    timestamp: datetime
    
    # Modification details
    parameter_modified: str
    original_value: Any
    payload_applied: TestPayload
    
    # Full modified request
    raw_modified_request: str
    
    # What we're testing
    testing_for: VulnerabilityType
    hypothesis: str  # "Testing if user_id allows IDOR"


@dataclass
class ResponseAnalysis:
    """Analysis of response after sending modified request"""
    response_id: str
    request_id: str
    timestamp: datetime
    
    # Response data
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time: float  # milliseconds
    
    # Anomalies detected
    anomalies: List[AnomalyType]
    anomaly_details: List[str]  # Descriptions of each anomaly
    
    # Comparison with baseline
    baseline_status: Optional[int] = None
    baseline_length: Optional[int] = None
    baseline_time: Optional[float] = None
    
    # Vulnerability assessment
    vulnerability_found: bool = False
    vulnerability_type: Optional[VulnerabilityType] = None
    confidence: float = 0.0  # 0.0-1.0
    evidence: List[str] = field(default_factory=list)
    
    # AI analysis
    ai_interpretation: str = ""
    false_positive_likelihood: float = 0.0


@dataclass
class TestDecision:
    """Decision on what to do next"""
    decision_id: str
    request_id: str
    timestamp: datetime
    
    # Decision
    action: TestAction
    reasoning: str
    
    # If MODIFY_AND_FORWARD
    modifications: Optional[List[ModifiedRequest]] = None
    
    # If CHAIN
    chain_with: Optional[str] = None  # ID of another exploit
    chain_reasoning: str = ""
    
    # Confidence
    confidence: float = 0.0


@dataclass
class ApplicationKnowledge:
    """Knowledge learned about the target application"""
    app_id: str  # Domain or identifier
    learned_at: datetime
    
    # Technology stack
    framework: Optional[str] = None  # "React", "Django", etc.
    server: Optional[str] = None
    waf_present: bool = False
    waf_type: Optional[str] = None
    
    # Patterns
    id_format: Optional[str] = None  # "sequential", "UUID", etc.
    auth_mechanism: Optional[str] = None  # "JWT", "session cookie", etc.
    common_parameters: List[str] = field(default_factory=list)
    
    # Vulnerabilities found
    known_vulns: List[VulnerabilityType] = field(default_factory=list)
    endpoints_tested: List[str] = field(default_factory=list)
    
    # Insights
    insights: List[str] = field(default_factory=list)  # "All IDs are sequential", etc.


@dataclass
class ExploitChain:
    """Chain of multiple exploits"""
    chain_id: str
    timestamp: datetime
    
    # Exploits in order
    exploits: List[str]  # List of vulnerability IDs
    exploit_descriptions: List[str]
    
    # Chain logic
    reasoning: str  # "Use IDOR to get admin token, then escalate with XSS"
    estimated_impact: str  # "Account takeover", "Data exfiltration", etc.
    
    # Success
    successful: bool = False
    evidence: List[str] = field(default_factory=list)


@dataclass
class ManualTestingSession:
    """A complete manual testing session"""
    session_id: str
    target: str
    started_at: datetime
    
    # Requests analyzed
    requests_intercepted: int = 0
    requests_modified: int = 0
    requests_forwarded: int = 0
    requests_dropped: int = 0
    
    # Findings
    vulnerabilities_found: List[str] = field(default_factory=list)  # IDs
    exploit_chains: List[ExploitChain] = field(default_factory=list)
    
    # Learning
    application_knowledge: Optional[ApplicationKnowledge] = None
    
    # Statistics
    parameters_tested: int = 0
    payloads_sent: int = 0
    anomalies_detected: int = 0
    
    # Status
    active: bool = True
    ended_at: Optional[datetime] = None


# Helper functions

def classify_parameter_type(name: str, value: Any) -> ParameterType:
    """Classify parameter based on name and value"""
    name_lower = name.lower()
    
    if 'id' in name_lower or 'uid' in name_lower or 'user' in name_lower:
        return ParameterType.ID
    elif 'token' in name_lower or 'jwt' in name_lower or 'auth' in name_lower:
        return ParameterType.AUTH_TOKEN
    elif 'file' in name_lower or 'upload' in name_lower:
        return ParameterType.FILE
    elif 'email' in name_lower or 'mail' in name_lower:
        return ParameterType.EMAIL
    elif 'user' in name_lower or 'username' in name_lower:
        return ParameterType.USERNAME
    elif 'pass' in name_lower or 'pwd' in name_lower:
        return ParameterType.PASSWORD
    elif 'amount' in name_lower or 'price' in name_lower or 'total' in name_lower:
        return ParameterType.AMOUNT
    elif isinstance(value, bool) or value in ['true', 'false', '0', '1']:
        return ParameterType.BOOLEAN
    elif isinstance(value, dict):
        return ParameterType.JSON
    
    return ParameterType.GENERIC


def suggest_vulnerabilities_for_param(param_type: ParameterType) -> List[VulnerabilityType]:
    """Suggest vulnerability types to test based on parameter type"""
    suggestions = {
        ParameterType.ID: [VulnerabilityType.IDOR, VulnerabilityType.PRIVILEGE_ESCALATION],
        ParameterType.AUTH_TOKEN: [VulnerabilityType.AUTH_BYPASS, VulnerabilityType.PRIVILEGE_ESCALATION],
        ParameterType.FILE: [VulnerabilityType.PATH_TRAVERSAL, VulnerabilityType.XXE],
        ParameterType.EMAIL: [VulnerabilityType.XSS, VulnerabilityType.SQLi],
        ParameterType.USERNAME: [VulnerabilityType.SQLi, VulnerabilityType.XSS, VulnerabilityType.AUTH_BYPASS],
        ParameterType.PASSWORD: [VulnerabilityType.AUTH_BYPASS, VulnerabilityType.SQLi],
        ParameterType.AMOUNT: [VulnerabilityType.BUSINESS_LOGIC, VulnerabilityType.SQLi],
        ParameterType.BOOLEAN: [VulnerabilityType.BUSINESS_LOGIC, VulnerabilityType.AUTH_BYPASS],
        ParameterType.JSON: [VulnerabilityType.XXE, VulnerabilityType.BUSINESS_LOGIC],
        ParameterType.GENERIC: [VulnerabilityType.XSS, VulnerabilityType.SQLi],
    }
    
    return suggestions.get(param_type, [VulnerabilityType.XSS, VulnerabilityType.SQLi])
