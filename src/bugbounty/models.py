"""
Data models for Bug Bounty Autopilot
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Any
from pathlib import Path


class ScanStatus(Enum):
    """Status of automated scan"""
    IDLE = "idle"
    DETECTING = "detecting"
    CONFIGURING = "configuring"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    GENERATING_POC = "generating_poc"
    GENERATING_REPORT = "generating_report"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    def to_cvss_range(self) -> tuple[float, float]:
        """Convert to CVSS score range"""
        ranges = {
            self.CRITICAL: (9.0, 10.0),
            self.HIGH: (7.0, 8.9),
            self.MEDIUM: (4.0, 6.9),
            self.LOW: (0.1, 3.9),
            self.INFO: (0.0, 0.0)
        }
        return ranges[self]
    
    def to_emoji(self) -> str:
        """Get emoji for severity"""
        emojis = {
            self.CRITICAL: "🔴",
            self.HIGH: "🟠",
            self.MEDIUM: "🟡",
            self.LOW: "🔵",
            self.INFO: "⚪"
        }
        return emojis[self]


class VulnerabilityType(Enum):
    """Common vulnerability types"""
    XSS = "Cross-Site Scripting"
    SQL_INJECTION = "SQL Injection"
    CSRF = "Cross-Site Request Forgery"
    IDOR = "Insecure Direct Object Reference"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"
    SSRF = "Server-Side Request Forgery"
    XXE = "XML External Entity"
    DESERIALIZATION = "Insecure Deserialization"
    COMMAND_INJECTION = "Command Injection"
    PATH_TRAVERSAL = "Path Traversal"
    OPEN_REDIRECT = "Open Redirect"
    INFO_DISCLOSURE = "Information Disclosure"
    SECURITY_MISCONFIGURATION = "Security Misconfiguration"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    UNKNOWN = "Unknown"


@dataclass
class Vulnerability:
    """Vulnerability data model"""
    id: str
    title: str
    vuln_type: VulnerabilityType
    severity: VulnerabilitySeverity
    url: str
    parameter: Optional[str] = None
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: str = "Certain"
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    references: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.now)
    false_positive: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['vuln_type'] = self.vuln_type.value
        data['severity'] = self.severity.value
        data['detected_at'] = self.detected_at.isoformat()
        return data
    
    def estimate_payout(self, program: str = "general") -> tuple[int, int]:
        """Estimate potential bug bounty payout"""
        base_payouts = {
            VulnerabilitySeverity.CRITICAL: (10000, 50000),
            VulnerabilitySeverity.HIGH: (2000, 10000),
            VulnerabilitySeverity.MEDIUM: (500, 2000),
            VulnerabilitySeverity.LOW: (100, 500),
            VulnerabilitySeverity.INFO: (0, 100)
        }
        
        multipliers = {
            "apple": 3.0,
            "google": 2.5,
            "microsoft": 2.0,
            "facebook": 2.5,
            "general": 1.0
        }
        
        base_min, base_max = base_payouts[self.severity]
        multiplier = multipliers.get(program.lower(), 1.0)
        
        return int(base_min * multiplier), int(base_max * multiplier)


@dataclass
class ProofOfConcept:
    """Proof of Concept exploit"""
    vulnerability_id: str
    exploit_code: str
    exploit_type: str
    steps: List[str]
    waf_bypass: bool = False
    safe_for_production: bool = True
    expected_result: str = ""
    screenshots: List[Path] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['screenshots'] = [str(s) for s in self.screenshots]
        return data


@dataclass
class BugReport:
    """Complete bug bounty report"""
    title: str
    vulnerability: Vulnerability
    poc: ProofOfConcept
    summary: str
    impact: str
    reproduction_steps: List[str]
    affected_urls: List[str]
    fix_recommendation: str
    reporter_name: str = "Aether AI Bug Hunter"
    program: str = "Custom"
    estimated_payout_min: int = 0
    estimated_payout_max: int = 0
    attachments: List[Path] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['vulnerability'] = self.vulnerability.to_dict()
        data['poc'] = self.poc.to_dict()
        data['created_at'] = self.created_at.isoformat()
        data['attachments'] = [str(a) for a in self.attachments]
        return data


@dataclass
class AutoScanResult:
    """Result of automated bug hunting session"""
    scan_id: str
    target_url: str
    status: ScanStatus
    burp_running: bool = False
    scan_started_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    reports_generated: List[BugReport] = field(default_factory=list)
    total_issues_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    estimated_total_payout: int = 0
    error_message: Optional[str] = None
    
    def update_counts(self):
        """Update vulnerability counts"""
        self.total_issues_found = len(self.vulnerabilities)
        self.critical_count = sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL)
        self.high_count = sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH)
        self.medium_count = sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM)
        self.low_count = sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.LOW)
        self.info_count = sum(1 for v in self.vulnerabilities if v.severity == VulnerabilitySeverity.INFO)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        data['scan_started_at'] = self.scan_started_at.isoformat() if self.scan_started_at else None
        data['scan_completed_at'] = self.scan_completed_at.isoformat() if self.scan_completed_at else None
        data['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        data['reports_generated'] = [r.to_dict() for r in self.reports_generated]
        return data
