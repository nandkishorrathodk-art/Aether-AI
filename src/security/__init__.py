"""
Aether AI Security Module
Comprehensive security testing and bug bounty hunting toolkit
"""

from .vulnerability_database import VulnerabilityDatabase, CVEEntry
from .tool_integrations import (
    MetasploitIntegration,
    NessusIntegration,
    ZAPIntegration,
    NucleiIntegration,
    SecurityToolOrchestrator,
    ScanTool,
    ScanResult
)
from .ai_scanner import AIVulnerabilityScanner, AIDetection
from .threat_intelligence import ThreatIntelligencePlatform, ThreatIndicator
from .report_generator import SecurityReportGenerator
from .cloud_scanner import CloudSecurityScanner, CloudPlatform, CloudFinding

__all__ = [
    "VulnerabilityDatabase",
    "CVEEntry",
    "MetasploitIntegration",
    "NessusIntegration",
    "ZAPIntegration",
    "NucleiIntegration",
    "SecurityToolOrchestrator",
    "ScanTool",
    "ScanResult",
    "AIVulnerabilityScanner",
    "AIDetection",
    "ThreatIntelligencePlatform",
    "ThreatIndicator",
    "SecurityReportGenerator",
    "CloudSecurityScanner",
    "CloudPlatform",
    "CloudFinding"
]
