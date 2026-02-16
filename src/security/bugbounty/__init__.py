"""
Bug Bounty Automation Module

AI-powered bug bounty hunting with BurpSuite integration.
Includes automated reconnaissance, scanning, vulnerability detection,
and exploit generation with ethical safeguards.
"""

from .burp_integration import BurpSuiteClient, ScanConfig
from .recon_engine import ReconEngine, Target
from .vulnerability_analyzer import VulnerabilityAnalyzer, Vulnerability
from .exploit_generator import ExploitGenerator, Exploit
from .report_generator import ReportGenerator, BugReport
from .scope_validator import ScopeValidator, Program

__all__ = [
    'BurpSuiteClient',
    'ScanConfig',
    'ReconEngine',
    'Target',
    'VulnerabilityAnalyzer',
    'Vulnerability',
    'ExploitGenerator',
    'Exploit',
    'ReportGenerator',
    'BugReport',
    'ScopeValidator',
    'Program',
]
