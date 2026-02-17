"""
Bug Bounty Autopilot Module

Automated bug hunting with Burp Suite Professional integration and AI-powered analysis.

Features:
- Automated Burp Suite scanning
- Intelligent vulnerability analysis
- PoC generation
- Professional report generation
- Real-time monitoring integration

Usage:
    from src.bugbounty import AutoHunter
    
    hunter = AutoHunter()
    await hunter.start_auto_hunt("https://example.com")
"""

from src.bugbounty.models import (
    AutoScanResult,
    BugReport,
    Vulnerability,
    ScanStatus,
    VulnerabilitySeverity
)
from src.bugbounty.burp_controller import BurpController
from src.bugbounty.scanner_manager import ScannerManager
from src.bugbounty.auto_hunter import AutoHunter
from src.bugbounty.poc_generator import PoCGenerator
from src.bugbounty.report_builder import ReportBuilder

__all__ = [
    "AutoHunter",
    "BurpController",
    "ScannerManager",
    "PoCGenerator",
    "ReportBuilder",
    "AutoScanResult",
    "BugReport",
    "Vulnerability",
    "ScanStatus",
    "VulnerabilitySeverity"
]

__version__ = "0.9.0"
