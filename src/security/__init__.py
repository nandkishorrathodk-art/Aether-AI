"""
Security module for Aether AI
Provides bug bounty hunting tools and vulnerability scanning
"""
from src.security.cve_database import get_cve_database, CVEDatabase
from src.security.nuclei_scanner import get_nuclei_scanner, NucleiScanner
from src.security.ai_vulnerability_scanner import get_ai_vulnerability_scanner, AIVulnerabilityScanner
from src.security.report_generator import get_report_generator, ReportGenerator

__all__ = [
    "get_cve_database",
    "CVEDatabase",
    "get_nuclei_scanner",
    "NucleiScanner",
    "get_ai_vulnerability_scanner",
    "AIVulnerabilityScanner",
    "get_report_generator",
    "ReportGenerator",
]
