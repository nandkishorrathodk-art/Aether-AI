#!/usr/bin/env python3
"""
Bug Bounty Automation Test Script

Tests the bug bounty automation features including BurpSuite integration,
reconnaissance, vulnerability analysis, and report generation.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import asyncio
import logging
from src.security.bugbounty.burp_integration import BurpSuiteClient, ScanConfig, ScanType
from src.security.bugbounty.recon_engine import ReconEngine, Target
from src.security.bugbounty.vulnerability_analyzer import VulnerabilityAnalyzer, Vulnerability, Severity, VulnerabilityType
from src.security.bugbounty.exploit_generator import ExploitGenerator
from src.security.bugbounty.report_generator import ReportGenerator, BugReport, Platform
from src.security.bugbounty.scope_validator import ScopeValidator, ScopeManager, Program
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_scope_validator():
    """Test scope validation"""
    print("\n" + "="*60)
    print("TEST 1: Scope Validator")
    print("="*60)
    
    # Create program
    program = Program(
        name="Test Program",
        platform="HackerOne",
        in_scope=["*.example.com", "https://api.example.com/*"],
        out_of_scope=["*.test.example.com"]
    )
    
    validator = ScopeValidator(program)
    
    # Test cases
    test_urls = [
        "https://app.example.com",
        "https://admin.example.com/login",
        "https://test.example.com",  # Out of scope
        "https://google.com",  # Not in scope
    ]
    
    for url in test_urls:
        result = validator.validate_url(url)
        status = "[OK] IN SCOPE" if result["in_scope"] else "[X] OUT OF SCOPE"
        print(f"{status}: {url}")
        if result["warnings"]:
            print(f"  Warnings: {', '.join(result['warnings'])}")
    
    print(f"\n{validator.get_scope_summary()}")
    print("\n" + validator.generate_scope_warning())


def test_scope_manager():
    """Test scope manager with multiple programs"""
    print("\n" + "="*60)
    print("TEST 2: Scope Manager")
    print("="*60)
    
    manager = ScopeManager()
    
    # Add programs
    program1 = Program(
        name="Example Corp",
        platform="HackerOne",
        in_scope=["*.example.com"]
    )
    
    program2 = Program(
        name="Test Corp",
        platform="Bugcrowd",
        in_scope=["*.testcorp.com"]
    )
    
    manager.add_program(program1)
    manager.add_program(program2)
    
    print(f"Programs: {manager.list_programs()}")
    
    # Switch programs
    manager.set_active_program("Example Corp")
    validator = manager.get_validator("Example Corp")
    print(f"\nActive program: {manager.active_program}")
    print(validator.get_scope_summary())


async def test_recon_engine():
    """Test reconnaissance engine"""
    print("\n" + "="*60)
    print("TEST 3: Reconnaissance Engine")
    print("="*60)
    
    engine = ReconEngine()
    
    # Test passive subdomain enumeration
    print("\nTesting passive subdomain enumeration...")
    subdomains = await engine.enumerate_subdomains_passive("example.com")
    print(f"Found {len(subdomains)} subdomains (showing first 10):")
    for subdomain in list(subdomains)[:10]:
        print(f"  - {subdomain}")
    
    # Test technology detection
    print("\nTesting technology detection...")
    techs = await engine.detect_technologies("https://example.com")
    print(f"Detected technologies: {techs}")


def test_vulnerability_analyzer():
    """Test vulnerability analyzer"""
    print("\n" + "="*60)
    print("TEST 4: Vulnerability Analyzer")
    print("="*60)
    
    analyzer = VulnerabilityAnalyzer()
    
    # Create test vulnerabilities
    vulns = [
        Vulnerability(
            title="SQL Injection in login form",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            url="https://example.com/login",
            description="SQL injection vulnerability in username parameter",
            parameter="username",
            cvss_score=9.8
        ),
        Vulnerability(
            title="Reflected XSS in search",
            vuln_type=VulnerabilityType.XXS_REFLECTED,
            severity=Severity.HIGH,
            url="https://example.com/search",
            description="XSS in search query parameter",
            parameter="q",
            cvss_score=7.4
        ),
        Vulnerability(
            title="Open Redirect",
            vuln_type=VulnerabilityType.OPEN_REDIRECT,
            severity=Severity.MEDIUM,
            url="https://example.com/redirect",
            description="Unvalidated redirect",
            parameter="url",
            cvss_score=5.4
        )
    ]
    
    # Analyze
    analysis = analyzer.analyze_vulnerabilities(vulns)
    
    print(f"Total vulnerabilities: {analysis['total']}")
    print(f"\nBy severity:")
    for severity, count in analysis['by_severity'].items():
        print(f"  {severity}: {count}")
    
    print(f"\nBy type:")
    for vtype, count in analysis['by_type'].items():
        print(f"  {vtype}: {count}")
    
    print(f"\nTop vulnerabilities:")
    sorted_vulns = sorted(vulns, key=lambda v: v.cvss_score, reverse=True)
    for vuln in sorted_vulns[:3]:
        print(f"  - {vuln.title} ({vuln.severity.value}) - CVSS: {vuln.cvss_score}")


def test_exploit_generator():
    """Test exploit generator"""
    print("\n" + "="*60)
    print("TEST 5: Exploit Generator")
    print("="*60)
    
    generator = ExploitGenerator()
    
    # Test XSS exploit
    print("\nGenerating XSS exploit...")
    xss_exploit = generator.generate_xss_exploit(
        url="https://example.com/search",
        parameter="q"
    )
    print(f"Type: {xss_exploit.exploit_type.value}")
    print(f"Code:\n{xss_exploit.code[:200]}...")
    
    # Test SQL injection exploit
    print("\nGenerating SQL injection exploit...")
    sqli_exploit = generator.generate_sqli_exploit(
        url="https://example.com/product",
        parameter="id"
    )
    print(f"Type: {sqli_exploit.exploit_type.value}")
    print(f"Steps: {len(sqli_exploit.steps)} steps")
    for i, step in enumerate(sqli_exploit.steps[:3], 1):
        print(f"  {i}. {step}")


def test_report_generator():
    """Test report generator"""
    print("\n" + "="*60)
    print("TEST 6: Report Generator")
    print("="*60)
    
    generator = ReportGenerator()
    
    # Create test report
    report = BugReport(
        title="SQL Injection in Authentication Bypass",
        vulnerability_type="SQL Injection",
        severity="Critical",
        url="https://example.com/login",
        description="The login form is vulnerable to SQL injection, allowing authentication bypass",
        impact="An attacker can bypass authentication and access any user account",
        remediation="Use parameterized queries and input validation",
        proof_of_concept="Username: admin' OR '1'='1\nPassword: anything",
        cvss_score=9.8,
        cwe_id="CWE-89",
        platform=Platform.HACKERONE
    )
    
    # Generate markdown
    print("\nMarkdown Report:")
    print("-" * 60)
    markdown = generator.generate_markdown(report)
    print(markdown[:500] + "...")
    
    # Generate HTML
    print("\n\nHTML Report (preview):")
    print("-" * 60)
    html = generator.generate_html(report)
    print(html[:300] + "...")
    
    # Bounty estimate
    print(f"\n\nEstimated Bounty: ${report.estimated_bounty}")


def test_burp_integration():
    """Test BurpSuite integration (requires BurpSuite running)"""
    print("\n" + "="*60)
    print("TEST 7: BurpSuite Integration")
    print("="*60)
    
    try:
        client = BurpSuiteClient(api_url="http://localhost:1337")
        
        # Get version
        version = client.get_version()
        print(f"BurpSuite version: {version}")
        
        # Note: Actual scanning requires authorization
        print("\n[WARNING] Scan test skipped (requires authorized target)")
        print("To test scanning:")
        print("1. Start BurpSuite Professional")
        print("2. Enable REST API (User Options -> Misc)")
        print("3. Use authorized target URL")
        
    except Exception as e:
        print(f"[ERROR] BurpSuite not available: {e}")
        print("\nBurpSuite integration requires:")
        print("1. BurpSuite Professional running")
        print("2. REST API enabled")
        print("3. API accessible at http://localhost:1337")


def main():
    """Run all tests"""
    print("="*60)
    print("Bug Bounty Automation Test Suite")
    print("="*60)
    
    # Run tests
    test_scope_validator()
    test_scope_manager()
    
    # Async tests
    loop = asyncio.get_event_loop()
    loop.run_until_complete(test_recon_engine())
    
    test_vulnerability_analyzer()
    test_exploit_generator()
    test_report_generator()
    test_burp_integration()
    
    print("\n" + "="*60)
    print("All tests completed!")
    print("="*60)
    
    print("\n[INFO] For full documentation, see:")
    print("   docs/BUGBOUNTY_AUTOMATION.md")
    
    print("\n[WARNING] REMEMBER:")
    print("   - Only test authorized targets")
    print("   - Follow bug bounty program rules")
    print("   - Use responsibly and ethically")


if __name__ == "__main__":
    main()
