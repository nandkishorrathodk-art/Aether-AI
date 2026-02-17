#!/usr/bin/env python3
"""Quick import test for bug bounty modules"""

try:
    from src.bugbounty.models import (
        Vulnerability, VulnerabilitySeverity, VulnerabilityType,
        ProofOfConcept, BugReport, AutoScanResult, ScanStatus
    )
    print("✓ Models imported successfully")
    
    from src.bugbounty.burp_controller import BurpController
    print("✓ BurpController imported successfully")
    
    from src.bugbounty.scanner_manager import ScannerManager
    print("✓ ScannerManager imported successfully")
    
    from src.bugbounty.poc_generator import PoCGenerator
    print("✓ PoCGenerator imported successfully")
    
    from src.bugbounty.report_builder import ReportBuilder
    print("✓ ReportBuilder imported successfully")
    
    from src.bugbounty.auto_hunter import AutoHunter
    print("✓ AutoHunter imported successfully")
    
    from src.api.routes.bugbounty_auto import router
    print("✓ API routes imported successfully")
    
    vuln = Vulnerability(
        id="test_1",
        title="Test XSS",
        vuln_type=VulnerabilityType.XSS,
        severity=VulnerabilitySeverity.HIGH,
        url="https://example.com"
    )
    print(f"✓ Created test vulnerability: {vuln.title}")
    print(f"  Severity emoji: {vuln.severity.to_emoji()}")
    
    min_pay, max_pay = vuln.estimate_payout("general")
    print(f"  Estimated payout: ${min_pay:,} - ${max_pay:,}")
    
    print("\n✅ All imports and basic functionality working!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
