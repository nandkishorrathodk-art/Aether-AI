"""
Unit tests for Bug Bounty Autopilot components
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime

from src.bugbounty.models import (
    Vulnerability, VulnerabilityType, VulnerabilitySeverity,
    ProofOfConcept, BugReport, AutoScanResult, ScanStatus
)
from src.bugbounty.burp_controller import BurpController
from src.bugbounty.scanner_manager import ScannerManager
from src.bugbounty.poc_generator import PoCGenerator
from src.bugbounty.report_builder import ReportBuilder
from src.bugbounty.auto_hunter import AutoHunter


class TestVulnerabilityModel:
    """Test Vulnerability data model"""
    
    def test_vulnerability_creation(self):
        vuln = Vulnerability(
            id="test_1",
            title="XSS in search",
            vuln_type=VulnerabilityType.XSS,
            severity=VulnerabilitySeverity.HIGH,
            url="https://example.com/search",
            parameter="q",
            description="Reflected XSS vulnerability"
        )
        
        assert vuln.id == "test_1"
        assert vuln.title == "XSS in search"
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.parameter == "q"
    
    def test_vulnerability_to_dict(self):
        vuln = Vulnerability(
            id="test_1",
            title="SQL Injection",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.CRITICAL,
            url="https://example.com/api"
        )
        
        data = vuln.to_dict()
        
        assert data["id"] == "test_1"
        assert data["vuln_type"] == "SQL Injection"
        assert data["severity"] == "critical"
        assert "detected_at" in data
    
    def test_payout_estimation(self):
        vuln = Vulnerability(
            id="test_1",
            title="Critical RCE",
            vuln_type=VulnerabilityType.COMMAND_INJECTION,
            severity=VulnerabilitySeverity.CRITICAL,
            url="https://example.com"
        )
        
        min_payout, max_payout = vuln.estimate_payout("general")
        assert min_payout > 0
        assert max_payout > min_payout
        
        apple_min, apple_max = vuln.estimate_payout("apple")
        assert apple_min > min_payout
        assert apple_max > max_payout
    
    def test_severity_to_emoji(self):
        assert VulnerabilitySeverity.CRITICAL.to_emoji() == "🔴"
        assert VulnerabilitySeverity.HIGH.to_emoji() == "🟠"
        assert VulnerabilitySeverity.MEDIUM.to_emoji() == "🟡"
        assert VulnerabilitySeverity.LOW.to_emoji() == "🔵"
        assert VulnerabilitySeverity.INFO.to_emoji() == "⚪"


class TestBurpController:
    """Test Burp Suite Controller"""
    
    @pytest.fixture
    def mock_burp_client(self):
        with patch('src.bugbounty.burp_controller.BurpSuiteClient') as mock:
            yield mock
    
    def test_burp_controller_initialization(self, mock_burp_client):
        controller = BurpController(
            api_url="http://localhost:1337",
            api_key="test_key"
        )
        
        assert controller.api_url == "http://localhost:1337"
        assert controller.api_key == "test_key"
        mock_burp_client.assert_called_once()
    
    def test_is_burp_running_success(self, mock_burp_client):
        mock_client = Mock()
        mock_client.get_version.return_value = {"version": "2023.1"}
        mock_burp_client.return_value = mock_client
        
        controller = BurpController()
        
        assert controller.is_burp_running() is True
    
    def test_is_burp_running_failure(self, mock_burp_client):
        mock_client = Mock()
        mock_client.get_version.side_effect = Exception("Connection refused")
        mock_burp_client.return_value = mock_client
        
        controller = BurpController()
        
        assert controller.is_burp_running() is False
    
    def test_parse_burp_issue_to_vulnerability(self, mock_burp_client):
        mock_burp_client.return_value = Mock()
        
        controller = BurpController()
        
        burp_issue = {
            "issue_type": {"name": "Cross-site scripting (reflected)"},
            "severity": "high",
            "origin": "https://example.com/search?q=test",
            "issue_detail": "XSS found in search parameter",
            "evidence": "parameter=q",
            "remediation": "Encode user input",
            "confidence": "Certain",
            "serial_number": 1
        }
        
        vuln = controller.parse_burp_issue_to_vulnerability(burp_issue, "scan_123")
        
        assert vuln.id == "scan_123_1"
        assert vuln.vuln_type == VulnerabilityType.XSS
        assert vuln.severity == VulnerabilitySeverity.HIGH
        assert vuln.url == "https://example.com/search?q=test"
        assert vuln.confidence == "Certain"
    
    @pytest.mark.asyncio
    async def test_start_scan_async(self, mock_burp_client):
        mock_client = Mock()
        mock_client.start_scan.return_value = "scan_456"
        mock_burp_client.return_value = mock_client
        
        controller = BurpController()
        
        scan_id = await controller.start_scan_async(
            urls=["https://example.com"],
            scan_type="CrawlAndAudit"
        )
        
        assert scan_id == "scan_456"
        assert scan_id in controller._active_scans


class TestScannerManager:
    """Test Scanner Manager"""
    
    @pytest.fixture
    def mock_burp_controller(self):
        controller = Mock(spec=BurpController)
        controller.is_burp_running.return_value = True
        controller.start_scan_async = AsyncMock(return_value="scan_789")
        controller.wait_for_scan_async = AsyncMock(return_value={"scan_status": "succeeded"})
        controller.get_scan_issues_async = AsyncMock(return_value=[])
        return controller
    
    @pytest.mark.asyncio
    async def test_start_scan_session(self, mock_burp_controller):
        manager = ScannerManager(burp_controller=mock_burp_controller)
        
        result = await manager.start_scan_session(
            target_url="https://example.com",
            validate_scope=False
        )
        
        assert result.target_url == "https://example.com"
        assert result.status == ScanStatus.COMPLETED
        assert result.burp_running is True
    
    @pytest.mark.asyncio
    async def test_start_scan_session_burp_not_running(self, mock_burp_controller):
        mock_burp_controller.is_burp_running.return_value = False
        
        manager = ScannerManager(burp_controller=mock_burp_controller)
        
        result = await manager.start_scan_session(
            target_url="https://example.com",
            validate_scope=False
        )
        
        assert result.status == ScanStatus.FAILED
        assert "Burp Suite is not running" in result.error_message
    
    def test_filter_false_positives(self):
        manager = ScannerManager()
        
        vulns = [
            Vulnerability(
                id="1",
                title="High Severity",
                vuln_type=VulnerabilityType.XSS,
                severity=VulnerabilitySeverity.HIGH,
                url="https://example.com",
                confidence="Certain"
            ),
            Vulnerability(
                id="2",
                title="Low Tentative",
                vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                severity=VulnerabilitySeverity.LOW,
                url="https://example.com",
                confidence="Tentative"
            ),
            Vulnerability(
                id="3",
                title="Info Firm",
                vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
                severity=VulnerabilitySeverity.INFO,
                url="https://example.com",
                confidence="Firm"
            )
        ]
        
        filtered = manager.filter_false_positives(vulns)
        
        assert len(filtered) == 1
        assert filtered[0].id == "1"
    
    def test_prioritize_vulnerabilities(self):
        manager = ScannerManager()
        
        vulns = [
            Vulnerability(
                id="1",
                title="Low",
                vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                severity=VulnerabilitySeverity.LOW,
                url="https://example.com"
            ),
            Vulnerability(
                id="2",
                title="Critical",
                vuln_type=VulnerabilityType.SQL_INJECTION,
                severity=VulnerabilitySeverity.CRITICAL,
                url="https://example.com"
            ),
            Vulnerability(
                id="3",
                title="High",
                vuln_type=VulnerabilityType.XSS,
                severity=VulnerabilitySeverity.HIGH,
                url="https://example.com"
            )
        ]
        
        prioritized = manager.prioritize_vulnerabilities(vulns)
        
        assert prioritized[0].id == "2"
        assert prioritized[1].id == "3"
        assert prioritized[2].id == "1"


class TestPoCGenerator:
    """Test PoC Generator"""
    
    @pytest.fixture
    def poc_gen(self):
        return PoCGenerator()
    
    @pytest.mark.asyncio
    async def test_generate_xss_poc(self, poc_gen):
        vuln = Vulnerability(
            id="test_xss",
            title="Reflected XSS",
            vuln_type=VulnerabilityType.XSS,
            severity=VulnerabilitySeverity.HIGH,
            url="https://example.com/search",
            parameter="q"
        )
        
        poc = await poc_gen.generate_poc(vuln, include_waf_bypass=True)
        
        assert poc.vulnerability_id == "test_xss"
        assert poc.exploit_type == "XSS"
        assert poc.waf_bypass is True
        assert poc.safe_for_production is True
        assert len(poc.steps) > 0
        assert "<script>" in poc.exploit_code or "alert" in poc.exploit_code
    
    @pytest.mark.asyncio
    async def test_generate_sqli_poc(self, poc_gen):
        vuln = Vulnerability(
            id="test_sqli",
            title="SQL Injection",
            vuln_type=VulnerabilityType.SQL_INJECTION,
            severity=VulnerabilitySeverity.CRITICAL,
            url="https://example.com/api/user",
            parameter="id"
        )
        
        poc = await poc_gen.generate_poc(vuln, safe_only=True)
        
        assert poc.vulnerability_id == "test_sqli"
        assert poc.exploit_type == "SQLi"
        assert poc.safe_for_production is True
        assert "SELECT" in poc.exploit_code or "OR" in poc.exploit_code
    
    @pytest.mark.asyncio
    async def test_generate_csrf_poc(self, poc_gen):
        vuln = Vulnerability(
            id="test_csrf",
            title="CSRF",
            vuln_type=VulnerabilityType.CSRF,
            severity=VulnerabilitySeverity.MEDIUM,
            url="https://example.com/api/transfer"
        )
        
        poc = await poc_gen.generate_poc(vuln)
        
        assert poc.vulnerability_id == "test_csrf"
        assert poc.exploit_type == "CSRF"
        assert "<form" in poc.exploit_code
        assert "method=" in poc.exploit_code


class TestReportBuilder:
    """Test Report Builder"""
    
    @pytest.fixture
    def report_builder(self, tmp_path):
        return ReportBuilder(output_dir=tmp_path)
    
    @pytest.fixture
    def sample_vulnerability(self):
        return Vulnerability(
            id="vuln_1",
            title="XSS in Search",
            vuln_type=VulnerabilityType.XSS,
            severity=VulnerabilitySeverity.HIGH,
            url="https://example.com/search",
            parameter="q",
            description="Reflected XSS found",
            evidence="Payload executed",
            remediation="Encode output"
        )
    
    @pytest.fixture
    def sample_poc(self):
        return ProofOfConcept(
            vulnerability_id="vuln_1",
            exploit_code='print("XSS PoC")',
            exploit_type="XSS",
            steps=["Step 1", "Step 2"],
            safe_for_production=True,
            expected_result="Alert dialog appears"
        )
    
    def test_build_report(self, report_builder, sample_vulnerability, sample_poc):
        report = report_builder.build_report(
            vulnerability=sample_vulnerability,
            poc=sample_poc,
            program="general"
        )
        
        assert report.title.startswith("[HIGH]")
        assert "XSS" in report.title
        assert report.vulnerability == sample_vulnerability
        assert report.poc == sample_poc
        assert report.estimated_payout_min > 0
    
    def test_generate_markdown_report(self, report_builder, sample_vulnerability, sample_poc):
        report = report_builder.build_report(sample_vulnerability, sample_poc)
        
        markdown = report_builder.generate_markdown_report(report)
        
        assert "# [HIGH]" in markdown
        assert "XSS in Search" in markdown
        assert "## Summary" in markdown
        assert "## Proof of Concept" in markdown
        assert "## Remediation" in markdown
    
    def test_generate_html_report(self, report_builder, sample_vulnerability, sample_poc):
        report = report_builder.build_report(sample_vulnerability, sample_poc)
        
        html = report_builder.generate_html_report(report)
        
        assert "<!DOCTYPE html>" in html
        assert "XSS in Search" in html
        assert "severity-badge" in html
        assert report.vulnerability.url in html
    
    def test_generate_json_report(self, report_builder, sample_vulnerability, sample_poc):
        report = report_builder.build_report(sample_vulnerability, sample_poc)
        
        json_str = report_builder.generate_json_report(report)
        
        import json
        data = json.loads(json_str)
        
        assert "title" in data
        assert "vulnerability" in data
        assert "poc" in data
    
    def test_save_report(self, report_builder, sample_vulnerability, sample_poc):
        report = report_builder.build_report(sample_vulnerability, sample_poc)
        
        saved_files = report_builder.save_report(
            report=report,
            formats=["markdown", "html", "json"]
        )
        
        assert "markdown" in saved_files
        assert "html" in saved_files
        assert "json" in saved_files
        
        assert saved_files["markdown"].exists()
        assert saved_files["html"].exists()
        assert saved_files["json"].exists()


class TestAutoHunter:
    """Test Auto Hunter"""
    
    @pytest.fixture
    def mock_components(self):
        burp = Mock(spec=BurpController)
        burp.is_burp_running.return_value = True
        
        scanner = Mock(spec=ScannerManager)
        scanner.start_scan_session = AsyncMock(return_value=AutoScanResult(
            scan_id="scan_1",
            target_url="https://example.com",
            status=ScanStatus.COMPLETED,
            vulnerabilities=[
                Vulnerability(
                    id="v1",
                    title="XSS",
                    vuln_type=VulnerabilityType.XSS,
                    severity=VulnerabilitySeverity.HIGH,
                    url="https://example.com"
                )
            ]
        ))
        
        poc_gen = Mock(spec=PoCGenerator)
        poc_gen.generate_poc = AsyncMock(return_value=ProofOfConcept(
            vulnerability_id="v1",
            exploit_code="test",
            exploit_type="XSS",
            steps=["1"],
            safe_for_production=True,
            expected_result="test"
        ))
        
        report_builder = Mock(spec=ReportBuilder)
        report_builder.build_report.return_value = Mock(spec=BugReport)
        report_builder.save_report.return_value = {}
        
        return burp, scanner, poc_gen, report_builder
    
    @pytest.mark.asyncio
    async def test_auto_hunter_initialization(self):
        hunter = AutoHunter()
        
        assert hunter.burp is not None
        assert hunter.scanner is not None
        assert hunter.poc_gen is not None
        assert hunter.report_builder is not None
    
    @pytest.mark.asyncio
    async def test_start_auto_hunt_success(self, mock_components):
        burp, scanner, poc_gen, report_builder = mock_components
        
        hunter = AutoHunter(
            burp_controller=burp,
            scanner_manager=scanner,
            poc_generator=poc_gen,
            report_builder=report_builder
        )
        
        result = await hunter.start_auto_hunt(
            target_url="https://example.com",
            auto_poc=True,
            auto_report=True
        )
        
        assert result.status == ScanStatus.COMPLETED
        assert result.target_url == "https://example.com"
    
    @pytest.mark.asyncio
    async def test_start_auto_hunt_burp_not_running(self, mock_components):
        burp, scanner, poc_gen, report_builder = mock_components
        burp.is_burp_running.return_value = False
        
        hunter = AutoHunter(
            burp_controller=burp,
            scanner_manager=scanner,
            poc_generator=poc_gen,
            report_builder=report_builder
        )
        
        result = await hunter.start_auto_hunt(
            target_url="https://example.com"
        )
        
        assert result.status == ScanStatus.FAILED
        assert "Burp Suite not detected" in result.error_message
    
    def test_generate_summary(self):
        hunter = AutoHunter()
        
        result = AutoScanResult(
            scan_id="test",
            target_url="https://example.com",
            status=ScanStatus.COMPLETED,
            scan_started_at=datetime.now(),
            scan_completed_at=datetime.now(),
            critical_count=2,
            high_count=3,
            medium_count=5
        )
        result.update_counts()
        
        summary = hunter.generate_summary(result)
        
        assert "Completed Successfully" in summary
        assert "https://example.com" in summary
        assert "Critical: 2" in summary
        assert "High: 3" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
