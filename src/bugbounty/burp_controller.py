"""
Burp Suite Controller

Enhanced Burp Suite REST API client with safety features and automation.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from src.security.bugbounty.burp_integration import (
    BurpSuiteClient, ScanConfig, ScanType, ScanStatus
)
from src.bugbounty.models import Vulnerability, VulnerabilitySeverity, VulnerabilityType
from src.config import settings

logger = logging.getLogger(__name__)


class BurpController:
    """
    Enhanced Burp Suite controller for automated bug hunting
    
    Features:
    - Async/sync interface
    - Automatic issue parsing
    - Safety checks
    - Error handling
    - Integration with monitoring system
    """
    
    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None
    ):
        """
        Initialize Burp Suite controller
        
        Args:
            api_url: Burp Suite API URL (defaults to settings)
            api_key: API key for authentication (defaults to settings)
        """
        self.api_url = api_url or settings.burpsuite_api_url
        self.api_key = api_key or settings.burpsuite_api_key
        
        self.client = BurpSuiteClient(
            api_url=self.api_url,
            api_key=self.api_key
        )
        
        self._active_scans: Dict[str, Dict[str, Any]] = {}
        
        logger.info(f"BurpController initialized with API: {self.api_url}")
    
    def is_burp_running(self) -> bool:
        """Check if Burp Suite is accessible"""
        try:
            self.client.get_version()
            return True
        except Exception as e:
            logger.debug(f"Burp Suite not accessible: {e}")
            return False
    
    def get_burp_info(self) -> Dict[str, Any]:
        """Get Burp Suite version and status"""
        try:
            version = self.client.get_version()
            return {
                "running": True,
                "version": version,
                "api_url": self.api_url,
                "active_scans": len(self._active_scans)
            }
        except Exception as e:
            return {
                "running": False,
                "error": str(e),
                "api_url": self.api_url
            }
    
    async def start_scan_async(
        self,
        urls: List[str],
        scan_type: str = "CrawlAndAudit",
        crawl_depth: int = 5,
        max_crawl_time: int = 300
    ) -> str:
        """
        Start scan asynchronously
        
        Args:
            urls: Target URLs to scan
            scan_type: Type of scan (CrawlAndAudit, CrawlOnly, AuditOnly)
            crawl_depth: Maximum crawl depth
            max_crawl_time: Maximum crawl time in seconds
            
        Returns:
            Scan ID
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._start_scan_sync,
            urls, scan_type, crawl_depth, max_crawl_time
        )
    
    def _start_scan_sync(
        self,
        urls: List[str],
        scan_type: str,
        crawl_depth: int,
        max_crawl_time: int
    ) -> str:
        """Internal sync scan start"""
        config = ScanConfig(
            urls=urls,
            scan_type=ScanType[scan_type.upper()] if isinstance(scan_type, str) else scan_type,
            crawl_depth=crawl_depth,
            max_crawl_time=max_crawl_time
        )
        
        scan_id = self.client.start_scan(config)
        
        self._active_scans[scan_id] = {
            "urls": urls,
            "started_at": datetime.now(),
            "status": ScanStatus.RUNNING.value
        }
        
        logger.info(f"Started scan {scan_id} for {urls}")
        return scan_id
    
    async def get_scan_status_async(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.client.get_scan_status,
            scan_id
        )
    
    async def get_scan_issues_async(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get scan issues asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.client.get_scan_issues,
            scan_id
        )
    
    async def wait_for_scan_async(
        self,
        scan_id: str,
        poll_interval: int = 10,
        timeout: int = 3600,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Wait for scan completion with progress updates
        
        Args:
            scan_id: Scan ID
            poll_interval: Seconds between status checks
            timeout: Maximum wait time
            progress_callback: Optional callback(status) for progress updates
            
        Returns:
            Final scan status
        """
        start_time = datetime.now()
        
        while True:
            status = await self.get_scan_status_async(scan_id)
            scan_status = status.get('scan_status', '')
            
            if progress_callback:
                await progress_callback(status)
            
            if scan_status in [ScanStatus.SUCCEEDED.value, ScanStatus.FAILED.value]:
                if scan_id in self._active_scans:
                    self._active_scans[scan_id]["status"] = scan_status
                    self._active_scans[scan_id]["completed_at"] = datetime.now()
                
                logger.info(f"Scan {scan_id} completed: {scan_status}")
                return status
            
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > timeout:
                logger.warning(f"Scan {scan_id} timeout after {timeout}s")
                await self.pause_scan_async(scan_id)
                raise TimeoutError(f"Scan timeout after {timeout}s")
            
            await asyncio.sleep(poll_interval)
    
    async def pause_scan_async(self, scan_id: str):
        """Pause scan asynchronously"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.client.pause_scan, scan_id)
        
        if scan_id in self._active_scans:
            self._active_scans[scan_id]["status"] = ScanStatus.PAUSED.value
    
    async def resume_scan_async(self, scan_id: str):
        """Resume scan asynchronously"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.client.resume_scan, scan_id)
        
        if scan_id in self._active_scans:
            self._active_scans[scan_id]["status"] = ScanStatus.RUNNING.value
    
    async def stop_scan_async(self, scan_id: str):
        """Stop and delete scan"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.client.delete_scan, scan_id)
        
        if scan_id in self._active_scans:
            del self._active_scans[scan_id]
        
        logger.info(f"Stopped scan: {scan_id}")
    
    def parse_burp_issue_to_vulnerability(
        self,
        issue: Dict[str, Any],
        scan_id: str
    ) -> Vulnerability:
        """
        Parse Burp Suite issue to Vulnerability model
        
        Args:
            issue: Burp Suite issue dictionary
            scan_id: Scan ID for reference
            
        Returns:
            Vulnerability object
        """
        issue_type = issue.get('issue_type', {})
        issue_name = issue_type.get('name', 'Unknown Issue')
        
        severity_map = {
            'high': VulnerabilitySeverity.HIGH,
            'medium': VulnerabilitySeverity.MEDIUM,
            'low': VulnerabilitySeverity.LOW,
            'information': VulnerabilitySeverity.INFO
        }
        
        severity_str = issue.get('severity', 'low').lower()
        severity = severity_map.get(severity_str, VulnerabilitySeverity.LOW)
        
        vuln_type = self._detect_vulnerability_type(issue_name)
        
        return Vulnerability(
            id=f"{scan_id}_{issue.get('serial_number', 0)}",
            title=issue_name,
            vuln_type=vuln_type,
            severity=severity,
            url=issue.get('origin', ''),
            parameter=self._extract_parameter(issue),
            description=issue.get('issue_detail', ''),
            evidence=issue.get('evidence', ''),
            remediation=issue.get('remediation', ''),
            confidence=issue.get('confidence', 'Certain'),
            cvss_score=self._estimate_cvss(severity),
            references=self._extract_references(issue)
        )
    
    def _detect_vulnerability_type(self, issue_name: str) -> VulnerabilityType:
        """Detect vulnerability type from issue name"""
        issue_lower = issue_name.lower()
        
        type_map = {
            'xss': VulnerabilityType.XSS,
            'cross-site scripting': VulnerabilityType.XSS,
            'sql': VulnerabilityType.SQL_INJECTION,
            'csrf': VulnerabilityType.CSRF,
            'idor': VulnerabilityType.IDOR,
            'file inclusion': VulnerabilityType.LFI,
            'ssrf': VulnerabilityType.SSRF,
            'xxe': VulnerabilityType.XXE,
            'deserialization': VulnerabilityType.DESERIALIZATION,
            'command injection': VulnerabilityType.COMMAND_INJECTION,
            'path traversal': VulnerabilityType.PATH_TRAVERSAL,
            'open redirect': VulnerabilityType.OPEN_REDIRECT,
            'information disclosure': VulnerabilityType.INFO_DISCLOSURE,
            'misconfiguration': VulnerabilityType.SECURITY_MISCONFIGURATION,
            'authentication': VulnerabilityType.BROKEN_AUTH
        }
        
        for key, vuln_type in type_map.items():
            if key in issue_lower:
                return vuln_type
        
        return VulnerabilityType.UNKNOWN
    
    def _extract_parameter(self, issue: Dict[str, Any]) -> Optional[str]:
        """Extract vulnerable parameter from issue"""
        evidence = issue.get('evidence', '')
        if 'parameter=' in evidence:
            try:
                return evidence.split('parameter=')[1].split()[0].strip('"\'')
            except:
                pass
        return None
    
    def _estimate_cvss(self, severity: VulnerabilitySeverity) -> float:
        """Estimate CVSS score from severity"""
        score_map = {
            VulnerabilitySeverity.CRITICAL: 9.5,
            VulnerabilitySeverity.HIGH: 7.5,
            VulnerabilitySeverity.MEDIUM: 5.5,
            VulnerabilitySeverity.LOW: 2.5,
            VulnerabilitySeverity.INFO: 0.0
        }
        return score_map.get(severity, 0.0)
    
    def _extract_references(self, issue: Dict[str, Any]) -> List[str]:
        """Extract references from issue"""
        refs = []
        
        issue_type = issue.get('issue_type', {})
        
        if 'references_html' in issue_type:
            refs_html = issue_type['references_html']
        
        if 'cwe' in str(issue).lower():
            refs.append("CWE")
        
        return refs
    
    def get_active_scans(self) -> Dict[str, Dict[str, Any]]:
        """Get all active scans"""
        return self._active_scans.copy()
