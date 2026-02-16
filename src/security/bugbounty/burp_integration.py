"""
BurpSuite Integration

Integrates with BurpSuite Pro API for automated security scanning.
Requires BurpSuite Professional with REST API enabled.
"""

import requests
import time
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Scan types for BurpSuite"""
    CRAWL_AND_AUDIT = "CrawlAndAudit"
    CRAWL_ONLY = "CrawlOnly"
    AUDIT_ONLY = "AuditOnly"
    LIGHT_ACTIVE = "LightActive"
    DEEP_SCAN = "DeepScan"


class ScanStatus(Enum):
    """Scan status"""
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass
class ScanConfig:
    """Configuration for BurpSuite scan"""
    urls: List[str]
    scan_type: ScanType = ScanType.CRAWL_AND_AUDIT
    crawl_depth: int = 5
    max_crawl_time: int = 300  # seconds
    audit_checks: List[str] = None  # None = all checks
    
    # Advanced options
    follow_redirects: bool = True
    scan_authenticated: bool = False
    cookies: Dict[str, str] = None
    headers: Dict[str, str] = None
    
    # Scope
    include_scope: List[str] = None
    exclude_scope: List[str] = None
    
    # Performance
    max_concurrent_requests: int = 10
    throttle_delay: int = 0  # ms between requests
    
    def to_burp_config(self) -> Dict[str, Any]:
        """Convert to BurpSuite API format"""
        config = {
            "scope": {
                "include": [{"rule": url} for url in self.urls],
                "exclude": [{"rule": pattern} for pattern in (self.exclude_scope or [])]
            },
            "scan_configurations": [{
                "type": self.scan_type.value,
                "name": "Aether AI Scan"
            }]
        }
        
        if self.crawl_depth:
            config["crawl_optimization"] = {
                "max_depth": self.crawl_depth,
                "max_time": self.max_crawl_time
            }
        
        if self.audit_checks:
            config["audit_checks"] = self.audit_checks
            
        return config


class BurpSuiteClient:
    """
    Client for BurpSuite Pro REST API
    
    Enables automated scanning, issue retrieval, and scan management.
    """
    
    def __init__(
        self,
        api_url: str = "http://localhost:1337",
        api_key: Optional[str] = None
    ):
        """
        Initialize BurpSuite client
        
        Args:
            api_url: BurpSuite REST API URL (default: http://localhost:1337)
            api_key: API key for authentication (if enabled)
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers['Authorization'] = f'Bearer {api_key}'
    
    def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> requests.Response:
        """Make API request"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"BurpSuite API request failed: {e}")
            raise
    
    def get_version(self) -> Dict[str, str]:
        """Get BurpSuite version"""
        response = self._request('GET', '/v0.1/')
        return response.json()
    
    def start_scan(self, config: ScanConfig) -> str:
        """
        Start a new scan
        
        Args:
            config: Scan configuration
            
        Returns:
            Scan task ID
        """
        burp_config = config.to_burp_config()
        
        response = self._request(
            'POST',
            '/v0.1/scan',
            json=burp_config
        )
        
        scan_id = response.headers.get('Location', '').split('/')[-1]
        logger.info(f"Started BurpSuite scan: {scan_id}")
        
        return scan_id
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get scan status
        
        Args:
            scan_id: Scan task ID
            
        Returns:
            Scan status information
        """
        response = self._request('GET', f'/v0.1/scan/{scan_id}')
        return response.json()
    
    def get_scan_issues(self, scan_id: str) -> List[Dict[str, Any]]:
        """
        Get issues found in scan
        
        Args:
            scan_id: Scan task ID
            
        Returns:
            List of security issues
        """
        response = self._request('GET', f'/v0.1/scan/{scan_id}/issues')
        return response.json().get('issues', [])
    
    def wait_for_scan(
        self,
        scan_id: str,
        poll_interval: int = 10,
        timeout: int = 3600
    ) -> Dict[str, Any]:
        """
        Wait for scan to complete
        
        Args:
            scan_id: Scan task ID
            poll_interval: Seconds between status checks
            timeout: Maximum wait time in seconds
            
        Returns:
            Final scan status
        """
        start_time = time.time()
        
        while True:
            status = self.get_scan_status(scan_id)
            scan_status = status.get('scan_status')
            
            if scan_status in [ScanStatus.SUCCEEDED.value, ScanStatus.FAILED.value]:
                logger.info(f"Scan {scan_id} completed with status: {scan_status}")
                return status
            
            if time.time() - start_time > timeout:
                logger.warning(f"Scan {scan_id} timeout after {timeout}s")
                self.pause_scan(scan_id)
                raise TimeoutError(f"Scan timeout after {timeout}s")
            
            logger.debug(f"Scan {scan_id} status: {scan_status}, waiting...")
            time.sleep(poll_interval)
    
    def pause_scan(self, scan_id: str):
        """Pause a running scan"""
        self._request('PATCH', f'/v0.1/scan/{scan_id}', json={"scan_status": "paused"})
        logger.info(f"Paused scan: {scan_id}")
    
    def resume_scan(self, scan_id: str):
        """Resume a paused scan"""
        self._request('PATCH', f'/v0.1/scan/{scan_id}', json={"scan_status": "running"})
        logger.info(f"Resumed scan: {scan_id}")
    
    def delete_scan(self, scan_id: str):
        """Delete a scan"""
        self._request('DELETE', f'/v0.1/scan/{scan_id}')
        logger.info(f"Deleted scan: {scan_id}")
    
    def get_all_scans(self) -> List[Dict[str, Any]]:
        """Get all scans"""
        response = self._request('GET', '/v0.1/scan')
        return response.json().get('scans', [])
    
    def get_issue_definitions(self) -> List[Dict[str, Any]]:
        """Get all issue type definitions"""
        response = self._request('GET', '/v0.1/knowledge_base/issue_definitions')
        return response.json()
    
    def scan_and_wait(
        self,
        config: ScanConfig,
        poll_interval: int = 10,
        timeout: int = 3600
    ) -> tuple[str, List[Dict[str, Any]]]:
        """
        Start scan and wait for completion
        
        Args:
            config: Scan configuration
            poll_interval: Seconds between status checks
            timeout: Maximum wait time
            
        Returns:
            Tuple of (scan_id, issues)
        """
        scan_id = self.start_scan(config)
        
        try:
            self.wait_for_scan(scan_id, poll_interval, timeout)
            issues = self.get_scan_issues(scan_id)
            return scan_id, issues
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
    
    def export_scan_report(
        self,
        scan_id: str,
        report_type: str = "HTML",
        include_all_issues: bool = True
    ) -> bytes:
        """
        Export scan report
        
        Args:
            scan_id: Scan task ID
            report_type: Report format (HTML, XML, JSON)
            include_all_issues: Include all issues or only confirmed
            
        Returns:
            Report content as bytes
        """
        payload = {
            "report_type": report_type,
            "include_all_issues": include_all_issues
        }
        
        response = self._request(
            'POST',
            f'/v0.1/scan/{scan_id}/report',
            json=payload
        )
        
        return response.content


# Example usage and tests
if __name__ == "__main__":
    # Initialize client
    client = BurpSuiteClient(api_url="http://localhost:1337")
    
    # Check BurpSuite is running
    try:
        version = client.get_version()
        print(f"BurpSuite version: {version}")
    except Exception as e:
        print(f"Error: BurpSuite not accessible. Make sure it's running with REST API enabled.")
        print(f"Details: {e}")
        exit(1)
    
    # Example scan configuration
    config = ScanConfig(
        urls=["http://testphp.vulnweb.com/"],  # Test target
        scan_type=ScanType.CRAWL_AND_AUDIT,
        crawl_depth=3,
        max_crawl_time=300
    )
    
    # Start scan
    print(f"\nStarting scan of: {config.urls}")
    scan_id = client.start_scan(config)
    print(f"Scan ID: {scan_id}")
    
    # Wait for completion
    print("Waiting for scan to complete...")
    try:
        status = client.wait_for_scan(scan_id, poll_interval=10, timeout=600)
        print(f"Scan completed: {status}")
        
        # Get issues
        issues = client.get_scan_issues(scan_id)
        print(f"\nFound {len(issues)} issues:")
        
        for issue in issues[:5]:  # Show first 5
            print(f"  - {issue.get('issue_type', {}).get('name')}")
            print(f"    Severity: {issue.get('severity')}")
            print(f"    URL: {issue.get('origin')}")
            print()
        
    except TimeoutError:
        print("Scan timeout")
