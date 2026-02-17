"""
Scanner Manager

Orchestrates scanning workflow with intelligent configuration and monitoring.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from urllib.parse import urlparse

from src.bugbounty.burp_controller import BurpController
from src.bugbounty.models import (
    AutoScanResult, ScanStatus, Vulnerability,
    VulnerabilitySeverity
)
from src.security.bugbounty.scope_validator import ScopeValidator, Program
from src.config import settings

logger = logging.getLogger(__name__)


class ScannerManager:
    """
    Manages automated scanning workflow
    
    Features:
    - Target validation
    - Scan configuration optimization
    - Progress monitoring
    - Result aggregation
    - Error handling and retry
    """
    
    def __init__(
        self,
        burp_controller: Optional[BurpController] = None,
        scope_validator: Optional[ScopeValidator] = None
    ):
        """
        Initialize scanner manager
        
        Args:
            burp_controller: Burp Suite controller instance
            scope_validator: Scope validator for target checking
        """
        self.burp = burp_controller or BurpController()
        self.scope_validator = scope_validator
        
        self._active_sessions: Dict[str, AutoScanResult] = {}
        self._progress_callbacks: Dict[str, List[Callable]] = {}
        
        logger.info("ScannerManager initialized")
    
    def set_scope_validator(self, validator: ScopeValidator):
        """Set scope validator for target validation"""
        self.scope_validator = validator
    
    async def start_scan_session(
        self,
        target_url: str,
        scan_type: str = "CrawlAndAudit",
        validate_scope: bool = True,
        crawl_depth: int = 5,
        max_scan_time: int = 3600,
        progress_callback: Optional[Callable] = None
    ) -> AutoScanResult:
        """
        Start automated scan session
        
        Args:
            target_url: Target URL to scan
            scan_type: Type of scan (CrawlAndAudit, CrawlOnly, AuditOnly)
            validate_scope: Whether to validate target is in scope
            crawl_depth: Maximum crawl depth
            max_scan_time: Maximum scan time in seconds
            progress_callback: Optional callback for progress updates
            
        Returns:
            AutoScanResult with scan status and results
        """
        session_id = f"scan_{int(datetime.now().timestamp())}"
        
        result = AutoScanResult(
            scan_id=session_id,
            target_url=target_url,
            status=ScanStatus.IDLE
        )
        
        self._active_sessions[session_id] = result
        
        if progress_callback:
            self._progress_callbacks[session_id] = [progress_callback]
        
        try:
            result.status = ScanStatus.DETECTING
            await self._notify_progress(session_id, result)
            
            if not self.burp.is_burp_running():
                raise RuntimeError("Burp Suite is not running. Please start Burp Suite Professional with REST API enabled.")
            
            result.burp_running = True
            
            if validate_scope and self.scope_validator:
                result.status = ScanStatus.CONFIGURING
                await self._notify_progress(session_id, result)
                
                scope_check = self.scope_validator.validate_url(target_url)
                if not scope_check["in_scope"]:
                    raise ValueError(
                        f"Target URL is OUT OF SCOPE: {scope_check.get('warnings', 'Unknown reason')}"
                    )
                
                logger.info(f"Target {target_url} validated as in-scope")
            
            result.status = ScanStatus.SCANNING
            result.scan_started_at = datetime.now()
            await self._notify_progress(session_id, result)
            
            scan_id = await self.burp.start_scan_async(
                urls=[target_url],
                scan_type=scan_type,
                crawl_depth=crawl_depth,
                max_crawl_time=min(max_scan_time // 2, 600)
            )
            
            logger.info(f"Burp scan started: {scan_id}")
            
            async def scan_progress_callback(status):
                await self._notify_progress(session_id, result)
            
            final_status = await self.burp.wait_for_scan_async(
                scan_id=scan_id,
                poll_interval=10,
                timeout=max_scan_time,
                progress_callback=scan_progress_callback
            )
            
            result.status = ScanStatus.ANALYZING
            await self._notify_progress(session_id, result)
            
            issues = await self.burp.get_scan_issues_async(scan_id)
            logger.info(f"Found {len(issues)} issues in scan {scan_id}")
            
            vulnerabilities = []
            for issue in issues:
                try:
                    vuln = self.burp.parse_burp_issue_to_vulnerability(issue, scan_id)
                    vulnerabilities.append(vuln)
                except Exception as e:
                    logger.warning(f"Failed to parse issue: {e}")
            
            result.vulnerabilities = vulnerabilities
            result.update_counts()
            result.scan_completed_at = datetime.now()
            result.status = ScanStatus.COMPLETED
            
            logger.info(
                f"Scan completed: {result.total_issues_found} issues "
                f"(Critical: {result.critical_count}, High: {result.high_count}, "
                f"Medium: {result.medium_count}, Low: {result.low_count})"
            )
            
            await self._notify_progress(session_id, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Scan session failed: {e}", exc_info=True)
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
            await self._notify_progress(session_id, result)
            return result
    
    async def pause_scan_session(self, session_id: str) -> bool:
        """Pause active scan session"""
        if session_id not in self._active_sessions:
            return False
        
        result = self._active_sessions[session_id]
        
        if result.status != ScanStatus.SCANNING:
            return False
        
        try:
            await self.burp.pause_scan_async(result.scan_id)
            result.status = ScanStatus.PAUSED
            await self._notify_progress(session_id, result)
            return True
        except Exception as e:
            logger.error(f"Failed to pause scan: {e}")
            return False
    
    async def resume_scan_session(self, session_id: str) -> bool:
        """Resume paused scan session"""
        if session_id not in self._active_sessions:
            return False
        
        result = self._active_sessions[session_id]
        
        if result.status != ScanStatus.PAUSED:
            return False
        
        try:
            await self.burp.resume_scan_async(result.scan_id)
            result.status = ScanStatus.SCANNING
            await self._notify_progress(session_id, result)
            return True
        except Exception as e:
            logger.error(f"Failed to resume scan: {e}")
            return False
    
    async def stop_scan_session(self, session_id: str) -> bool:
        """Stop and cleanup scan session"""
        if session_id not in self._active_sessions:
            return False
        
        result = self._active_sessions[session_id]
        
        try:
            if result.scan_id:
                await self.burp.stop_scan_async(result.scan_id)
            
            result.status = ScanStatus.FAILED
            result.error_message = "Stopped by user"
            await self._notify_progress(session_id, result)
            
            del self._active_sessions[session_id]
            if session_id in self._progress_callbacks:
                del self._progress_callbacks[session_id]
            
            return True
        except Exception as e:
            logger.error(f"Failed to stop scan: {e}")
            return False
    
    def get_scan_result(self, session_id: str) -> Optional[AutoScanResult]:
        """Get scan result by session ID"""
        return self._active_sessions.get(session_id)
    
    def get_active_sessions(self) -> Dict[str, AutoScanResult]:
        """Get all active scan sessions"""
        return self._active_sessions.copy()
    
    def add_progress_callback(
        self,
        session_id: str,
        callback: Callable[[AutoScanResult], None]
    ):
        """Add progress callback for session"""
        if session_id not in self._progress_callbacks:
            self._progress_callbacks[session_id] = []
        self._progress_callbacks[session_id].append(callback)
    
    async def _notify_progress(self, session_id: str, result: AutoScanResult):
        """Notify all progress callbacks"""
        if session_id not in self._progress_callbacks:
            return
        
        for callback in self._progress_callbacks[session_id]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(result)
                else:
                    callback(result)
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")
    
    def filter_false_positives(
        self,
        vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Filter out likely false positives
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Filtered list
        """
        filtered = []
        
        for vuln in vulnerabilities:
            if vuln.confidence.lower() in ['tentative', 'firm']:
                if vuln.severity in [VulnerabilitySeverity.LOW, VulnerabilitySeverity.INFO]:
                    logger.debug(f"Filtered false positive: {vuln.title}")
                    continue
            
            filtered.append(vuln)
        
        return filtered
    
    def prioritize_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        program: str = "general"
    ) -> List[Vulnerability]:
        """
        Prioritize vulnerabilities by potential impact and payout
        
        Args:
            vulnerabilities: List of vulnerabilities
            program: Bug bounty program name
            
        Returns:
            Sorted list (highest priority first)
        """
        def priority_score(vuln: Vulnerability) -> float:
            severity_scores = {
                VulnerabilitySeverity.CRITICAL: 100,
                VulnerabilitySeverity.HIGH: 75,
                VulnerabilitySeverity.MEDIUM: 50,
                VulnerabilitySeverity.LOW: 25,
                VulnerabilitySeverity.INFO: 10
            }
            
            confidence_multipliers = {
                'certain': 1.0,
                'firm': 0.8,
                'tentative': 0.5
            }
            
            base_score = severity_scores.get(vuln.severity, 0)
            confidence = confidence_multipliers.get(vuln.confidence.lower(), 0.5)
            
            min_payout, max_payout = vuln.estimate_payout(program)
            payout_score = (min_payout + max_payout) / 2000
            
            return (base_score * confidence) + payout_score
        
        return sorted(vulnerabilities, key=priority_score, reverse=True)
