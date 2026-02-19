"""
Auto Hunter

Main automated bug hunting workflow integrating all components.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from pathlib import Path

from src.bugbounty.burp_controller import BurpController
from src.bugbounty.scanner_manager import ScannerManager
from src.bugbounty.poc_generator import PoCGenerator
from src.bugbounty.report_builder import ReportBuilder
from src.bugbounty.voice_notifier import get_voice_notifier
from src.bugbounty.models import (
    AutoScanResult, ScanStatus, Vulnerability, BugReport,
    VulnerabilitySeverity
)
from src.monitoring.bridge import get_monitoring_bridge
from src.security.bugbounty.scope_validator import ScopeValidator, Program
from src.config import settings

logger = logging.getLogger(__name__)


class AutoHunter:
    """
    Automated Bug Hunting Orchestrator
    
    Features:
    - Detects Burp Suite automatically
    - Configures proxy and scans
    - Analyzes vulnerabilities with AI
    - Generates PoCs and reports
    - Integrates with monitoring system
    - Provides real-time updates
    
    Usage:
        hunter = AutoHunter()
        result = await hunter.start_auto_hunt("https://example.com")
    """
    
    def __init__(
        self,
        burp_controller: Optional[BurpController] = None,
        scanner_manager: Optional[ScannerManager] = None,
        poc_generator: Optional[PoCGenerator] = None,
        report_builder: Optional[ReportBuilder] = None,
        enable_voice: bool = False
    ):
        """
        Initialize AutoHunter
        
        Args:
            burp_controller: Burp Suite controller
            scanner_manager: Scanner manager
            poc_generator: PoC generator
            report_builder: Report builder
            enable_voice: Enable voice notifications (Hindi-English TTS)
        """
        self.burp = burp_controller or BurpController()
        self.scanner = scanner_manager or ScannerManager(burp_controller=self.burp)
        self.poc_gen = poc_generator or PoCGenerator()
        self.report_builder = report_builder or ReportBuilder()
        self.voice = get_voice_notifier(enable_voice=enable_voice)
        
        self.monitoring = get_monitoring_bridge()
        
        self._active_hunts: Dict[str, AutoScanResult] = {}
        self._status_callbacks: Dict[str, List[Callable]] = {}
        
        logger.info("AutoHunter initialized")
    
    async def start_auto_hunt(
        self,
        target_url: str,
        program: str = "general",
        scope_validator: Optional[ScopeValidator] = None,
        auto_poc: bool = True,
        auto_report: bool = True,
        report_formats: List[str] = ["markdown", "html", "json"],
        status_callback: Optional[Callable] = None
    ) -> AutoScanResult:
        """
        Start automated bug hunting session
        
        Args:
            target_url: Target URL to hunt
            program: Bug bounty program name
            scope_validator: Optional scope validator
            auto_poc: Automatically generate PoCs
            auto_report: Automatically generate reports
            report_formats: Report formats to generate
            status_callback: Optional callback for status updates
            
        Returns:
            AutoScanResult with findings
        """
        hunt_id = f"hunt_{int(datetime.now().timestamp())}"
        
        logger.info(f"Starting auto hunt {hunt_id} for {target_url}")
        
        # Voice: Announce hunt start
        await self.voice.announce_hunt_start(target_url)
        
        result = AutoScanResult(
            scan_id=hunt_id,
            target_url=target_url,
            status=ScanStatus.IDLE
        )
        
        self._active_hunts[hunt_id] = result
        
        if status_callback:
            self._status_callbacks[hunt_id] = [status_callback]
        
        try:
            result.status = ScanStatus.DETECTING
            await self._notify_status(hunt_id, result)
            
            burp_running = await self._detect_burp_suite()
            result.burp_running = burp_running
            
            if not burp_running:
                result.status = ScanStatus.FAILED
                result.error_message = "Burp Suite not detected. Please start Burp Suite Professional with REST API enabled."
                logger.error(result.error_message)
                
                # Voice: Burp not found
                await self.voice.announce_burp_not_found()
                
                await self._notify_status(hunt_id, result)
                return result
            
            logger.info("Burp Suite detected and running")
            
            if scope_validator:
                self.scanner.set_scope_validator(scope_validator)
            
            result.status = ScanStatus.SCANNING
            await self._notify_status(hunt_id, result)
            
            async def scan_progress(scan_result: AutoScanResult):
                result.status = scan_result.status
                result.vulnerabilities = scan_result.vulnerabilities
                result.update_counts()
                await self._notify_status(hunt_id, result)
            
            scan_result = await self.scanner.start_scan_session(
                target_url=target_url,
                validate_scope=(scope_validator is not None),
                progress_callback=scan_progress
            )
            
            result.vulnerabilities = scan_result.vulnerabilities
            result.scan_started_at = scan_result.scan_started_at
            result.scan_completed_at = scan_result.scan_completed_at
            result.update_counts()
            
            if scan_result.status == ScanStatus.FAILED:
                result.status = ScanStatus.FAILED
                result.error_message = scan_result.error_message
                logger.error(f"Scan failed: {result.error_message}")
                await self._notify_status(hunt_id, result)
                return result
            
            logger.info(f"Scan completed: {result.total_issues_found} vulnerabilities found")
            
            # Voice: Announce bugs found
            if result.total_issues_found > 0:
                await self.voice.announce_multiple_bugs(
                    result.total_issues_found,
                    result.critical_count,
                    result.high_count
                )
            
            high_priority_vulns = self.scanner.prioritize_vulnerabilities(
                result.vulnerabilities,
                program=program
            )
            
            critical_high = [
                v for v in high_priority_vulns
                if v.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]
            ]
            
            # Voice: Announce each critical/high bug
            for vuln in critical_high[:3]:  # First 3 only
                await self.voice.announce_bug_found(vuln)
            
            if auto_poc and critical_high:
                result.status = ScanStatus.GENERATING_POC
                await self._notify_status(hunt_id, result)
                
                logger.info(f"Generating PoCs for {len(critical_high)} critical/high vulnerabilities")
                
                for vuln in critical_high[:5]:
                    try:
                        # Voice: Announce PoC generation
                        await self.voice.announce_poc_generation(vuln.type)
                        
                        poc = await self.poc_gen.generate_poc(
                            vulnerability=vuln,
                            include_waf_bypass=True,
                            safe_only=True
                        )
                        
                        if auto_report:
                            report = self.report_builder.build_report(
                                vulnerability=vuln,
                                poc=poc,
                                program=program
                            )
                            result.reports_generated.append(report)
                        
                        logger.info(f"Generated PoC for: {vuln.title}")
                        
                    except Exception as e:
                        logger.warning(f"Failed to generate PoC for {vuln.title}: {e}")
            
            if auto_report and result.reports_generated:
                result.status = ScanStatus.GENERATING_REPORT
                await self._notify_status(hunt_id, result)
                
                logger.info(f"Saving {len(result.reports_generated)} reports")
                
                for report in result.reports_generated:
                    try:
                        saved_files = self.report_builder.save_report(
                            report=report,
                            formats=report_formats
                        )
                        
                        for fmt, path in saved_files.items():
                            report.attachments.append(path)
                        
                        logger.info(f"Saved report: {report.title}")
                        
                    except Exception as e:
                        logger.warning(f"Failed to save report {report.title}: {e}")
            
            result.estimated_total_payout = sum(
                report.estimated_payout_max for report in result.reports_generated
            )
            
            # Voice: Reports ready
            if result.reports_generated:
                await self.voice.announce_report_ready("markdown, HTML, JSON")
                
                if result.estimated_total_payout > 0:
                    min_payout = sum(r.estimated_payout_min for r in result.reports_generated)
                    await self.voice.announce_payout_estimate(
                        int(min_payout),
                        int(result.estimated_total_payout)
                    )
            
            result.status = ScanStatus.COMPLETED
            await self._notify_status(hunt_id, result)
            
            # Voice: Celebrate success!
            if result.critical_count > 0 or result.high_count > 0:
                await self.voice.celebrate_success()
            
            logger.info(
                f"Auto hunt completed successfully!\n"
                f"  - Total vulnerabilities: {result.total_issues_found}\n"
                f"  - Critical: {result.critical_count}\n"
                f"  - High: {result.high_count}\n"
                f"  - Reports generated: {len(result.reports_generated)}\n"
                f"  - Estimated total payout: ${result.estimated_total_payout:,}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Auto hunt failed: {e}", exc_info=True)
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
            await self._notify_status(hunt_id, result)
            return result
    
    async def pause_hunt(self, hunt_id: str) -> bool:
        """Pause active hunt"""
        if hunt_id not in self._active_hunts:
            return False
        
        result = self._active_hunts[hunt_id]
        
        if result.status != ScanStatus.SCANNING:
            return False
        
        success = await self.scanner.pause_scan_session(result.scan_id)
        
        if success:
            result.status = ScanStatus.PAUSED
            await self._notify_status(hunt_id, result)
        
        return success
    
    async def resume_hunt(self, hunt_id: str) -> bool:
        """Resume paused hunt"""
        if hunt_id not in self._active_hunts:
            return False
        
        result = self._active_hunts[hunt_id]
        
        if result.status != ScanStatus.PAUSED:
            return False
        
        success = await self.scanner.resume_scan_session(result.scan_id)
        
        if success:
            result.status = ScanStatus.SCANNING
            await self._notify_status(hunt_id, result)
        
        return success
    
    async def stop_hunt(self, hunt_id: str) -> bool:
        """Stop and cleanup hunt"""
        if hunt_id not in self._active_hunts:
            return False
        
        result = self._active_hunts[hunt_id]
        
        success = await self.scanner.stop_scan_session(result.scan_id)
        
        if success:
            del self._active_hunts[hunt_id]
            if hunt_id in self._status_callbacks:
                del self._status_callbacks[hunt_id]
        
        return success
    
    def get_hunt_result(self, hunt_id: str) -> Optional[AutoScanResult]:
        """Get hunt result by ID"""
        return self._active_hunts.get(hunt_id)
    
    def get_active_hunts(self) -> Dict[str, AutoScanResult]:
        """Get all active hunts"""
        return self._active_hunts.copy()
    
    def add_status_callback(
        self,
        hunt_id: str,
        callback: Callable[[AutoScanResult], None]
    ):
        """Add status callback for hunt"""
        if hunt_id not in self._status_callbacks:
            self._status_callbacks[hunt_id] = []
        self._status_callbacks[hunt_id].append(callback)
    
    async def _detect_burp_suite(self) -> bool:
        """
        Detect if Burp Suite is running
        
        Checks:
        1. Burp Suite API availability
        2. Process detection via monitoring service
        
        Returns:
            True if Burp Suite is detected
        """
        if self.burp.is_burp_running():
            logger.info("Burp Suite API is accessible")
            return True
        
        try:
            app_check = await self.monitoring.check_app("burp")
            if app_check:
                logger.info("Burp Suite process detected by monitoring service")
                return True
        except Exception as e:
            logger.debug(f"Monitoring check failed: {e}")
        
        logger.warning("Burp Suite not detected")
        return False
    
    async def _notify_status(self, hunt_id: str, result: AutoScanResult):
        """Notify all status callbacks"""
        if hunt_id not in self._status_callbacks:
            return
        
        for callback in self._status_callbacks[hunt_id]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(result)
                else:
                    callback(result)
            except Exception as e:
                logger.warning(f"Status callback failed: {e}")
    
    def generate_summary(self, result: AutoScanResult) -> str:
        """
        Generate human-readable summary
        
        Args:
            result: Scan result
            
        Returns:
            Formatted summary string
        """
        if result.status == ScanStatus.FAILED:
            return f"❌ Hunt failed: {result.error_message}"
        
        if result.status == ScanStatus.COMPLETED:
            summary = f"""✅ Auto Hunt Completed Successfully!

🎯 Target: {result.target_url}
⏱️ Duration: {(result.scan_completed_at - result.scan_started_at).total_seconds() / 60:.1f} minutes

📊 Vulnerabilities Found:
  🔴 Critical: {result.critical_count}
  🟠 High: {result.high_count}
  🟡 Medium: {result.medium_count}
  🔵 Low: {result.low_count}
  ⚪ Info: {result.info_count}
  
📝 Reports Generated: {len(result.reports_generated)}
💰 Estimated Total Payout: ${result.estimated_total_payout:,}

"""
            
            if result.reports_generated:
                summary += "🎁 Top Findings:\n"
                for i, report in enumerate(result.reports_generated[:3], 1):
                    summary += f"  {i}. {report.title} (${report.estimated_payout_min:,}-${report.estimated_payout_max:,})\n"
            
            return summary
        
        return f"🔄 Hunt in progress: {result.status.value}"
