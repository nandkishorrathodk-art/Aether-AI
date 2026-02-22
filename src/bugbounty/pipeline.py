"""
Bug Bounty Pipeline

Wires ALL existing disconnected bug bounty modules into one
unified autonomous hunting pipeline.

Existing modules it uses:
- auto_hunter.py     → Full hunt orchestration
- program_analyzer.py → Find best programs
- burp_controller.py  → BurpSuite API integration
- voice_notifier.py   → Voice announcements on bugs
- poc_generator.py    → Generate PoC for found bugs
- report_builder.py   → Format report for submission

Usage:
    pipeline = BugBountyPipeline(narrate_callback=aether.narrate)
    await pipeline.run_full_hunt("hackerone.com")
"""

import asyncio
import logging
import re
from typing import Optional, Callable, List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class BugBountyPipeline:
    """
    Unified Bug Bounty Hunting Pipeline.
    
    One call triggers:
    1. Program discovery on HackerOne/Bugcrowd
    2. Scope analysis
    3. BurpSuite scan launch  
    4. Voice alerts on bug finds
    5. PoC generation
    6. Report formatting
    """

    def __init__(self, narrate_callback: Optional[Callable] = None):
        """
        Args:
            narrate_callback: Function to speak updates (e.g., pipeline.narrate)
        """
        self.narrate = narrate_callback or (lambda text: logger.info(f"[NARRATE] {text}"))
        self.is_running = False
        self.bugs_found: List[Dict] = []
        self.current_program: Optional[str] = None
        self.current_target: Optional[str] = None

        # Lazy-load components
        self._voice_notifier = None
        self._burp_controller = None
        self._program_analyzer = None

        logger.info("🕷️ Bug Bounty Pipeline initialized")

    def _get_voice_notifier(self):
        if self._voice_notifier is None:
            try:
                from src.bugbounty.voice_notifier import get_voice_notifier
                self._voice_notifier = get_voice_notifier(enable_voice=True)
            except Exception as e:
                logger.warning(f"Voice notifier unavailable: {e}")
        return self._voice_notifier

    def _get_burp_controller(self):
        if self._burp_controller is None:
            try:
                from src.bugbounty.burp_controller import BurpController
                self._burp_controller = BurpController()
            except Exception as e:
                logger.warning(f"Burp controller unavailable: {e}")
        return self._burp_controller

    async def find_best_program(self) -> Optional[str]:
        """
        Search HackerOne/Bugcrowd for a high-paying bug bounty program.
        Returns the best program name.
        """
        self.narrate("HackerOne par search kar raha hoon best paying programs ke liye, sir...")

        try:
            from src.bugbounty.program_analyzer import ProgramAnalyzer
            analyzer = ProgramAnalyzer()
            programs = await analyzer.get_top_programs(
                platform="hackerone",
                min_payout=500,
                limit=5
            )
            if programs:
                best = programs[0]
                program_name = best.get("name", "Unknown Program")
                max_payout = best.get("max_payout", 0)
                self.narrate(
                    f"Boss! Ek achha program mila: {program_name}. "
                    f"Maximum payout ${max_payout}. Is par hunt karun?"
                )
                self.current_program = program_name
                return program_name
            else:
                self.narrate("Sir, abhi koi perfect programs nahi mile. Manual program dalo toh main scan karta hoon.")
                return None

        except Exception as e:
            logger.error(f"Program discovery failed: {e}")
            # Fallback narration
            self.narrate("Program search mein thodi dikkat aayi, sir. Seedha target URL do toh scan shuru karta hoon.")
            return None

    async def setup_and_scan(self, target_url: str) -> bool:
        """
        Setup BurpSuite and start scanning target.
        Uses existing burpsuite_tasks for the GUI workflow,
        then burp_controller for REST API monitoring.
        """
        self.current_target = target_url
        self.narrate(f"Target set kiya: {target_url}. BurpSuite scan shuru kar raha hoon, sir...")

        try:
            # Step 1: GUI-based BurpSuite Setup (opens app, sets proxy, enables intercept)
            from src.action.tasks.burpsuite_tasks import setup_burpsuite_and_scan

            async def _callback(progress):
                desc = progress.get("current_step_description", "")
                if desc and progress.get("status") == "step_start":
                    self.narrate(desc)

            burp_ready = await setup_burpsuite_and_scan(target_url, _callback)

            if not burp_ready:
                self.narrate("BurpSuite setup mein problem aai, sir. Manual check karo.")
                return False

            # Step 2: Try REST API scan if BurpSuite Pro is available
            burp = self._get_burp_controller()
            if burp and burp.is_burp_running():
                self.narrate(f"BurpSuite API connect hogaya! {target_url} ka automated scan shuru karta hoon...")
                try:
                    scan_id = await burp.start_scan_async(
                        urls=[target_url],
                        scan_type="CrawlAndAudit",
                        crawl_depth=3,
                        max_crawl_time=300
                    )
                    self.narrate(f"Scan chal raha hai, sir. Scan ID: {scan_id}. Bug milne par seedha bolunga!")
                    # Start monitoring in background
                    asyncio.create_task(self._monitor_scan(scan_id, burp))
                    return True
                except Exception as e:
                    logger.warning(f"REST API scan failed, continuing with GUI: {e}")

            self.narrate("BurpSuite intercept ON hai. Browser se target open karo aur requests capture hogi!")
            return True

        except Exception as e:
            logger.error(f"Scan setup failed: {e}")
            self.narrate(f"Setup mein error aaya, sir: {str(e)[:100]}")
            return False

    async def _monitor_scan(self, scan_id: str, burp_controller):
        """Monitor BurpSuite scan and narrate findings in real-time"""
        voice = self._get_voice_notifier()

        async def _on_progress(status_data):
            progress_pct = status_data.get("scan_status", {}).get("crawl_requests_made", 0)
            endpoints = status_data.get("scan_status", {}).get("audit_queue_items_waiting", 0)
            if endpoints > 0 and progress_pct % 50 == 0:
                self.narrate(f"Scan chal raha hai... {progress_pct} requests bheje. {endpoints} endpoints mile.")
            if voice:
                await voice.announce_scan_progress(progress_pct, endpoints)

        final_status = await burp_controller.wait_for_scan_async(
            scan_id=scan_id,
            poll_interval=15,
            timeout=1800,
            progress_callback=_on_progress
        )

        # Get issues
        issues = await burp_controller.get_scan_issues_async(scan_id)
        await self._process_findings(issues, burp_controller)

    async def _process_findings(self, issues: List[Dict], burp_controller):
        """Process and announce vulnerabilities found"""
        voice = self._get_voice_notifier()

        if not issues:
            self.narrate("Sir, is target par abhi koi obvious vulnerability nahi mili. Deeper testing try karte hain?")
            return

        self.narrate(f"BOSS! {len(issues)} potential issues mile mere scan mein!")

        critical_bugs = []
        for issue in issues:
            vuln = burp_controller.parse_burp_issue_to_vulnerability(issue, "scan")
            self.bugs_found.append(vuln)

            severity = getattr(vuln, 'severity', None)
            if severity and str(severity).lower() in ("critical", "high"):
                critical_bugs.append(vuln)
                if voice:
                    await voice.announce_bug_found(vuln)
                bug_name = getattr(vuln, 'name', 'Unknown Bug')
                self.narrate(f"🚨 BOSS! Critical bug mila: {bug_name}! PoC generate karun?")

        if critical_bugs:
            await self._generate_poc_for_bugs(critical_bugs)

    async def _generate_poc_for_bugs(self, bugs: List):
        """Generate PoC and report for found bugs"""
        voice = self._get_voice_notifier()

        for bug in bugs[:3]:  # Max 3 PoCs at a time
            try:
                bug_type = str(getattr(bug, 'type', 'unknown'))
                self.narrate(f"PoC generate kar raha hoon {bug_type} ke liye...")

                if voice:
                    await voice.announce_poc_generation(bug_type)

                from src.bugbounty.poc_generator import PoCGenerator
                poc_gen = PoCGenerator()
                poc = await poc_gen.generate(bug)

                from src.bugbounty.report_builder import ReportBuilder
                report_builder = ReportBuilder()
                report = report_builder.build(bug, poc)

                self.narrate(f"Report ready hai, sir! {bug_type} ka PoC aur submission report ban gaya.")
                if voice:
                    await voice.announce_report_ready("markdown")

            except Exception as e:
                logger.error(f"PoC generation failed: {e}")
                self.narrate(f"PoC generation mein thodi dikkat aayi. Manual review karo, sir.")

    async def run_full_hunt(self, command: str = "") -> Dict[str, Any]:
        """
        Full autonomous bug hunting session.
        Called by God Mode when user says "bug bounty karo" or similar.
        """
        if self.is_running:
            self.narrate("Ek hunt already chal rahi hai, sir. Us ka wait karein ya stop karun?")
            return {"status": "already_running"}

        self.is_running = True
        self.bugs_found = []
        results = {}

        try:
            self.narrate("Bug bounty hunt shuru kar raha hoon, sir! Ek dum autonomous mode mein...")

            # Step 1: Find best program
            program = await self.find_best_program()

            if not program:
                # If no program found, use any provided URL from command
                url_match = re.search(r'https?://[^\s]+', command)
                if url_match:
                    self.current_target = url_match.group(0)
                    self.narrate(f"Command se target liya: {self.current_target}")

            # Step 2: Setup BurpSuite and scan
            if self.current_target:
                scan_success = await self.setup_and_scan(self.current_target)
                results["scan_started"] = scan_success
            else:
                self.narrate(
                    "Sir, target URL dijiye. Kaunsa website scan karein? "
                    "Ya HackerOne program ka naam batao."
                )
                results["needs_input"] = True

            results["bugs_found_so_far"] = len(self.bugs_found)
            return results

        except Exception as e:
            logger.error(f"Full hunt failed: {e}")
            self.narrate(f"Hunt mein error aaya, sir: {str(e)[:100]}")
            return {"status": "error", "error": str(e)}

        finally:
            self.is_running = False


# Global instance
_pipeline_instance: Optional[BugBountyPipeline] = None


def get_bug_bounty_pipeline(narrate_callback=None) -> BugBountyPipeline:
    """Get or create global bug bounty pipeline"""
    global _pipeline_instance
    if _pipeline_instance is None or narrate_callback:
        _pipeline_instance = BugBountyPipeline(narrate_callback=narrate_callback)
    return _pipeline_instance


logger.info("🕷️ Bug Bounty Pipeline module loaded - AUTONOMOUS HUNTING READY")
