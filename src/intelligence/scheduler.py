"""
Intelligence Scheduler
Handles scheduled tasks like daily report generation
"""

import schedule
import time
import logging
import threading
from datetime import datetime
from typing import Optional

from src.intelligence import get_daily_reporter
from src.config import settings

logger = logging.getLogger(__name__)


class IntelligenceScheduler:
    """Manages scheduled intelligence tasks"""
    
    def __init__(self):
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        logger.info("IntelligenceScheduler initialized")
    
    def setup_schedules(self):
        """Setup all scheduled tasks"""
        schedule.clear()
        
        if settings.enable_daily_reports:
            report_time = settings.daily_report_time
            schedule.every().day.at(report_time).do(self._generate_daily_report)
            logger.info(f"Scheduled daily report generation at {report_time}")
        
        logger.info("All schedules configured")
    
    def _generate_daily_report(self):
        """Generate and save daily report"""
        try:
            logger.info("Starting scheduled daily report generation")
            
            reporter = get_daily_reporter()
            report = reporter.generate_daily_report()
            
            logger.info(f"Daily report generated: {report.date}")
            logger.info(f"Total activities: {report.total_activities}")
            logger.info(f"Productivity score: {report.productivity_score}/100")
            
            print("\n" + "=" * 80)
            print(report.to_text())
            print("=" * 80 + "\n")
            
        except Exception as e:
            logger.error(f"Failed to generate scheduled daily report: {e}")
    
    def start(self):
        """Start the scheduler in a background thread"""
        if self.running:
            logger.warning("Scheduler already running")
            return
        
        self.setup_schedules()
        self.running = True
        
        def run_scheduler():
            logger.info("Scheduler thread started")
            while self.running:
                schedule.run_pending()
                time.sleep(60)
            logger.info("Scheduler thread stopped")
        
        self.scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        self.scheduler_thread.start()
        
        logger.info("Intelligence scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        if not self.running:
            logger.warning("Scheduler not running")
            return
        
        self.running = False
        
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        
        schedule.clear()
        logger.info("Intelligence scheduler stopped")
    
    def run_now(self, task: str):
        """Manually trigger a scheduled task"""
        if task == "daily_report":
            self._generate_daily_report()
        else:
            logger.warning(f"Unknown task: {task}")
    
    def get_next_run_time(self) -> Optional[str]:
        """Get next scheduled run time"""
        jobs = schedule.get_jobs()
        
        if not jobs:
            return None
        
        next_job = min(jobs, key=lambda j: j.next_run)
        return next_job.next_run.strftime("%Y-%m-%d %H:%M:%S")
    
    def get_status(self) -> dict:
        """Get scheduler status"""
        return {
            "running": self.running,
            "jobs_count": len(schedule.get_jobs()),
            "next_run": self.get_next_run_time(),
            "daily_report_enabled": settings.enable_daily_reports,
            "daily_report_time": settings.daily_report_time
        }


_scheduler = None


def get_scheduler() -> IntelligenceScheduler:
    """Get global scheduler instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = IntelligenceScheduler()
    return _scheduler


def start_intelligence_scheduler():
    """Start the intelligence scheduler"""
    scheduler = get_scheduler()
    scheduler.start()


def stop_intelligence_scheduler():
    """Stop the intelligence scheduler"""
    scheduler = get_scheduler()
    scheduler.stop()
