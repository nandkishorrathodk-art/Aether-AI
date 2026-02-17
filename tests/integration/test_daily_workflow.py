"""
Integration Tests for Daily Intelligence Workflow
Tests end-to-end daily reporting, trending, and earnings tracking
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime
import os

from src.intelligence.database import IntelligenceDatabase
from src.intelligence.daily_reporter import DailyReporter
from src.intelligence.trend_analyzer import TrendAnalyzer
from src.intelligence.wealth_tracker import WealthTracker


@pytest.fixture
def temp_db():
    """Create a temporary database for testing"""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        db_path = Path(f.name)
    
    db = IntelligenceDatabase(db_path)
    yield db
    
    db.close()
    
    try:
        if db_path.exists():
            os.unlink(db_path)
    except PermissionError:
        pass


@pytest.fixture
def intelligence_components(temp_db):
    """Create all intelligence components"""
    reporter = DailyReporter(db=temp_db)
    analyzer = TrendAnalyzer()
    tracker = WealthTracker(db=temp_db)
    
    return {
        "db": temp_db,
        "reporter": reporter,
        "analyzer": analyzer,
        "tracker": tracker
    }


class TestDailyWorkflow:
    """Test complete daily intelligence workflow"""
    
    def test_empty_day_workflow(self, intelligence_components):
        """Test workflow with no activities"""
        reporter = intelligence_components["reporter"]
        
        report = reporter.generate_daily_report()
        
        assert report.total_activities == 0
        assert len(report.suggestions_for_tomorrow) > 0
        assert report.productivity_score >= 0
    
    def test_typical_day_workflow(self, intelligence_components):
        """Test typical day with activities and earnings"""
        db = intelligence_components["db"]
        reporter = intelligence_components["reporter"]
        tracker = intelligence_components["tracker"]
        
        db.log_activity(
            "bug_bounty",
            "Scanned Apple.com for vulnerabilities",
            duration_minutes=120,
            metadata={"target": "apple.com", "findings": 2},
            success=True
        )
        
        db.log_activity(
            "learning",
            "Studied advanced XSS techniques",
            duration_minutes=60,
            success=True
        )
        
        db.log_activity(
            "youtube_content",
            "Created bug bounty tutorial video",
            duration_minutes=90,
            metadata={"video_title": "Finding XSS in 2026"},
            success=True
        )
        
        tracker.add_earning(
            source="hackerone",
            amount_usd=500.0,
            program_name="Apple",
            vulnerability_type="XSS",
            severity="medium",
            status="pending"
        )
        
        report = reporter.generate_daily_report()
        
        assert report.total_activities == 3
        assert report.total_time_minutes == 270
        assert "bug_bounty" in report.activities_breakdown
        assert "learning" in report.activities_breakdown
        assert report.earnings_summary["total_earned"] == 500.0
        assert report.productivity_score > 50
        
        report_text = report.to_text()
        assert "Daily Report" in report_text
        assert "bug_bounty" in report_text.lower()
    
    @pytest.mark.asyncio
    async def test_daily_planning_workflow(self, intelligence_components):
        """Test daily planning with trend analysis"""
        analyzer = intelligence_components["analyzer"]
        
        bug_bounty_trends = await analyzer.analyze_bug_bounty_trends()
        youtube_trends = await analyzer.analyze_youtube_trends()
        job_trends = await analyzer.analyze_tech_job_trends()
        
        assert len(bug_bounty_trends.trends) > 0
        assert len(youtube_trends.trends) > 0
        assert len(job_trends.trends) > 0
        
        high_value_programs = [
            t for t in bug_bounty_trends.trends
            if t.get("max_payout", 0) > 100000
        ]
        assert len(high_value_programs) > 0
        
        high_cpm_niches = [
            t for t in youtube_trends.trends
            if max(t.get("cpm_range", [0, 0])) > 15
        ]
        assert len(high_cpm_niches) > 0
    
    def test_earnings_tracking_workflow(self, intelligence_components):
        """Test complete earnings tracking workflow"""
        tracker = intelligence_components["tracker"]
        
        earning1_id = tracker.add_earning(
            source="hackerone",
            amount_usd=1000.0,
            program_name="Apple",
            vulnerability_type="SQLi",
            severity="critical",
            status="pending"
        )
        
        earning2_id = tracker.add_earning(
            source="bugcrowd",
            amount_usd=500.0,
            program_name="Google",
            vulnerability_type="XSS",
            severity="medium",
            status="paid"
        )
        
        stats = tracker.get_wealth_stats()
        
        assert stats.total_earned == 1500.0
        assert stats.pending_amount == 1000.0
        assert stats.paid_amount == 500.0
        assert stats.total_reports == 2
        
        tracker.update_report_status(earning1_id, "paid", datetime.now())
        
        updated_stats = tracker.get_wealth_stats()
        assert updated_stats.paid_amount == 1500.0
        assert updated_stats.pending_amount == 0.0
        
        prediction = tracker.predict_next_payout()
        assert prediction["predicted_amount"] > 0
        assert 0 <= prediction["confidence"] <= 1
    
    def test_weekly_summary_workflow(self, intelligence_components):
        """Test weekly summary generation"""
        db = intelligence_components["db"]
        reporter = intelligence_components["reporter"]
        
        for day in range(7):
            for _ in range(3):
                db.log_activity(
                    "bug_bounty",
                    f"Day {day} activity",
                    duration_minutes=60
                )
        
        weekly_summary = reporter.get_weekly_summary()
        
        assert weekly_summary["total_activities"] == 21
        assert weekly_summary["period"] == "last_7_days"
        assert weekly_summary["average_daily_activities"] == 3.0
    
    def test_monthly_earnings_workflow(self, intelligence_components):
        """Test monthly earnings tracking"""
        tracker = intelligence_components["tracker"]
        
        for i in range(5):
            tracker.add_earning(
                source="hackerone",
                amount_usd=1000.0 * (i + 1),
                status="paid" if i % 2 == 0 else "pending"
            )
        
        monthly_breakdown = tracker.get_monthly_breakdown()
        
        assert isinstance(monthly_breakdown, dict)
        assert len(monthly_breakdown) > 0
        
        yearly_summary = tracker.get_yearly_summary()
        
        assert yearly_summary["total_earned"] == 15000.0
        assert yearly_summary["total_reports"] == 5
    
    def test_productivity_scoring_workflow(self, intelligence_components):
        """Test productivity score calculation"""
        db = intelligence_components["db"]
        reporter = intelligence_components["reporter"]
        tracker = intelligence_components["tracker"]
        
        for _ in range(10):
            db.log_activity(
                "bug_bounty",
                "High productivity activity",
                duration_minutes=30,
                success=True
            )
        
        tracker.add_earning("hackerone", 2000.0)
        
        report = reporter.generate_daily_report()
        
        assert report.productivity_score > 70
        assert len(report.achievements) > 0
    
    @pytest.mark.asyncio
    async def test_complete_daily_cycle(self, intelligence_components):
        """Test complete daily intelligence cycle"""
        db = intelligence_components["db"]
        reporter = intelligence_components["reporter"]
        analyzer = intelligence_components["analyzer"]
        tracker = intelligence_components["tracker"]
        
        db.log_activity("bug_bounty", "Morning scan", 120, success=True)
        db.log_activity("learning", "Study session", 60, success=True)
        db.log_activity("youtube_content", "Video creation", 90, success=True)
        
        tracker.add_earning("hackerone", 750.0, severity="medium", status="pending")
        
        trends = await analyzer.get_all_trends()
        
        assert "bug_bounty" in trends
        assert "youtube" in trends
        assert "tech_jobs" in trends
        
        report = reporter.generate_daily_report()
        
        assert report.total_activities == 3
        assert report.earnings_summary["total_earned"] == 750.0
        
        stats = tracker.get_wealth_stats()
        
        assert stats.total_earned == 750.0
        
        report_dict = report.to_dict()
        assert "date" in report_dict
        assert "total_activities" in report_dict
        assert "achievements" in report_dict
        assert "suggestions_for_tomorrow" in report_dict
        
        assert len(report.suggestions_for_tomorrow) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
