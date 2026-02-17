"""
Unit Tests for Intelligence Module
Tests daily reporter, trend analyzer, wealth tracker, and database
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
import os

from src.intelligence.database import IntelligenceDatabase
from src.intelligence.daily_reporter import DailyReporter
from src.intelligence.trend_analyzer import TrendAnalyzer
from src.intelligence.wealth_tracker import WealthTracker


class TestIntelligenceDatabase:
    """Test IntelligenceDatabase functionality"""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = Path(f.name)
        
        db = IntelligenceDatabase(db_path)
        yield db
        
        db.close()
        
        try:
            if db_path.exists():
                os.unlink(db_path)
        except (PermissionError, OSError):
            pass
    
    def test_database_initialization(self, temp_db):
        """Test database tables are created"""
        assert temp_db.db_path.exists()
    
    def test_log_activity(self, temp_db):
        """Test activity logging"""
        activity_id = temp_db.log_activity(
            activity_type="bug_bounty",
            description="Scanned Apple.com",
            duration_minutes=60,
            metadata={"target": "apple.com"},
            success=True
        )
        
        assert activity_id > 0
        
        activities = temp_db.get_activities(limit=10)
        assert len(activities) == 1
        assert activities[0]["activity_type"] == "bug_bounty"
        assert activities[0]["duration_minutes"] == 60
    
    def test_add_earning(self, temp_db):
        """Test earning tracking"""
        earning_id = temp_db.add_earning(
            source="hackerone",
            amount_usd=500.0,
            program_name="Apple",
            vulnerability_type="XSS",
            severity="medium",
            status="pending"
        )
        
        assert earning_id > 0
        
        earnings = temp_db.get_earnings(limit=10)
        assert len(earnings) == 1
        assert earnings[0]["amount_usd"] == 500.0
        assert earnings[0]["program_name"] == "Apple"
    
    def test_update_earning_status(self, temp_db):
        """Test updating earning status"""
        earning_id = temp_db.add_earning(
            source="bugcrowd",
            amount_usd=1000.0,
            status="pending"
        )
        
        success = temp_db.update_earning_status(
            earning_id=earning_id,
            status="paid",
            paid_at=datetime.now()
        )
        
        assert success is True
        
        earnings = temp_db.get_earnings(limit=10)
        assert earnings[0]["status"] == "paid"
        assert earnings[0]["paid_at"] is not None
    
    def test_get_earnings_stats(self, temp_db):
        """Test earnings statistics"""
        temp_db.add_earning("hackerone", 500.0, status="pending")
        temp_db.add_earning("bugcrowd", 1000.0, status="paid")
        temp_db.add_earning("immunefi", 2000.0, status="paid")
        
        stats = temp_db.get_earnings_stats()
        
        assert stats["total_amount"] == 3500.0
        assert stats["total_reports"] == 3
        assert "pending" in stats["by_status"]
        assert "paid" in stats["by_status"]
    
    def test_save_and_get_daily_summary(self, temp_db):
        """Test daily summary persistence"""
        date = "2026-02-17"
        
        summary_id = temp_db.save_daily_summary(
            date=date,
            total_activities=10,
            total_time_minutes=300,
            achievements=["Completed 5 scans"],
            suggestions=["Try harder targets"],
            total_earnings=500.0,
            report_text="Test report"
        )
        
        assert summary_id > 0
        
        summary = temp_db.get_daily_summary(date)
        
        assert summary is not None
        assert summary["total_activities"] == 10
        assert summary["total_time_minutes"] == 300
        assert len(summary["achievements"]) == 1


class TestDailyReporter:
    """Test DailyReporter functionality"""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database"""
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
    def reporter(self, temp_db):
        """Create a reporter with temp database"""
        return DailyReporter(db=temp_db)
    
    def test_generate_daily_report_empty(self, reporter, temp_db):
        """Test report generation with no activities"""
        report = reporter.generate_daily_report()
        
        assert report.total_activities == 0
        assert report.total_time_minutes == 0
        assert report.productivity_score >= 0
    
    def test_generate_daily_report_with_activities(self, reporter, temp_db):
        """Test report generation with activities"""
        today = datetime.now()
        
        temp_db.log_activity(
            "bug_bounty",
            "Scanned target",
            duration_minutes=120,
            success=True
        )
        temp_db.log_activity(
            "learning",
            "Studied XSS",
            duration_minutes=60,
            success=True
        )
        
        report = reporter.generate_daily_report(today)
        
        assert report.total_activities == 2
        assert report.total_time_minutes == 180
        assert "bug_bounty" in report.activities_breakdown
        assert "learning" in report.activities_breakdown
    
    def test_report_with_earnings(self, reporter, temp_db):
        """Test report including earnings"""
        today = datetime.now()
        
        temp_db.add_earning("hackerone", 500.0, status="paid")
        temp_db.add_earning("bugcrowd", 1000.0, status="pending")
        
        report = reporter.generate_daily_report(today)
        
        assert report.earnings_summary["total_earned"] == 1500.0
        assert report.earnings_summary["pending_count"] == 1
        assert report.earnings_summary["paid_count"] == 1
    
    def test_report_text_generation(self, reporter, temp_db):
        """Test report text formatting"""
        temp_db.log_activity("bug_bounty", "Test", 60, success=True)
        
        report = reporter.generate_daily_report()
        report_text = report.to_text()
        
        assert "Daily Report" in report_text
        assert "Total Time:" in report_text
        assert "Productivity Score:" in report_text
    
    def test_weekly_summary(self, reporter, temp_db):
        """Test weekly summary generation"""
        for i in range(5):
            temp_db.log_activity(
                "bug_bounty",
                f"Activity {i}",
                duration_minutes=60
            )
        
        summary = reporter.get_weekly_summary()
        
        assert summary["total_activities"] == 5
        assert summary["period"] == "last_7_days"
        assert "start_date" in summary
        assert "end_date" in summary
    
    def test_monthly_summary(self, reporter, temp_db):
        """Test monthly summary generation"""
        for i in range(10):
            temp_db.log_activity(
                "learning",
                f"Activity {i}",
                duration_minutes=30
            )
        
        summary = reporter.get_monthly_summary()
        
        assert summary["total_activities"] == 10
        assert summary["period"] == "last_30_days"


@pytest.mark.asyncio
class TestTrendAnalyzer:
    """Test TrendAnalyzer functionality"""
    
    @pytest.fixture
    def analyzer(self):
        """Create a trend analyzer"""
        return TrendAnalyzer()
    
    async def test_analyze_bug_bounty_trends(self, analyzer):
        """Test bug bounty trend analysis"""
        trends = await analyzer.analyze_bug_bounty_trends()
        
        assert trends.category == "bug_bounty"
        assert len(trends.trends) > 0
        assert any(t["program"] == "Apple Security Bounty" for t in trends.trends)
        assert trends.analysis is not None
    
    async def test_analyze_youtube_trends(self, analyzer):
        """Test YouTube trend analysis"""
        trends = await analyzer.analyze_youtube_trends()
        
        assert trends.category == "youtube"
        assert len(trends.trends) > 0
        
        for trend in trends.trends:
            assert "niche" in trend
            assert "cpm_range" in trend
            assert len(trend["cpm_range"]) == 2
    
    async def test_analyze_tech_job_trends(self, analyzer):
        """Test tech job market analysis"""
        trends = await analyzer.analyze_tech_job_trends()
        
        assert trends.category == "tech_jobs"
        assert len(trends.trends) > 0
        
        for trend in trends.trends:
            assert "role" in trend
            assert "avg_salary_usd" in trend
            assert "required_skills" in trend
    
    async def test_get_all_trends(self, analyzer):
        """Test getting all trends at once"""
        all_trends = await analyzer.get_all_trends()
        
        assert "bug_bounty" in all_trends
        assert "youtube" in all_trends
        assert "tech_jobs" in all_trends
        assert "generated_at" in all_trends
    
    async def test_trend_caching(self, analyzer):
        """Test trend data caching"""
        trends1 = await analyzer.analyze_bug_bounty_trends()
        trends2 = await analyzer.analyze_bug_bounty_trends()
        
        assert trends1.updated_at == trends2.updated_at
        
        analyzer.clear_cache()
        
        assert "bug_bounty" not in analyzer.cache


class TestWealthTracker:
    """Test WealthTracker functionality"""
    
    @pytest.fixture
    def temp_db(self):
        """Create a temporary database"""
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
    def tracker(self, temp_db):
        """Create a wealth tracker with temp database"""
        return WealthTracker(db=temp_db)
    
    def test_add_earning(self, tracker):
        """Test adding earnings"""
        earning_id = tracker.add_earning(
            source="hackerone",
            amount_usd=1000.0,
            program_name="Apple",
            severity="high"
        )
        
        assert earning_id > 0
    
    def test_get_wealth_stats(self, tracker):
        """Test wealth statistics calculation"""
        tracker.add_earning("hackerone", 500.0, status="pending")
        tracker.add_earning("bugcrowd", 1000.0, status="paid")
        tracker.add_earning("immunefi", 2000.0, status="paid")
        
        stats = tracker.get_wealth_stats()
        
        assert stats.total_earned == 3500.0
        assert stats.pending_amount == 500.0
        assert stats.paid_amount == 3000.0
        assert stats.total_reports == 3
    
    def test_monthly_breakdown(self, tracker):
        """Test monthly earnings breakdown"""
        tracker.add_earning("hackerone", 1000.0)
        tracker.add_earning("bugcrowd", 500.0)
        
        breakdown = tracker.get_monthly_breakdown()
        
        assert isinstance(breakdown, dict)
        assert len(breakdown) > 0
    
    def test_payout_prediction(self, tracker):
        """Test payout prediction"""
        tracker.add_earning("hackerone", 1000.0, status="paid")
        tracker.add_earning("bugcrowd", 500.0, status="pending")
        
        prediction = tracker.predict_next_payout()
        
        assert "predicted_amount" in prediction
        assert "confidence" in prediction
        assert prediction["predicted_amount"] > 0
    
    def test_yearly_summary(self, tracker):
        """Test yearly earnings summary"""
        tracker.add_earning("hackerone", 1000.0, severity="high")
        tracker.add_earning("bugcrowd", 500.0, severity="medium")
        
        summary = tracker.get_yearly_summary()
        
        assert "year" in summary
        assert summary["total_earned"] == 1500.0
        assert summary["total_reports"] == 2
        assert "by_severity" in summary


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
