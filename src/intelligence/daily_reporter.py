"""
Daily Reporter Module
Generates comprehensive daily activity summaries and reports
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

from src.intelligence.database import IntelligenceDatabase
from src.config import settings

logger = logging.getLogger(__name__)


class DailyReport:
    """Data model for daily report"""
    
    def __init__(
        self,
        date: str,
        total_activities: int,
        total_time_minutes: int,
        activities_breakdown: Dict,
        achievements: List[str],
        earnings_summary: Dict,
        suggestions_for_tomorrow: List[str],
        productivity_score: float
    ):
        self.date = date
        self.total_activities = total_activities
        self.total_time_minutes = total_time_minutes
        self.activities_breakdown = activities_breakdown
        self.achievements = achievements
        self.earnings_summary = earnings_summary
        self.suggestions_for_tomorrow = suggestions_for_tomorrow
        self.productivity_score = productivity_score
    
    def to_dict(self) -> Dict:
        return {
            "date": self.date,
            "total_activities": self.total_activities,
            "total_time_hours": round(self.total_time_minutes / 60, 2),
            "total_time_minutes": self.total_time_minutes,
            "activities_breakdown": self.activities_breakdown,
            "achievements": self.achievements,
            "earnings_summary": self.earnings_summary,
            "suggestions_for_tomorrow": self.suggestions_for_tomorrow,
            "productivity_score": self.productivity_score
        }
    
    def to_text(self) -> str:
        """Generate human-readable report text"""
        lines = []
        lines.append(f"📊 Daily Report - {self.date}")
        lines.append("=" * 60)
        lines.append("")
        
        hours = self.total_time_minutes // 60
        minutes = self.total_time_minutes % 60
        lines.append(f"⏱️ Total Time: {hours}h {minutes}m")
        lines.append(f"📝 Total Activities: {self.total_activities}")
        lines.append(f"🎯 Productivity Score: {self.productivity_score}/100")
        lines.append("")
        
        if self.activities_breakdown:
            lines.append("📋 Activities Breakdown:")
            for activity_type, stats in self.activities_breakdown.items():
                lines.append(f"  • {activity_type}: {stats['count']} activities, {stats['time_minutes']}m")
            lines.append("")
        
        if self.achievements:
            lines.append("🏆 Achievements:")
            for achievement in self.achievements:
                lines.append(f"  ✓ {achievement}")
            lines.append("")
        
        if self.earnings_summary:
            total = self.earnings_summary.get("total_earned", 0)
            pending = self.earnings_summary.get("pending_count", 0)
            paid = self.earnings_summary.get("paid_count", 0)
            
            lines.append("💰 Earnings Summary:")
            lines.append(f"  • Total Earned: ${total:.2f}")
            lines.append(f"  • Pending Reports: {pending}")
            lines.append(f"  • Paid Reports: {paid}")
            lines.append("")
        
        if self.suggestions_for_tomorrow:
            lines.append("💡 Suggestions for Tomorrow:")
            for suggestion in self.suggestions_for_tomorrow:
                lines.append(f"  → {suggestion}")
            lines.append("")
        
        lines.append("=" * 60)
        lines.append("Keep up the great work! 🚀")
        
        return "\n".join(lines)


class DailyReporter:
    """Generates and manages daily reports"""
    
    def __init__(self, db: Optional[IntelligenceDatabase] = None):
        self.db = db or IntelligenceDatabase()
        logger.info("DailyReporter initialized")
    
    def generate_daily_report(
        self,
        date: Optional[datetime] = None
    ) -> DailyReport:
        """Generate comprehensive daily report"""
        if date is None:
            date = datetime.now()
        
        date_str = date.strftime("%Y-%m-%d")
        logger.info(f"Generating daily report for {date_str}")
        
        start_of_day = datetime.combine(date.date(), datetime.min.time())
        end_of_day = start_of_day + timedelta(days=1, seconds=-1)
        
        activities = self.db.get_activities(
            start_date=start_of_day,
            end_date=end_of_day,
            limit=1000
        )
        
        earnings = self.db.get_earnings(
            start_date=start_of_day,
            end_date=end_of_day,
            limit=1000
        )
        
        activities_breakdown = self._analyze_activities(activities)
        achievements = self._extract_achievements(activities)
        earnings_summary = self._summarize_earnings(earnings)
        suggestions = self._generate_suggestions(activities, earnings)
        productivity_score = self._calculate_productivity_score(activities, earnings)
        
        total_activities = len(activities)
        total_time = sum(a.get("duration_minutes", 0) for a in activities)
        
        report = DailyReport(
            date=date_str,
            total_activities=total_activities,
            total_time_minutes=total_time,
            activities_breakdown=activities_breakdown,
            achievements=achievements,
            earnings_summary=earnings_summary,
            suggestions_for_tomorrow=suggestions,
            productivity_score=productivity_score
        )
        
        report_text = report.to_text()
        
        total_earnings = earnings_summary.get("total_earned", 0.0)
        self.db.save_daily_summary(
            date=date_str,
            total_activities=total_activities,
            total_time_minutes=total_time,
            achievements=achievements,
            suggestions=suggestions,
            total_earnings=total_earnings,
            report_text=report_text
        )
        
        if settings.daily_report_path:
            self._save_report_to_file(report, settings.daily_report_path)
        
        logger.info(f"Daily report generated successfully for {date_str}")
        return report
    
    def _analyze_activities(self, activities: List[Dict]) -> Dict:
        """Analyze activities by type"""
        breakdown = {}
        
        for activity in activities:
            activity_type = activity.get("activity_type", "other")
            
            if activity_type not in breakdown:
                breakdown[activity_type] = {
                    "count": 0,
                    "time_minutes": 0,
                    "success_rate": []
                }
            
            breakdown[activity_type]["count"] += 1
            breakdown[activity_type]["time_minutes"] += activity.get("duration_minutes", 0)
            breakdown[activity_type]["success_rate"].append(activity.get("success", True))
        
        for activity_type in breakdown:
            success_list = breakdown[activity_type]["success_rate"]
            breakdown[activity_type]["success_rate"] = (
                sum(success_list) / len(success_list) * 100
                if success_list else 0
            )
        
        return breakdown
    
    def _extract_achievements(self, activities: List[Dict]) -> List[str]:
        """Extract notable achievements from activities"""
        achievements = []
        
        activity_types = {}
        for activity in activities:
            atype = activity.get("activity_type", "")
            activity_types[atype] = activity_types.get(atype, 0) + 1
        
        for atype, count in activity_types.items():
            if count >= 5:
                achievements.append(f"Completed {count} {atype} activities")
        
        total_time = sum(a.get("duration_minutes", 0) for a in activities)
        if total_time >= 240:
            hours = total_time // 60
            achievements.append(f"Worked for {hours}+ hours")
        
        successful = [a for a in activities if a.get("success", True)]
        if len(successful) == len(activities) and len(activities) > 0:
            achievements.append(f"100% success rate on all {len(activities)} activities")
        
        for activity in activities:
            metadata = activity.get("metadata", {})
            if metadata and metadata.get("achievement"):
                achievements.append(metadata["achievement"])
        
        return achievements[:10]
    
    def _summarize_earnings(self, earnings: List[Dict]) -> Dict:
        """Summarize earnings data"""
        if not earnings:
            return {
                "total_earned": 0.0,
                "pending_count": 0,
                "paid_count": 0,
                "by_source": {}
            }
        
        total_earned = sum(e.get("amount_usd", 0) for e in earnings)
        pending_count = sum(1 for e in earnings if e.get("status") == "pending")
        paid_count = sum(1 for e in earnings if e.get("status") == "paid")
        
        by_source = {}
        for earning in earnings:
            source = earning.get("source", "unknown")
            if source not in by_source:
                by_source[source] = {"count": 0, "total": 0.0}
            
            by_source[source]["count"] += 1
            by_source[source]["total"] += earning.get("amount_usd", 0)
        
        return {
            "total_earned": total_earned,
            "pending_count": pending_count,
            "paid_count": paid_count,
            "by_source": by_source
        }
    
    def _generate_suggestions(
        self,
        activities: List[Dict],
        earnings: List[Dict]
    ) -> List[str]:
        """Generate suggestions for tomorrow based on today's data"""
        suggestions = []
        
        if not activities:
            suggestions.append("Start logging your activities to get better insights")
            suggestions.append("Try bug bounty hunting or YouTube content creation")
            return suggestions
        
        total_time = sum(a.get("duration_minutes", 0) for a in activities)
        if total_time < 120:
            suggestions.append("Consider spending more time on productive activities (target: 2+ hours)")
        elif total_time >= 240:
            suggestions.append("Great work today! Maintain this productivity tomorrow")
        
        activity_types = set(a.get("activity_type") for a in activities)
        if "bug_bounty" not in activity_types:
            suggestions.append("Try bug bounty hunting - high earning potential")
        
        if "learning" not in activity_types:
            suggestions.append("Dedicate time to learning new skills")
        
        if not earnings:
            suggestions.append("Focus on monetizable activities like bug bounties")
        else:
            suggestions.append("Keep up the bug bounty submissions!")
        
        failed_activities = [a for a in activities if not a.get("success", True)]
        if len(failed_activities) > len(activities) * 0.3:
            suggestions.append("Review failed activities and improve approach")
        
        if len(suggestions) == 0:
            suggestions.append("Continue your excellent work tomorrow!")
        
        return suggestions[:5]
    
    def _calculate_productivity_score(
        self,
        activities: List[Dict],
        earnings: List[Dict]
    ) -> float:
        """Calculate productivity score (0-100)"""
        score = 0.0
        
        if activities:
            score += min(len(activities) * 5, 30)
        
        total_time = sum(a.get("duration_minutes", 0) for a in activities)
        score += min(total_time / 10, 30)
        
        if activities:
            success_rate = sum(1 for a in activities if a.get("success", True)) / len(activities)
            score += success_rate * 20
        
        if earnings:
            score += min(len(earnings) * 5, 20)
        
        return min(round(score, 2), 100.0)
    
    def _save_report_to_file(self, report: DailyReport, report_dir: Path):
        """Save report to file"""
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
            
            filename = f"daily_report_{report.date}.txt"
            filepath = report_dir / filename
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report.to_text())
            
            logger.info(f"Saved report to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save report to file: {e}")
    
    def get_weekly_summary(self) -> Dict:
        """Get weekly summary of activities and earnings"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        
        activities = self.db.get_activities(
            start_date=start_date,
            end_date=end_date,
            limit=10000
        )
        
        earnings_stats = self.db.get_earnings_stats(
            start_date=start_date,
            end_date=end_date
        )
        
        total_time = sum(a.get("duration_minutes", 0) for a in activities)
        
        return {
            "period": "last_7_days",
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d"),
            "total_activities": len(activities),
            "total_time_hours": round(total_time / 60, 2),
            "earnings": earnings_stats,
            "average_daily_activities": round(len(activities) / 7, 1)
        }
    
    def get_monthly_summary(self) -> Dict:
        """Get monthly summary of activities and earnings"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        activities = self.db.get_activities(
            start_date=start_date,
            end_date=end_date,
            limit=100000
        )
        
        earnings_stats = self.db.get_earnings_stats(
            start_date=start_date,
            end_date=end_date
        )
        
        total_time = sum(a.get("duration_minutes", 0) for a in activities)
        
        return {
            "period": "last_30_days",
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d"),
            "total_activities": len(activities),
            "total_time_hours": round(total_time / 60, 2),
            "earnings": earnings_stats,
            "average_daily_activities": round(len(activities) / 30, 1)
        }
