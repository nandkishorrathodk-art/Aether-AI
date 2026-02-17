"""
Wealth Tracker Module
Tracks bug bounty earnings, report submissions, and payout predictions
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path

from src.intelligence.database import IntelligenceDatabase

logger = logging.getLogger(__name__)


class WealthStats:
    """Data model for wealth statistics"""
    
    def __init__(
        self,
        total_earned: float,
        pending_amount: float,
        paid_amount: float,
        total_reports: int,
        pending_reports: int,
        paid_reports: int,
        by_program: Dict,
        by_severity: Dict,
        monthly_projection: float
    ):
        self.total_earned = total_earned
        self.pending_amount = pending_amount
        self.paid_amount = paid_amount
        self.total_reports = total_reports
        self.pending_reports = pending_reports
        self.paid_reports = paid_reports
        self.by_program = by_program
        self.by_severity = by_severity
        self.monthly_projection = monthly_projection
    
    def to_dict(self) -> Dict:
        return {
            "total_earned": self.total_earned,
            "pending_amount": self.pending_amount,
            "paid_amount": self.paid_amount,
            "total_reports": self.total_reports,
            "pending_reports": self.pending_reports,
            "paid_reports": self.paid_reports,
            "by_program": self.by_program,
            "by_severity": self.by_severity,
            "monthly_projection": self.monthly_projection,
            "average_payout": round(self.total_earned / max(self.total_reports, 1), 2)
        }


class WealthTracker:
    """Tracks earnings and predicts payouts"""
    
    def __init__(self, db: Optional[IntelligenceDatabase] = None):
        self.db = db or IntelligenceDatabase()
        logger.info("WealthTracker initialized")
    
    def add_earning(
        self,
        source: str,
        amount_usd: float,
        program_name: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: str = "pending",
        report_url: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> int:
        """Add a new earning record"""
        earning_id = self.db.add_earning(
            source=source,
            amount_usd=amount_usd,
            program_name=program_name,
            vulnerability_type=vulnerability_type,
            severity=severity,
            status=status,
            report_url=report_url,
            submitted_at=datetime.now(),
            metadata=metadata
        )
        
        logger.info(f"Added earning: ${amount_usd} from {program_name or source}")
        return earning_id
    
    def update_report_status(
        self,
        earning_id: int,
        status: str,
        paid_at: Optional[datetime] = None
    ) -> bool:
        """Update report submission status"""
        success = self.db.update_earning_status(earning_id, status, paid_at)
        
        if success:
            logger.info(f"Updated earning {earning_id} status to {status}")
        
        return success
    
    def get_wealth_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> WealthStats:
        """Get comprehensive wealth statistics"""
        logger.info("Calculating wealth statistics")
        
        earnings = self.db.get_earnings(
            start_date=start_date,
            end_date=end_date,
            limit=10000
        )
        
        total_earned = sum(e.get("amount_usd", 0) for e in earnings)
        
        pending_earnings = [e for e in earnings if e.get("status") == "pending"]
        pending_amount = sum(e.get("amount_usd", 0) for e in pending_earnings)
        pending_reports = len(pending_earnings)
        
        paid_earnings = [e for e in earnings if e.get("status") == "paid"]
        paid_amount = sum(e.get("amount_usd", 0) for e in paid_earnings)
        paid_reports = len(paid_earnings)
        
        by_program = self._group_by_program(earnings)
        by_severity = self._group_by_severity(earnings)
        
        monthly_projection = self._calculate_monthly_projection(earnings)
        
        stats = WealthStats(
            total_earned=total_earned,
            pending_amount=pending_amount,
            paid_amount=paid_amount,
            total_reports=len(earnings),
            pending_reports=pending_reports,
            paid_reports=paid_reports,
            by_program=by_program,
            by_severity=by_severity,
            monthly_projection=monthly_projection
        )
        
        return stats
    
    def get_earnings_history(
        self,
        limit: int = 50,
        source: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict]:
        """Get earnings history with filters"""
        return self.db.get_earnings(
            source=source,
            status=status,
            limit=limit
        )
    
    def get_monthly_breakdown(self) -> Dict:
        """Get monthly earnings breakdown"""
        logger.info("Generating monthly earnings breakdown")
        
        monthly_data = {}
        
        for i in range(12):
            month_start = datetime.now().replace(day=1) - timedelta(days=i * 30)
            month_end = month_start + timedelta(days=30)
            
            month_key = month_start.strftime("%Y-%m")
            
            earnings = self.db.get_earnings(
                start_date=month_start,
                end_date=month_end,
                limit=10000
            )
            
            total = sum(e.get("amount_usd", 0) for e in earnings)
            count = len(earnings)
            
            monthly_data[month_key] = {
                "total_earned": total,
                "report_count": count,
                "average_payout": round(total / max(count, 1), 2)
            }
        
        return monthly_data
    
    def predict_next_payout(self) -> Dict:
        """Predict next payout based on historical data"""
        logger.info("Predicting next payout")
        
        earnings = self.db.get_earnings(limit=100)
        
        if not earnings:
            return {
                "predicted_amount": 0.0,
                "confidence": 0.0,
                "based_on": "no_data",
                "estimated_date": None
            }
        
        recent_paid = [
            e for e in earnings 
            if e.get("status") == "paid" and e.get("paid_at")
        ]
        
        if not recent_paid:
            avg_amount = sum(e.get("amount_usd", 0) for e in earnings) / len(earnings)
            
            return {
                "predicted_amount": round(avg_amount, 2),
                "confidence": 0.5,
                "based_on": "average_submission",
                "estimated_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            }
        
        avg_payout = sum(e.get("amount_usd", 0) for e in recent_paid) / len(recent_paid)
        
        pending = [e for e in earnings if e.get("status") == "pending"]
        
        if pending:
            oldest_pending = min(
                pending,
                key=lambda e: datetime.fromisoformat(e.get("created_at", datetime.now().isoformat()))
            )
            
            submission_date = datetime.fromisoformat(oldest_pending.get("created_at"))
            estimated_date = submission_date + timedelta(days=45)
            
            return {
                "predicted_amount": round(avg_payout, 2),
                "confidence": 0.7,
                "based_on": "pending_report",
                "estimated_date": estimated_date.strftime("%Y-%m-%d"),
                "report_id": oldest_pending.get("id")
            }
        
        return {
            "predicted_amount": round(avg_payout, 2),
            "confidence": 0.6,
            "based_on": "historical_average",
            "estimated_date": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        }
    
    def get_yearly_summary(self) -> Dict:
        """Get yearly earnings summary"""
        start_of_year = datetime.now().replace(month=1, day=1, hour=0, minute=0, second=0)
        
        stats = self.get_wealth_stats(start_date=start_of_year)
        
        days_elapsed = (datetime.now() - start_of_year).days
        daily_average = stats.total_earned / max(days_elapsed, 1)
        
        return {
            "year": datetime.now().year,
            "total_earned": stats.total_earned,
            "total_reports": stats.total_reports,
            "paid_amount": stats.paid_amount,
            "pending_amount": stats.pending_amount,
            "daily_average": round(daily_average, 2),
            "monthly_average": round(daily_average * 30, 2),
            "by_program": stats.by_program,
            "by_severity": stats.by_severity
        }
    
    def _group_by_program(self, earnings: List[Dict]) -> Dict:
        """Group earnings by program"""
        by_program = {}
        
        for earning in earnings:
            program = earning.get("program_name", "Unknown")
            
            if program not in by_program:
                by_program[program] = {
                    "count": 0,
                    "total": 0.0,
                    "pending": 0,
                    "paid": 0
                }
            
            by_program[program]["count"] += 1
            by_program[program]["total"] += earning.get("amount_usd", 0)
            
            status = earning.get("status", "unknown")
            if status == "pending":
                by_program[program]["pending"] += 1
            elif status == "paid":
                by_program[program]["paid"] += 1
        
        return by_program
    
    def _group_by_severity(self, earnings: List[Dict]) -> Dict:
        """Group earnings by severity"""
        by_severity = {}
        
        for earning in earnings:
            severity = earning.get("severity", "unknown")
            
            if severity not in by_severity:
                by_severity[severity] = {
                    "count": 0,
                    "total": 0.0,
                    "average": 0.0
                }
            
            by_severity[severity]["count"] += 1
            by_severity[severity]["total"] += earning.get("amount_usd", 0)
        
        for severity in by_severity:
            count = by_severity[severity]["count"]
            total = by_severity[severity]["total"]
            by_severity[severity]["average"] = round(total / max(count, 1), 2)
        
        return by_severity
    
    def _calculate_monthly_projection(self, earnings: List[Dict]) -> float:
        """Calculate monthly earnings projection"""
        if not earnings:
            return 0.0
        
        now = datetime.now()
        thirty_days_ago = now - timedelta(days=30)
        
        recent_earnings = [
            e for e in earnings
            if datetime.fromisoformat(e.get("created_at", now.isoformat())) >= thirty_days_ago
        ]
        
        if not recent_earnings:
            return 0.0
        
        total_recent = sum(e.get("amount_usd", 0) for e in recent_earnings)
        
        days_in_period = (now - thirty_days_ago).days
        daily_average = total_recent / max(days_in_period, 1)
        
        monthly_projection = daily_average * 30
        
        return round(monthly_projection, 2)
