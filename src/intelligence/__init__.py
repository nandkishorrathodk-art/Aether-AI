"""
Intelligence Module
Daily reports, trend analysis, and wealth tracking for Aether AI v0.9.0
"""

from src.intelligence.daily_reporter import DailyReporter
from src.intelligence.trend_analyzer import TrendAnalyzer
from src.intelligence.wealth_tracker import WealthTracker
from src.intelligence.database import IntelligenceDatabase

_daily_reporter = None
_trend_analyzer = None
_wealth_tracker = None
_intelligence_db = None


def get_intelligence_db() -> IntelligenceDatabase:
    global _intelligence_db
    if _intelligence_db is None:
        _intelligence_db = IntelligenceDatabase()
    return _intelligence_db


def get_daily_reporter() -> DailyReporter:
    global _daily_reporter
    if _daily_reporter is None:
        _daily_reporter = DailyReporter(db=get_intelligence_db())
    return _daily_reporter


def get_trend_analyzer() -> TrendAnalyzer:
    global _trend_analyzer
    if _trend_analyzer is None:
        _trend_analyzer = TrendAnalyzer()
    return _trend_analyzer


def get_wealth_tracker() -> WealthTracker:
    global _wealth_tracker
    if _wealth_tracker is None:
        _wealth_tracker = WealthTracker(db=get_intelligence_db())
    return _wealth_tracker


__all__ = [
    "DailyReporter",
    "TrendAnalyzer",
    "WealthTracker",
    "IntelligenceDatabase",
    "get_daily_reporter",
    "get_trend_analyzer",
    "get_wealth_tracker",
    "get_intelligence_db",
]
