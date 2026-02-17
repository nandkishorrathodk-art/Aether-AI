"""
Intelligence Database Module
Handles activity logs and earnings tracking for Aether AI
"""

import sqlite3
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from pathlib import Path
import json
import logging

from src.config import settings

logger = logging.getLogger(__name__)


class IntelligenceDatabase:
    """Database handler for intelligence data"""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path("./data/intelligence.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = None
        self._init_database()
        logger.info(f"IntelligenceDatabase initialized at {self.db_path}")
    
    def close(self):
        """Close database connection"""
        if self._conn:
            self._conn.close()
            self._conn = None
    
    def _init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    activity_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    duration_minutes INTEGER DEFAULT 0,
                    metadata TEXT,
                    success BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_activity_type 
                ON activity_logs(activity_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at 
                ON activity_logs(created_at)
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS earnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    program_name TEXT,
                    vulnerability_type TEXT,
                    severity TEXT,
                    amount_usd REAL NOT NULL,
                    status TEXT DEFAULT 'pending',
                    report_url TEXT,
                    submitted_at TIMESTAMP,
                    paid_at TIMESTAMP,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_earnings_source 
                ON earnings(source)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_earnings_status 
                ON earnings(status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_earnings_created_at 
                ON earnings(created_at)
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS daily_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT UNIQUE NOT NULL,
                    total_activities INTEGER DEFAULT 0,
                    total_time_minutes INTEGER DEFAULT 0,
                    achievements TEXT,
                    suggestions TEXT,
                    total_earnings REAL DEFAULT 0.0,
                    report_text TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_summary_date 
                ON daily_summaries(date)
            """)
            
            conn.commit()
            logger.debug("Intelligence database tables initialized")
    
    def log_activity(
        self,
        activity_type: str,
        description: str,
        duration_minutes: int = 0,
        metadata: Optional[Dict] = None,
        success: bool = True
    ) -> int:
        """Log an activity"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO activity_logs 
                (activity_type, description, duration_minutes, metadata, success)
                VALUES (?, ?, ?, ?, ?)
            """, (
                activity_type,
                description,
                duration_minutes,
                json.dumps(metadata) if metadata else None,
                success
            ))
            activity_id = cursor.lastrowid
            conn.commit()
        
        logger.debug(f"Logged activity {activity_id}: {activity_type}")
        return activity_id
    
    def get_activities(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        activity_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get activity logs with optional filters"""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM activity_logs WHERE 1=1"
            params = []
            
            if start_date:
                query += " AND datetime(created_at) >= datetime(?)"
                params.append(start_date.isoformat())
            
            if end_date:
                query += " AND datetime(created_at) <= datetime(?)"
                params.append(end_date.isoformat())
            
            if activity_type:
                query += " AND activity_type = ?"
                params.append(activity_type)
            
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
        
        activities = []
        for row in rows:
            activity = dict(row)
            if activity.get("metadata"):
                activity["metadata"] = json.loads(activity["metadata"])
            activities.append(activity)
        
        return activities
    
    def add_earning(
        self,
        source: str,
        amount_usd: float,
        program_name: Optional[str] = None,
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: str = "pending",
        report_url: Optional[str] = None,
        submitted_at: Optional[datetime] = None,
        metadata: Optional[Dict] = None
    ) -> int:
        """Add an earning record"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO earnings 
                (source, program_name, vulnerability_type, severity, amount_usd, 
                 status, report_url, submitted_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                source,
                program_name,
                vulnerability_type,
                severity,
                amount_usd,
                status,
                report_url,
                submitted_at.isoformat() if submitted_at else None,
                json.dumps(metadata) if metadata else None
            ))
            earning_id = cursor.lastrowid
            conn.commit()
        
        logger.info(f"Added earning {earning_id}: ${amount_usd} from {source}")
        return earning_id
    
    def update_earning_status(
        self,
        earning_id: int,
        status: str,
        paid_at: Optional[datetime] = None
    ) -> bool:
        """Update earning status"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            if paid_at:
                cursor.execute("""
                    UPDATE earnings 
                    SET status = ?, paid_at = ?
                    WHERE id = ?
                """, (status, paid_at.isoformat(), earning_id))
            else:
                cursor.execute("""
                    UPDATE earnings 
                    SET status = ?
                    WHERE id = ?
                """, (status, earning_id))
            
            conn.commit()
            affected = cursor.rowcount
        
        return affected > 0
    
    def get_earnings(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        source: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get earnings with optional filters"""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM earnings WHERE 1=1"
            params = []
            
            if start_date:
                query += " AND datetime(created_at) >= datetime(?)"
                params.append(start_date.isoformat())
            
            if end_date:
                query += " AND datetime(created_at) <= datetime(?)"
                params.append(end_date.isoformat())
            
            if source:
                query += " AND source = ?"
                params.append(source)
            
            if status:
                query += " AND status = ?"
                params.append(status)
            
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
        
        earnings = []
        for row in rows:
            earning = dict(row)
            if earning.get("metadata"):
                earning["metadata"] = json.loads(earning["metadata"])
            earnings.append(earning)
        
        return earnings
    
    def get_earnings_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict:
        """Get earnings statistics"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            query = "SELECT status, COUNT(*) as count, SUM(amount_usd) as total FROM earnings WHERE 1=1"
            params = []
            
            if start_date:
                query += " AND datetime(created_at) >= datetime(?)"
                params.append(start_date.isoformat())
            
            if end_date:
                query += " AND datetime(created_at) <= datetime(?)"
                params.append(end_date.isoformat())
            
            query += " GROUP BY status"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
        
        stats = {
            "by_status": {},
            "total_amount": 0.0,
            "total_reports": 0
        }
        
        for row in rows:
            status, count, total = row
            stats["by_status"][status] = {
                "count": count,
                "total": total or 0.0
            }
            stats["total_amount"] += total or 0.0
            stats["total_reports"] += count
        
        return stats
    
    def save_daily_summary(
        self,
        date: str,
        total_activities: int,
        total_time_minutes: int,
        achievements: List[str],
        suggestions: List[str],
        total_earnings: float,
        report_text: str
    ) -> int:
        """Save daily summary"""
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO daily_summaries 
                (date, total_activities, total_time_minutes, achievements, 
                 suggestions, total_earnings, report_text)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                date,
                total_activities,
                total_time_minutes,
                json.dumps(achievements),
                json.dumps(suggestions),
                total_earnings,
                report_text
            ))
            summary_id = cursor.lastrowid
            conn.commit()
        
        logger.info(f"Saved daily summary for {date}")
        return summary_id
    
    def get_daily_summary(self, date: str) -> Optional[Dict]:
        """Get daily summary for a specific date"""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM daily_summaries WHERE date = ?
            """, (date,))
            row = cursor.fetchone()
        
        if row:
            summary = dict(row)
            summary["achievements"] = json.loads(summary["achievements"])
            summary["suggestions"] = json.loads(summary["suggestions"])
            return summary
        
        return None
