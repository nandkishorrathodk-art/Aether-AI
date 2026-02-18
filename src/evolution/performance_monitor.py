"""
Performance Monitor - Track System Metrics

Monitors API response times, error rates, resource usage, and feature usage
to provide data for the Self-Improvement Engine.
"""

import os
import json
import time
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
from collections import defaultdict, deque

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PerformanceMonitor:
    """
    Monitors system performance and collects metrics for analysis
    """
    
    def __init__(self, metrics_file: str = "data/performance_metrics.json"):
        self.metrics_file = Path(metrics_file)
        self.metrics_file.parent.mkdir(parents=True, exist_ok=True)
        
        # In-memory metrics for current session
        self.response_times = deque(maxlen=1000)  # Last 1000 requests
        self.error_count = 0
        self.request_count = 0
        self.feature_usage = defaultdict(int)
        self.start_time = time.time()
        
        logger.info("Performance Monitor initialized")
    
    def record_request(self, endpoint: str, response_time: float, success: bool):
        """Record an API request"""
        self.request_count += 1
        self.response_times.append(response_time)
        
        if not success:
            self.error_count += 1
        
        # Track feature usage by endpoint
        self.feature_usage[endpoint] += 1
    
    def record_feature_usage(self, feature_name: str):
        """Record usage of a feature"""
        self.feature_usage[feature_name] += 1
    
    def get_current_metrics(self) -> Dict:
        """Get current session metrics"""
        process = psutil.Process()
        memory_info = process.memory_info()
        
        metrics = {
            "avg_response_time": sum(self.response_times) / len(self.response_times) if self.response_times else 0,
            "max_response_time": max(self.response_times) if self.response_times else 0,
            "min_response_time": min(self.response_times) if self.response_times else 0,
            "error_rate": self.error_count / self.request_count if self.request_count > 0 else 0,
            "total_requests": self.request_count,
            "total_errors": self.error_count,
            "memory_usage_mb": memory_info.rss / 1024 / 1024,  # MB
            "cpu_percent": process.cpu_percent(),
            "uptime_hours": (time.time() - self.start_time) / 3600,
            "feature_usage": dict(self.feature_usage),
            "timestamp": datetime.now().isoformat()
        }
        
        return metrics
    
    def save_metrics(self):
        """Save metrics to file"""
        try:
            metrics = self.get_current_metrics()
            
            # Load existing metrics
            historical_metrics = []
            if self.metrics_file.exists():
                try:
                    historical_metrics = json.loads(self.metrics_file.read_text())
                except Exception as e:
                    logger.error(f"Failed to load historical metrics: {e}")
            
            # Append current metrics
            historical_metrics.append(metrics)
            
            # Keep last 30 days
            cutoff_date = datetime.now() - timedelta(days=30)
            historical_metrics = [
                entry for entry in historical_metrics
                if datetime.fromisoformat(entry["timestamp"]) > cutoff_date
            ]
            
            # Save
            self.metrics_file.write_text(json.dumps(historical_metrics, indent=2))
            logger.info("Performance metrics saved")
            
        except Exception as e:
            logger.error(f"Failed to save metrics: {e}")
    
    def get_daily_summary(self) -> Dict:
        """Get summary of today's performance"""
        try:
            if not self.metrics_file.exists():
                return {}
            
            historical_metrics = json.loads(self.metrics_file.read_text())
            today = datetime.now().date()
            
            today_metrics = [
                entry for entry in historical_metrics
                if datetime.fromisoformat(entry["timestamp"]).date() == today
            ]
            
            if not today_metrics:
                return {}
            
            # Calculate daily aggregates
            total_requests = sum(m["total_requests"] for m in today_metrics)
            total_errors = sum(m["total_errors"] for m in today_metrics)
            avg_response_times = [m["avg_response_time"] for m in today_metrics]
            memory_usage = [m["memory_usage_mb"] for m in today_metrics]
            
            return {
                "date": today.isoformat(),
                "total_requests": total_requests,
                "total_errors": total_errors,
                "error_rate": total_errors / total_requests if total_requests > 0 else 0,
                "avg_response_time": sum(avg_response_times) / len(avg_response_times),
                "avg_memory_usage_mb": sum(memory_usage) / len(memory_usage),
                "peak_memory_usage_mb": max(memory_usage),
                "data_points": len(today_metrics)
            }
            
        except Exception as e:
            logger.error(f"Failed to get daily summary: {e}")
            return {}
    
    def get_weekly_trend(self) -> List[Dict]:
        """Get performance trend for the last 7 days"""
        try:
            if not self.metrics_file.exists():
                return []
            
            historical_metrics = json.loads(self.metrics_file.read_text())
            
            # Group by day
            daily_data = defaultdict(list)
            for entry in historical_metrics:
                date = datetime.fromisoformat(entry["timestamp"]).date()
                daily_data[date].append(entry)
            
            # Get last 7 days
            trend = []
            for i in range(7):
                date = datetime.now().date() - timedelta(days=i)
                day_entries = daily_data.get(date, [])
                
                if day_entries:
                    total_requests = sum(e["total_requests"] for e in day_entries)
                    total_errors = sum(e["total_errors"] for e in day_entries)
                    avg_response_times = [e["avg_response_time"] for e in day_entries]
                    
                    trend.append({
                        "date": date.isoformat(),
                        "total_requests": total_requests,
                        "error_rate": total_errors / total_requests if total_requests > 0 else 0,
                        "avg_response_time": sum(avg_response_times) / len(avg_response_times)
                    })
            
            return list(reversed(trend))  # Oldest to newest
            
        except Exception as e:
            logger.error(f"Failed to get weekly trend: {e}")
            return []
    
    def reset(self):
        """Reset current session metrics"""
        self.response_times.clear()
        self.error_count = 0
        self.request_count = 0
        self.feature_usage.clear()
        self.start_time = time.time()
        logger.info("Performance metrics reset")


# Global performance monitor instance
performance_monitor = PerformanceMonitor()
