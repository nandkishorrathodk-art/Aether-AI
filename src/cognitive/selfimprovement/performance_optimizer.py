"""
Self-Improvement System - Performance optimization and continuous learning.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
from collections import defaultdict


@dataclass
class PerformanceMetrics:
    """System performance metrics."""
    avg_response_time: float
    success_rate: float
    user_satisfaction: float
    task_completion_rate: float
    error_rate: float
    timestamp: str


@dataclass
class FeedbackRecord:
    """User feedback record."""
    task_type: str
    feedback_type: str
    rating: float
    comments: str
    timestamp: str


class PerformanceOptimizer:
    """
    Self-improvement system for performance optimization.
    
    Tracks metrics, learns from feedback, and optimizes behavior.
    """
    
    def __init__(self):
        """Initialize performance optimizer."""
        self.metrics_history: List[PerformanceMetrics] = []
        self.feedback_records: List[FeedbackRecord] = []
        self.task_strategies: Dict[str, Dict[str, Any]] = {}
        self.optimization_suggestions: List[str] = []
    
    def record_task_performance(self, task_type: str, response_time: float,
                               success: bool, user_rating: Optional[float] = None):
        """
        Record task performance.
        
        Args:
            task_type: Type of task performed
            response_time: Time taken (seconds)
            success: Whether task succeeded
            user_rating: Optional user rating (1-5)
        """
        if task_type not in self.task_strategies:
            self.task_strategies[task_type] = {
                'total_attempts': 0,
                'successes': 0,
                'avg_response_time': 0.0,
                'ratings': [],
                'best_strategy': None
            }
        
        strategy = self.task_strategies[task_type]
        strategy['total_attempts'] += 1
        
        if success:
            strategy['successes'] += 1
        
        strategy['avg_response_time'] = (
            (strategy['avg_response_time'] * (strategy['total_attempts'] - 1) + response_time)
            / strategy['total_attempts']
        )
        
        if user_rating:
            strategy['ratings'].append(user_rating)
    
    def collect_feedback(self, task_type: str, feedback_type: str,
                        rating: float, comments: str = ""):
        """
        Collect user feedback.
        
        Args:
            task_type: Type of task
            feedback_type: "positive", "negative", or "neutral"
            rating: Rating 1-5
            comments: Optional feedback comments
        """
        feedback = FeedbackRecord(
            task_type=task_type,
            feedback_type=feedback_type,
            rating=rating,
            comments=comments,
            timestamp=datetime.now().isoformat()
        )
        
        self.feedback_records.append(feedback)
        
        self._analyze_feedback_patterns()
    
    def _analyze_feedback_patterns(self):
        """Analyze feedback to identify improvement areas."""
        if len(self.feedback_records) < 5:
            return
        
        recent_feedback = self.feedback_records[-20:]
        
        task_feedback = defaultdict(list)
        for feedback in recent_feedback:
            task_feedback[feedback.task_type].append(feedback.rating)
        
        for task_type, ratings in task_feedback.items():
            avg_rating = sum(ratings) / len(ratings)
            
            if avg_rating < 3.0:
                suggestion = f"Improve {task_type} - average rating {avg_rating:.1f}/5"
                if suggestion not in self.optimization_suggestions:
                    self.optimization_suggestions.append(suggestion)
    
    def compute_current_metrics(self) -> PerformanceMetrics:
        """Compute current performance metrics."""
        if not self.task_strategies:
            return PerformanceMetrics(
                avg_response_time=0.0,
                success_rate=0.0,
                user_satisfaction=0.0,
                task_completion_rate=0.0,
                error_rate=0.0,
                timestamp=datetime.now().isoformat()
            )
        
        total_attempts = sum(s['total_attempts'] for s in self.task_strategies.values())
        total_successes = sum(s['successes'] for s in self.task_strategies.values())
        
        all_response_times = [s['avg_response_time'] for s in self.task_strategies.values()]
        avg_response_time = sum(all_response_times) / len(all_response_times)
        
        success_rate = total_successes / total_attempts if total_attempts > 0 else 0.0
        
        all_ratings = []
        for strategy in self.task_strategies.values():
            all_ratings.extend(strategy['ratings'])
        
        user_satisfaction = sum(all_ratings) / len(all_ratings) if all_ratings else 0.0
        
        metrics = PerformanceMetrics(
            avg_response_time=round(avg_response_time, 2),
            success_rate=round(success_rate, 2),
            user_satisfaction=round(user_satisfaction / 5.0, 2),
            task_completion_rate=round(success_rate, 2),
            error_rate=round(1.0 - success_rate, 2),
            timestamp=datetime.now().isoformat()
        )
        
        self.metrics_history.append(metrics)
        
        return metrics
    
    def get_optimization_recommendations(self) -> List[str]:
        """Get recommendations for performance optimization."""
        recommendations = []
        
        metrics = self.compute_current_metrics()
        
        if metrics.avg_response_time > 5.0:
            recommendations.append("Response time high - consider caching or optimization")
        
        if metrics.success_rate < 0.9:
            recommendations.append(f"Success rate {metrics.success_rate:.1%} - review error handling")
        
        if metrics.user_satisfaction < 0.7:
            recommendations.append("User satisfaction low - analyze feedback for improvement areas")
        
        recommendations.extend(self.optimization_suggestions)
        
        if not recommendations:
            recommendations.append("System performing well - no critical issues detected")
        
        return recommendations[:10]
    
    def identify_improvement_areas(self) -> Dict[str, Any]:
        """Identify specific areas for improvement."""
        areas = {
            'low_performing_tasks': [],
            'slow_responses': [],
            'high_error_rates': [],
            'low_satisfaction': []
        }
        
        for task_type, strategy in self.task_strategies.items():
            success_rate = strategy['successes'] / strategy['total_attempts']
            
            if success_rate < 0.8:
                areas['high_error_rates'].append({
                    'task': task_type,
                    'success_rate': round(success_rate, 2)
                })
            
            if strategy['avg_response_time'] > 5.0:
                areas['slow_responses'].append({
                    'task': task_type,
                    'avg_time': round(strategy['avg_response_time'], 2)
                })
            
            if strategy['ratings']:
                avg_rating = sum(strategy['ratings']) / len(strategy['ratings'])
                if avg_rating < 3.0:
                    areas['low_satisfaction'].append({
                        'task': task_type,
                        'avg_rating': round(avg_rating, 2)
                    })
        
        return areas
    
    def suggest_strategy_changes(self, task_type: str) -> Dict[str, Any]:
        """Suggest strategy changes for a task type."""
        if task_type not in self.task_strategies:
            return {'suggestion': 'No data available for this task type'}
        
        strategy = self.task_strategies[task_type]
        success_rate = strategy['successes'] / strategy['total_attempts']
        
        suggestions = []
        
        if success_rate < 0.7:
            suggestions.append("Consider alternative approach - current success rate low")
        
        if strategy['avg_response_time'] > 10.0:
            suggestions.append("Optimize for speed - response time exceeds target")
        
        if strategy['ratings']:
            avg_rating = sum(strategy['ratings']) / len(strategy['ratings'])
            if avg_rating < 3.5:
                suggestions.append("Improve output quality - user satisfaction below target")
        
        if not suggestions:
            suggestions.append("Current strategy performing well")
        
        return {
            'task_type': task_type,
            'current_performance': {
                'success_rate': round(success_rate, 2),
                'avg_response_time': round(strategy['avg_response_time'], 2),
                'total_attempts': strategy['total_attempts']
            },
            'suggestions': suggestions
        }
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        current_metrics = self.compute_current_metrics()
        
        improvement_areas = self.identify_improvement_areas()
        
        recommendations = self.get_optimization_recommendations()
        
        trend_analysis = self._analyze_trends()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'current_metrics': {
                'avg_response_time': current_metrics.avg_response_time,
                'success_rate': current_metrics.success_rate,
                'user_satisfaction': current_metrics.user_satisfaction,
                'error_rate': current_metrics.error_rate
            },
            'improvement_areas': improvement_areas,
            'recommendations': recommendations,
            'trend_analysis': trend_analysis,
            'total_tasks_processed': sum(s['total_attempts'] for s in self.task_strategies.values()),
            'feedback_count': len(self.feedback_records)
        }
    
    def _analyze_trends(self) -> Dict[str, str]:
        """Analyze performance trends over time."""
        if len(self.metrics_history) < 2:
            return {'trend': 'insufficient_data'}
        
        recent = self.metrics_history[-10:]
        
        response_times = [m.avg_response_time for m in recent]
        success_rates = [m.success_rate for m in recent]
        
        response_trend = "stable"
        if len(response_times) >= 3:
            if response_times[-1] < response_times[0] * 0.9:
                response_trend = "improving"
            elif response_times[-1] > response_times[0] * 1.1:
                response_trend = "degrading"
        
        success_trend = "stable"
        if len(success_rates) >= 3:
            if success_rates[-1] > success_rates[0] + 0.05:
                success_trend = "improving"
            elif success_rates[-1] < success_rates[0] - 0.05:
                success_trend = "degrading"
        
        return {
            'response_time_trend': response_trend,
            'success_rate_trend': success_trend,
            'overall_trend': success_trend if success_trend != "stable" else response_trend
        }
    
    def export_metrics(self, filepath: str):
        """Export metrics to JSON file."""
        data = {
            'metrics_history': [
                {
                    'avg_response_time': m.avg_response_time,
                    'success_rate': m.success_rate,
                    'user_satisfaction': m.user_satisfaction,
                    'timestamp': m.timestamp
                }
                for m in self.metrics_history
            ],
            'feedback_records': [
                {
                    'task_type': f.task_type,
                    'rating': f.rating,
                    'comments': f.comments,
                    'timestamp': f.timestamp
                }
                for f in self.feedback_records
            ],
            'task_strategies': self.task_strategies
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def import_metrics(self, filepath: str):
        """Import metrics from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.metrics_history = [
            PerformanceMetrics(**m) for m in data.get('metrics_history', [])
        ]
        
        self.feedback_records = [
            FeedbackRecord(**f) for f in data.get('feedback_records', [])
        ]
        
        self.task_strategies = data.get('task_strategies', {})
