"""
Proactive Intelligence Engine

This is what makes Aether SMARTER than any competitor:
- Anticipates user needs
- Offers suggestions before asked
- Learns user patterns
- Automates repetitive tasks

NO OTHER AI DOES THIS!
"""

import time
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict
from src.utils.logger import get_logger
from src.cognitive.llm.model_loader import ModelLoader
from src.cognitive.memory.user_profile import UserProfile

logger = get_logger(__name__)


class ProactiveEngine:
    """
    Proactive intelligence that anticipates needs
    
    Features that beat competitors:
    1. Pattern learning - understands what you do regularly
    2. Context awareness - knows what you're working on
    3. Time-based suggestions - right suggestion at right time
    4. Automation discovery - finds repetitive tasks to automate
    """
    
    def __init__(self, user_id: str = "default"):
        self.logger = get_logger(__name__)
        self.model_loader = ModelLoader()
        self.user_profile = UserProfile(user_id=user_id)
        self.user_id = user_id
        
        # Pattern tracking
        self.activity_log: List[Dict[str, Any]] = []
        self.patterns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        self.logger.info("ProactiveEngine initialized")
    
    def log_activity(self, activity: str, context: Dict[str, Any] = None):
        """
        Log user activity for pattern learning
        
        Args:
            activity: Activity description
            context: Additional context
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'activity': activity,
            'context': context or {},
            'hour': datetime.now().hour,
            'day_of_week': datetime.now().weekday()
        }
        
        self.activity_log.append(entry)
        
        # Update user profile
        self.user_profile.record_activity(activity, context)
        
        # Learn patterns
        self._learn_patterns()
    
    def get_suggestions(
        self,
        context: Dict[str, Any] = None,
        max_suggestions: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Get proactive suggestions based on context and patterns
        
        This is THE killer feature - suggests things before you ask!
        """
        suggestions = []
        
        # Time-based suggestions
        time_suggestions = self._get_time_based_suggestions()
        suggestions.extend(time_suggestions)
        
        # Context-based suggestions
        if context:
            context_suggestions = self._get_context_suggestions(context)
            suggestions.extend(context_suggestions)
        
        # Pattern-based suggestions
        pattern_suggestions = self._get_pattern_suggestions()
        suggestions.extend(pattern_suggestions)
        
        # Automation opportunities
        automation_suggestions = self._find_automation_opportunities()
        suggestions.extend(automation_suggestions)
        
        # Rank by relevance and return top N
        ranked = self._rank_suggestions(suggestions)
        return ranked[:max_suggestions]
    
    def _learn_patterns(self):
        """
        Learn patterns from activity log
        
        Patterns detected:
        - Daily routines
        - Common sequences
        - Time-based habits
        - Tool preferences
        """
        if len(self.activity_log) < 10:
            return  # Need more data
        
        # Daily patterns (same time every day)
        current_hour = datetime.now().hour
        activities_this_hour = [
            a for a in self.activity_log
            if a['hour'] == current_hour
        ]
        
        if len(activities_this_hour) >= 3:
            most_common = max(
                set(a['activity'] for a in activities_this_hour),
                key=lambda x: sum(1 for a in activities_this_hour if a['activity'] == x)
            )
            
            self.patterns['time_based'].append({
                'hour': current_hour,
                'activity': most_common,
                'frequency': len(activities_this_hour)
            })
        
        # Sequential patterns (A then B)
        if len(self.activity_log) >= 2:
            for i in range(len(self.activity_log) - 1):
                sequence = (
                    self.activity_log[i]['activity'],
                    self.activity_log[i + 1]['activity']
                )
                
                self.patterns['sequences'].append({
                    'sequence': sequence,
                    'timestamp': self.activity_log[i + 1]['timestamp']
                })
    
    def _get_time_based_suggestions(self) -> List[Dict[str, Any]]:
        """Suggestions based on time of day"""
        suggestions = []
        current_hour = datetime.now().hour
        
        # Morning (6-10 AM)
        if 6 <= current_hour < 10:
            suggestions.append({
                'type': 'time_based',
                'priority': 'high',
                'title': 'Start Daily Planning',
                'description': 'Review your calendar and create today\'s task list',
                'action': 'open_calendar'
            })
        
        # Work hours (10 AM - 5 PM)
        elif 10 <= current_hour < 17:
            # Check for meetings soon
            suggestions.append({
                'type': 'time_based',
                'priority': 'medium',
                'title': 'Stay Focused',
                'description': 'Do you want me to block distracting websites?',
                'action': 'enable_focus_mode'
            })
        
        # Evening (6-10 PM)
        elif 18 <= current_hour < 22:
            suggestions.append({
                'type': 'time_based',
                'priority': 'medium',
                'title': 'Daily Summary',
                'description': 'Review what you accomplished today',
                'action': 'generate_summary'
            })
        
        return suggestions
    
    def _get_context_suggestions(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Suggestions based on current context"""
        suggestions = []
        
        # If working on code
        if context.get('activity') == 'coding':
            file_type = context.get('file_type')
            
            suggestions.append({
                'type': 'context',
                'priority': 'high',
                'title': 'Run Tests',
                'description': f'Would you like me to run tests for your {file_type} code?',
                'action': 'run_tests'
            })
            
            suggestions.append({
                'type': 'context',
                'priority': 'medium',
                'title': 'Code Review',
                'description': 'I can review your code for bugs and improvements',
                'action': 'review_code'
            })
        
        # If reading documentation
        elif context.get('activity') == 'reading_docs':
            suggestions.append({
                'type': 'context',
                'priority': 'medium',
                'title': 'Generate Code Example',
                'description': 'Want me to create a code example based on this documentation?',
                'action': 'generate_example'
            })
        
        # If debugging
        elif context.get('activity') == 'debugging':
            error_message = context.get('error')
            
            suggestions.append({
                'type': 'context',
                'priority': 'high',
                'title': 'Auto-Fix Bug',
                'description': f'I can try to fix this error: {error_message[:50]}...',
                'action': 'auto_fix_bug',
                'params': {'error': error_message}
            })
        
        return suggestions
    
    def _get_pattern_suggestions(self) -> List[Dict[str, Any]]:
        """Suggestions based on learned patterns"""
        suggestions = []
        
        # Check time-based patterns
        current_hour = datetime.now().hour
        for pattern in self.patterns.get('time_based', []):
            if pattern['hour'] == current_hour:
                suggestions.append({
                    'type': 'pattern',
                    'priority': 'medium',
                    'title': f'Usual Activity: {pattern["activity"]}',
                    'description': f'You usually {pattern["activity"]} around this time',
                    'action': 'suggest_routine'
                })
        
        return suggestions
    
    def _find_automation_opportunities(self) -> List[Dict[str, Any]]:
        """
        Find repetitive tasks that can be automated
        
        THIS IS GENIUS - no other AI proactively finds automation opportunities!
        """
        suggestions = []
        
        # Count repeated activities
        activity_counts = defaultdict(int)
        for entry in self.activity_log[-100:]:  # Last 100 activities
            activity_counts[entry['activity']] += 1
        
        # If something done 5+ times, suggest automation
        for activity, count in activity_counts.items():
            if count >= 5:
                suggestions.append({
                    'type': 'automation',
                    'priority': 'high',
                    'title': f'Automate: {activity}',
                    'description': f'You\'ve done this {count} times. Let me automate it!',
                    'action': 'create_automation',
                    'params': {'activity': activity}
                })
        
        return suggestions
    
    def _rank_suggestions(self, suggestions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank suggestions by priority and relevance"""
        priority_order = {'high': 3, 'medium': 2, 'low': 1}
        
        return sorted(
            suggestions,
            key=lambda s: priority_order.get(s.get('priority', 'low'), 0),
            reverse=True
        )
    
    def create_automation(self, activity: str) -> Dict[str, Any]:
        """
        Create automation for repetitive task
        
        Args:
            activity: Activity to automate
            
        Returns:
            Automation script/configuration
        """
        # Find related activity entries
        related = [e for e in self.activity_log if e['activity'] == activity]
        
        if not related:
            return {'error': 'No activity history found'}
        
        # Analyze context to understand the task
        contexts = [e.get('context', {}) for e in related]
        
        # Generate automation with AI
        automation_prompt = f"""Create an automation script for this repetitive task:

Activity: {activity}

Context from previous executions:
{contexts[:3]}

Generate:
1. Python script to automate this
2. Instructions for user
3. Error handling

Make it production-ready and safe."""

        response = self.model_loader.generate_response(
            prompt=automation_prompt,
            task_type="code"
        )
        
        return {
            'activity': activity,
            'frequency': len(related),
            'automation_script': response,
            'success': True
        }
    
    def monitor_and_suggest(
        self,
        callback: Callable[[List[Dict[str, Any]]], None],
        check_interval: int = 300  # 5 minutes
    ):
        """
        Continuously monitor and provide suggestions
        
        Args:
            callback: Function to call with suggestions
            check_interval: How often to check (seconds)
        """
        import threading
        
        def monitor_loop():
            while True:
                try:
                    suggestions = self.get_suggestions()
                    if suggestions:
                        callback(suggestions)
                    
                    time.sleep(check_interval)
                    
                except Exception as e:
                    self.logger.error(f"Monitoring error: {e}")
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        self.logger.info("Proactive monitoring started")
