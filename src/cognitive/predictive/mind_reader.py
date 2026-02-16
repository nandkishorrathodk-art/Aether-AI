"""
Predictive AI - Mind Reader
Predicts user needs BEFORE they ask
"""
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, Counter
import re

class UserBehaviorTracker:
    def __init__(self):
        self.activity_log = []
        self.time_patterns = defaultdict(list)
        self.context_patterns = defaultdict(list)
        self.sequence_patterns = []
    
    def log_activity(self, activity: str, context: Dict[str, Any] = None):
        now = datetime.now()
        record = {
            'activity': activity,
            'timestamp': now.isoformat(),
            'hour': now.hour,
            'day_of_week': now.strftime('%A'),
            'context': context or {}
        }
        
        self.activity_log.append(record)
        
        time_key = f"{record['day_of_week']}_{record['hour']}"
        self.time_patterns[time_key].append(activity)
        
        if len(self.activity_log) >= 2:
            prev_activity = self.activity_log[-2]['activity']
            self.sequence_patterns.append((prev_activity, activity))
    
    def get_time_based_patterns(self, top_k: int = 5) -> List[Dict[str, Any]]:
        patterns = []
        now = datetime.now()
        time_key = f"{now.strftime('%A')}_{now.hour}"
        
        if time_key in self.time_patterns:
            activity_counts = Counter(self.time_patterns[time_key])
            for activity, count in activity_counts.most_common(top_k):
                patterns.append({
                    'activity': activity,
                    'frequency': count,
                    'time_context': time_key,
                    'confidence': count / len(self.time_patterns[time_key])
                })
        
        return patterns
    
    def get_sequence_predictions(self, current_activity: str, top_k: int = 3) -> List[Dict[str, Any]]:
        next_activities = [
            seq[1] for seq in self.sequence_patterns 
            if seq[0] == current_activity
        ]
        
        if not next_activities:
            return []
        
        activity_counts = Counter(next_activities)
        total = len(next_activities)
        
        predictions = []
        for activity, count in activity_counts.most_common(top_k):
            predictions.append({
                'activity': activity,
                'probability': count / total,
                'frequency': count
            })
        
        return predictions

class HabitLearner:
    def __init__(self):
        self.habits = {}
        self.habit_triggers = defaultdict(list)
    
    def detect_habit(self, activity: str, frequency_threshold: int = 3):
        if activity not in self.habits:
            self.habits[activity] = {
                'count': 1,
                'timestamps': [datetime.now()],
                'is_habit': False
            }
        else:
            self.habits[activity]['count'] += 1
            self.habits[activity]['timestamps'].append(datetime.now())
            
            if self.habits[activity]['count'] >= frequency_threshold:
                self.habits[activity]['is_habit'] = True
                self._analyze_habit_pattern(activity)
    
    def _analyze_habit_pattern(self, activity: str):
        timestamps = self.habits[activity]['timestamps']
        
        if len(timestamps) < 2:
            return
        
        intervals = [
            (timestamps[i+1] - timestamps[i]).total_seconds() 
            for i in range(len(timestamps) - 1)
        ]
        
        avg_interval = sum(intervals) / len(intervals)
        
        if avg_interval < 3600:
            pattern = "frequent"
        elif avg_interval < 86400:
            pattern = "daily"
        elif avg_interval < 604800:
            pattern = "weekly"
        else:
            pattern = "occasional"
        
        self.habits[activity]['pattern'] = pattern
        self.habits[activity]['avg_interval_seconds'] = avg_interval
    
    def get_habits(self) -> List[Dict[str, Any]]:
        return [
            {
                'activity': activity,
                'count': data['count'],
                'is_habit': data.get('is_habit', False),
                'pattern': data.get('pattern', 'unknown'),
                'avg_interval_seconds': data.get('avg_interval_seconds', 0)
            }
            for activity, data in self.habits.items()
            if data.get('is_habit', False)
        ]

class ProactiveAssistant:
    def __init__(self):
        self.scheduled_suggestions = []
        self.proactive_actions = []
    
    def schedule_suggestion(self, suggestion: str, trigger_time: datetime, 
                           priority: str = "normal"):
        self.scheduled_suggestions.append({
            'suggestion': suggestion,
            'trigger_time': trigger_time.isoformat(),
            'priority': priority,
            'status': 'pending'
        })
    
    def get_due_suggestions(self) -> List[Dict[str, Any]]:
        now = datetime.now()
        due = []
        
        for suggestion in self.scheduled_suggestions:
            if suggestion['status'] == 'pending':
                trigger_time = datetime.fromisoformat(suggestion['trigger_time'])
                if now >= trigger_time:
                    suggestion['status'] = 'active'
                    due.append(suggestion)
        
        return sorted(due, key=lambda x: x['priority'], reverse=True)
    
    def create_proactive_action(self, action: str, reason: str):
        self.proactive_actions.append({
            'action': action,
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
            'executed': False
        })

class MindReader:
    def __init__(self, data_dir: Path = None):
        self.data_dir = data_dir or Path(__file__).parent.parent.parent.parent / "data" / "predictive"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.behavior_tracker = UserBehaviorTracker()
        self.habit_learner = HabitLearner()
        self.proactive_assistant = ProactiveAssistant()
        
        self.load_state()
    
    def predict_next_need(self, user_id: str = "default", current_context: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        current_context = current_context or {}
        
        if self.behavior_tracker.activity_log:
            last_activity = self.behavior_tracker.activity_log[-1]['activity']
            sequence_predictions = self.behavior_tracker.get_sequence_predictions(last_activity)
            
            if sequence_predictions:
                top_prediction = sequence_predictions[0]
                return {
                    'type': 'sequence_based',
                    'prediction': top_prediction['activity'],
                    'probability': top_prediction['probability'],
                    'reason': f"Based on {top_prediction['frequency']} past occurrences after '{last_activity}'"
                }
        
        time_patterns = self.behavior_tracker.get_time_based_patterns()
        if time_patterns:
            top_pattern = time_patterns[0]
            return {
                'type': 'time_based',
                'prediction': top_pattern['activity'],
                'confidence': top_pattern['confidence'],
                'reason': f"You usually do this at {top_pattern['time_context']}"
            }
        
        habits = self.habit_learner.get_habits()
        if habits:
            for habit in habits:
                if habit['pattern'] == 'daily':
                    return {
                        'type': 'habit_based',
                        'prediction': habit['activity'],
                        'reason': f"This is a daily habit ({habit['count']} times)"
                    }
        
        return None
    
    def log_user_action(self, action: str, context: Dict[str, Any] = None):
        self.behavior_tracker.log_activity(action, context)
        self.habit_learner.detect_habit(action)
        
        if len(self.behavior_tracker.activity_log) % 10 == 0:
            self.save_state()
    
    def generate_proactive_suggestions(self) -> List[str]:
        suggestions = []
        
        now = datetime.now()
        hour = now.hour
        day = now.strftime('%A')
        
        if hour == 9 and day == "Monday":
            suggestions.append("Good morning! Shall I prepare your weekly status report?")
        
        if hour == 17 and day == "Friday":
            suggestions.append("End of week! Want me to summarize your accomplishments?")
        
        habits = self.habit_learner.get_habits()
        for habit in habits:
            if habit['pattern'] == 'daily':
                suggestions.append(f"Time for your daily {habit['activity']}?")
        
        prediction = self.predict_next_need()
        if prediction:
            suggestions.append(f"Predicted: You might want to {prediction['prediction']}")
        
        return suggestions
    
    def auto_execute_routine(self, routine_name: str) -> Dict[str, Any]:
        routines = {
            'morning_setup': [
                "Open email client",
                "Check calendar",
                "Review priorities"
            ],
            'end_of_day': [
                "Save all work",
                "Backup files",
                "Shutdown non-essential apps"
            ],
            'weekly_report': [
                "Collect metrics",
                "Generate report",
                "Email to stakeholders"
            ]
        }
        
        if routine_name in routines:
            return {
                'routine': routine_name,
                'actions': routines[routine_name],
                'status': 'ready_to_execute'
            }
        
        return {'error': f'Routine {routine_name} not found'}
    
    def get_prediction_stats(self) -> Dict[str, Any]:
        return {
            'total_activities_logged': len(self.behavior_tracker.activity_log),
            'identified_habits': len(self.habit_learner.get_habits()),
            'time_patterns': len(self.behavior_tracker.time_patterns),
            'sequence_patterns': len(self.behavior_tracker.sequence_patterns),
            'scheduled_suggestions': len(self.proactive_assistant.scheduled_suggestions),
            'proactive_actions': len(self.proactive_assistant.proactive_actions)
        }
    
    def save_state(self):
        state_path = self.data_dir / "mind_reader_state.json"
        state = {
            'activity_log': self.behavior_tracker.activity_log[-1000:],
            'habits': self.habit_learner.habits,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self):
        try:
            state_path = self.data_dir / "mind_reader_state.json"
            if state_path.exists():
                with open(state_path, 'r') as f:
                    state = json.load(f)
                    self.behavior_tracker.activity_log = state.get('activity_log', [])
                    self.habit_learner.habits = state.get('habits', {})
        except Exception as e:
            print(f"[MIND_READER] Could not load state: {e}")

mind_reader = MindReader()

def predict_user_need(user_id: str = "default", context: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
    return mind_reader.predict_next_need(user_id, context)

def log_user_action(action: str, context: Dict[str, Any] = None):
    mind_reader.log_user_action(action, context)

def get_proactive_suggestions() -> List[str]:
    return mind_reader.generate_proactive_suggestions()

def get_prediction_stats() -> Dict[str, Any]:
    return mind_reader.get_prediction_stats()
