"""
Conversation State Manager - Tracks ongoing tasks and context
Enhanced with advanced memory, learning, and prediction capabilities
"""
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict
import json

class TaskState(Enum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    WAITING_INPUT = "waiting_input"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

@dataclass
class UserPreferences:
    """Tracks learned user preferences and habits"""
    
    preferred_platforms: List[str] = field(default_factory=list)
    preferred_tools: List[str] = field(default_factory=list)
    browser_setup: Dict[str, Any] = field(default_factory=dict)
    common_workflows: List[List[str]] = field(default_factory=list)
    language_preference: str = "hinglish"
    detail_level: str = "normal"
    confirmation_needed: List[str] = field(default_factory=lambda: ["active_scan", "delete", "format"])
    
    def learn_from_correction(self, correction: str, context: Dict[str, Any]):
        """Learn from user corrections"""
        if "proxy" in correction.lower() and "firefox" in correction.lower():
            self.browser_setup["firefox_proxy"] = "ready"
        elif "already" in correction.lower() or "bataya" in correction.lower():
            pass

@dataclass
class ConversationHistory:
    """Maintains conversation history for context"""
    
    turns: List[Dict[str, Any]] = field(default_factory=list)
    max_history: int = 50
    
    def add_turn(self, user_input: str, aether_response: str, actions: List[str]):
        """Add a conversation turn"""
        self.turns.append({
            "timestamp": datetime.now(),
            "user": user_input,
            "aether": aether_response,
            "actions": actions
        })
        
        if len(self.turns) > self.max_history:
            self.turns = self.turns[-self.max_history:]
    
    def get_recent_topics(self, n: int = 5) -> List[str]:
        """Get recent conversation topics"""
        topics = []
        for turn in self.turns[-n:]:
            if "bug bounty" in turn["user"].lower():
                topics.append("bug_bounty")
            elif "burpsuite" in turn["user"].lower():
                topics.append("burpsuite")
            elif any(platform in turn["user"].lower() for platform in ["hackerone", "bugcrowd"]):
                topics.append("platform_selection")
        return list(set(topics))
    
    def get_last_mentioned_app(self) -> Optional[str]:
        """Get last mentioned application"""
        for turn in reversed(self.turns):
            for app in ["burpsuite", "firefox", "chrome", "cmd", "terminal"]:
                if app in turn["user"].lower() or app in turn["aether"].lower():
                    return app
        return None

@dataclass
class ConversationContext:
    """Tracks the current conversation context and task state"""
    
    current_task: Optional[str] = None
    task_state: TaskState = TaskState.IDLE
    task_steps: List[str] = field(default_factory=list)
    completed_steps: List[str] = field(default_factory=list)
    current_step: Optional[str] = None
    current_step_index: int = 0
    
    last_action: Optional[str] = None
    last_action_result: Optional[str] = None
    last_action_time: Optional[datetime] = None
    action_history: List[Tuple[str, str, datetime]] = field(default_factory=list)
    
    pending_question: Optional[str] = None
    expected_info: Optional[str] = None
    
    apps_opened: List[str] = field(default_factory=list)
    targets_found: List[Dict[str, Any]] = field(default_factory=list)
    selected_target: Optional[Dict[str, Any]] = None
    
    user_corrections: List[str] = field(default_factory=list)
    learned_facts: Dict[str, Any] = field(default_factory=dict)
    
    conversation_history: ConversationHistory = field(default_factory=ConversationHistory)
    user_preferences: UserPreferences = field(default_factory=UserPreferences)
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    pause_reason: Optional[str] = None
    interrupted_at_step: Optional[str] = None
    
    def start_task(self, task: str, steps: List[str]):
        """Start a new task with defined steps"""
        self.current_task = task
        self.task_state = TaskState.PLANNING
        self.task_steps = steps
        self.completed_steps = []
        self.current_step = None
        self.current_step_index = 0
    
    def move_to_next_step(self):
        """Move to next step in task"""
        if self.current_step and self.current_step in self.task_steps:
            self.completed_steps.append(self.current_step)
        
        remaining = [s for s in self.task_steps if s not in self.completed_steps]
        if remaining:
            self.current_step = remaining[0]
            self.current_step_index = self.task_steps.index(remaining[0])
            self.task_state = TaskState.EXECUTING
        else:
            self.current_step = None
            self.task_state = TaskState.COMPLETED
    
    def record_action(self, action: str, result: str):
        """Record an action and its result"""
        self.last_action = action
        self.last_action_result = result
        self.last_action_time = datetime.now()
        self.action_history.append((action, result, datetime.now()))
        
        if len(self.action_history) > 100:
            self.action_history = self.action_history[-100:]
    
    def wait_for_input(self, question: str, expected: str):
        """Mark as waiting for user input"""
        self.task_state = TaskState.WAITING_INPUT
        self.pending_question = question
        self.expected_info = expected
    
    def clear_waiting(self):
        """Clear waiting state"""
        self.task_state = TaskState.EXECUTING
        self.pending_question = None
        self.expected_info = None
    
    def pause_task(self, reason: str):
        """Pause current task"""
        self.task_state = TaskState.PAUSED
        self.pause_reason = reason
        self.interrupted_at_step = self.current_step
    
    def resume_task(self):
        """Resume paused task"""
        if self.task_state == TaskState.PAUSED:
            self.task_state = TaskState.EXECUTING
            self.pause_reason = None
    
    def add_app_opened(self, app: str):
        """Track opened application"""
        if app not in self.apps_opened:
            self.apps_opened.append(app)
    
    def add_target_found(self, target: Dict[str, Any]):
        """Track found targets/programs"""
        self.targets_found.append(target)
    
    def set_selected_target(self, target: Dict[str, Any]):
        """Set the selected target"""
        self.selected_target = target
    
    def add_user_correction(self, correction: str):
        """Track user corrections to learn from"""
        self.user_corrections.append(correction)
        self.user_preferences.learn_from_correction(correction, self.metadata)
    
    def learn_fact(self, key: str, value: Any):
        """Store learned fact about user setup"""
        self.learned_facts[key] = value
    
    def get_learned_fact(self, key: str) -> Optional[Any]:
        """Retrieve learned fact"""
        return self.learned_facts.get(key)
    
    def predict_next_action(self) -> Optional[str]:
        """Predict next logical action based on current state"""
        if self.task_state == TaskState.IDLE:
            return None
        
        if "burpsuite" in self.apps_opened:
            if self.selected_target:
                if self.get_learned_fact("proxy_setup") == "done":
                    return "Enable intercept or start crawling"
                else:
                    return "Setup browser proxy"
            else:
                return "Select target/program"
        
        if self.current_task and "bug bounty" in self.current_task.lower():
            if not self.apps_opened:
                return "Open BurpSuite"
            elif not self.targets_found:
                return "Search for bug bounty programs"
        
        return None
    
    def get_progress_percentage(self) -> int:
        """Calculate task progress percentage"""
        if not self.task_steps:
            return 0
        return int((len(self.completed_steps) / len(self.task_steps)) * 100)
    
    def add_conversation_turn(self, user_input: str, aether_response: str, actions: List[str]):
        """Add conversation turn to history"""
        self.conversation_history.add_turn(user_input, aether_response, actions)
    
    def get_summary(self) -> str:
        """Get current state summary for context injection"""
        if self.task_state == TaskState.IDLE:
            summary = "[CONVERSATION CONTEXT]\n"
            summary += "No active task.\n"
            if self.learned_facts:
                summary += "\n[LEARNED FACTS - Remember these!]\n"
                for key, value in self.learned_facts.items():
                    summary += f"- {key}: {value}\n"
            return summary
        
        summary = "[CONVERSATION CONTEXT]\n"
        summary += f"Current Task: {self.current_task}\n"
        summary += f"State: {self.task_state.value}\n"
        summary += f"Progress: {self.get_progress_percentage()}%\n"
        
        if self.completed_steps:
            summary += f"Completed Steps: {', '.join(self.completed_steps)}\n"
        
        if self.current_step:
            summary += f"Current Step: {self.current_step} ({self.current_step_index + 1}/{len(self.task_steps)})\n"
        
        remaining = [s for s in self.task_steps if s not in self.completed_steps]
        if remaining:
            summary += f"Remaining Steps: {', '.join(remaining)}\n"
        
        if self.last_action:
            time_ago = (datetime.now() - self.last_action_time).seconds if self.last_action_time else 0
            summary += f"Last Action: {self.last_action} ({time_ago}s ago)\n"
            summary += f"Result: {self.last_action_result}\n"
        
        if self.pending_question:
            summary += f"\n[WAITING FOR USER INPUT]\n"
            summary += f"Question Asked: {self.pending_question}\n"
            summary += f"Expected Info: {self.expected_info}\n"
        
        if self.apps_opened:
            summary += f"\n[APPS OPENED]\n{', '.join(self.apps_opened)}\n"
        
        if self.selected_target:
            summary += f"\n[SELECTED TARGET]\n{self.selected_target.get('name', 'Unknown')}\n"
        
        if self.learned_facts:
            summary += "\n[LEARNED FACTS - Remember these!]\n"
            for key, value in self.learned_facts.items():
                summary += f"- {key}: {value}\n"
        
        if self.user_preferences.browser_setup:
            summary += "\n[USER BROWSER SETUP]\n"
            for browser, status in self.user_preferences.browser_setup.items():
                summary += f"- {browser}: {status}\n"
        
        next_action = self.predict_next_action()
        if next_action:
            summary += f"\n[SUGGESTED NEXT ACTION]\n{next_action}\n"
        
        recent_topics = self.conversation_history.get_recent_topics()
        if recent_topics:
            summary += f"\n[RECENT TOPICS]\n{', '.join(recent_topics)}\n"
        
        if self.task_state == TaskState.PAUSED:
            summary += f"\n[TASK PAUSED]\nReason: {self.pause_reason}\n"
            summary += f"Interrupted at: {self.interrupted_at_step}\n"
        
        return summary
    
    def reset(self):
        """Reset state (keeps learned facts and preferences)"""
        self.current_task = None
        self.task_state = TaskState.IDLE
        self.task_steps = []
        self.completed_steps = []
        self.current_step = None
        self.current_step_index = 0
        self.last_action = None
        self.last_action_result = None
        self.pending_question = None
        self.expected_info = None
        self.apps_opened = []
        self.targets_found = []
        self.selected_target = None


class ConversationStateManager:
    """Manages conversation state across requests with persistence and analytics"""
    
    def __init__(self):
        self.sessions: Dict[str, ConversationContext] = {}
        self.session_analytics: Dict[str, Dict[str, Any]] = defaultdict(dict)
    
    def get_context(self, session_id: str) -> ConversationContext:
        """Get or create conversation context for session"""
        if session_id not in self.sessions:
            self.sessions[session_id] = ConversationContext()
            self.session_analytics[session_id] = {
                "created_at": datetime.now(),
                "total_turns": 0,
                "total_actions": 0,
                "tasks_completed": 0
            }
        return self.sessions[session_id]
    
    def update_analytics(self, session_id: str, turn_completed: bool = False, action_executed: bool = False):
        """Update session analytics"""
        if session_id in self.session_analytics:
            if turn_completed:
                self.session_analytics[session_id]["total_turns"] += 1
            if action_executed:
                self.session_analytics[session_id]["total_actions"] += 1
            
            context = self.get_context(session_id)
            if context.task_state == TaskState.COMPLETED:
                self.session_analytics[session_id]["tasks_completed"] += 1
    
    def get_session_summary(self, session_id: str) -> str:
        """Get session analytics summary"""
        if session_id not in self.session_analytics:
            return "No session data"
        
        analytics = self.session_analytics[session_id]
        summary = f"Session Analytics:\n"
        summary += f"- Created: {analytics['created_at'].strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += f"- Total Turns: {analytics['total_turns']}\n"
        summary += f"- Total Actions: {analytics['total_actions']}\n"
        summary += f"- Tasks Completed: {analytics['tasks_completed']}\n"
        
        return summary
    
    def clear_session(self, session_id: str, keep_learned: bool = True):
        """Clear session state"""
        if session_id in self.sessions:
            if keep_learned:
                learned = self.sessions[session_id].learned_facts
                prefs = self.sessions[session_id].user_preferences
                self.sessions[session_id] = ConversationContext()
                self.sessions[session_id].learned_facts = learned
                self.sessions[session_id].user_preferences = prefs
            else:
                del self.sessions[session_id]
    
    def get_all_learned_facts(self, session_id: str) -> Dict[str, Any]:
        """Get all learned facts for a session"""
        if session_id in self.sessions:
            return self.sessions[session_id].learned_facts
        return {}
    
    def save_state(self, session_id: str, filepath: str):
        """Save conversation state to file"""
        if session_id not in self.sessions:
            return
        
        context = self.sessions[session_id]
        state_data = {
            "session_id": session_id,
            "current_task": context.current_task,
            "task_state": context.task_state.value,
            "completed_steps": context.completed_steps,
            "learned_facts": context.learned_facts,
            "user_preferences": {
                "browser_setup": context.user_preferences.browser_setup,
                "preferred_platforms": context.user_preferences.preferred_platforms,
                "preferred_tools": context.user_preferences.preferred_tools
            },
            "saved_at": datetime.now().isoformat()
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(state_data, f, indent=2)
        except Exception as e:
            print(f"Failed to save state: {e}")
    
    def load_state(self, session_id: str, filepath: str):
        """Load conversation state from file"""
        try:
            with open(filepath, 'r') as f:
                state_data = json.load(f)
            
            context = self.get_context(session_id)
            context.learned_facts = state_data.get("learned_facts", {})
            context.user_preferences.browser_setup = state_data.get("user_preferences", {}).get("browser_setup", {})
            context.user_preferences.preferred_platforms = state_data.get("user_preferences", {}).get("preferred_platforms", [])
            context.user_preferences.preferred_tools = state_data.get("user_preferences", {}).get("preferred_tools", [])
            
            return True
        except Exception as e:
            print(f"Failed to load state: {e}")
            return False


state_manager = ConversationStateManager()
