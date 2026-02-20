import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from src.cognitive.llm.model_router import ModelRouter
from src.automation.desktop_automation import get_desktop_automation
from src.monitoring.screen_monitor import ScreenMonitor

logger = logging.getLogger(__name__)


class DesktopAIAgent:
    """
    Autonomous AI Agent that controls desktop
    - Watches screen
    - Understands what user is doing
    - Helps automatically
    - Executes tasks on desktop
    """
    
    def __init__(self):
        self.model_router = ModelRouter()
        self.desktop_automation = get_desktop_automation()
        self.screen_monitor = ScreenMonitor()
        self.running = False
        self.task_history: List[Dict[str, Any]] = []
        logger.info("Desktop AI Agent initialized - Ready to assist")
    
    async def start(self):
        """Start autonomous desktop agent"""
        self.running = True
        logger.info("🤖 Desktop AI Agent started - AI is now controlling desktop")
        
        while self.running:
            try:
                await self._autonomous_loop()
                await asyncio.sleep(5)
            except Exception as e:
                logger.error(f"Agent loop error: {e}")
                await asyncio.sleep(10)
    
    def stop(self):
        """Stop agent"""
        self.running = False
        logger.info("Desktop AI Agent stopped")
    
    async def _autonomous_loop(self):
        """Main autonomous decision loop"""
        screenshot = await self.screen_monitor.capture_screen()
        
        context = {
            "timestamp": datetime.now().isoformat(),
            "screen": "captured",
            "recent_tasks": self.task_history[-5:] if self.task_history else []
        }
        
        decision = await self._make_decision(screenshot, context)
        
        if decision.get("action"):
            await self._execute_decision(decision)
    
    async def _make_decision(self, screenshot: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """AI decides what to do next"""
        
        prompt = f"""
You are an autonomous desktop AI assistant. Based on the current screen and context, decide if you should help the user.

Context: {context}

Available actions you can take:
- create_file: Create files
- open_url: Open websites
- search_google: Search Google
- launch_app: Launch applications
- type_text: Type text
- click: Click on screen
- run_command: Run system commands
- get_system_info: Check system status

Respond in JSON format:
{{
    "should_act": true/false,
    "reasoning": "why you should/shouldn't act",
    "action": "action_name",
    "params": {{}},
    "confidence": 0.0-1.0
}}

Only act if you're very confident it will help the user. Don't be intrusive.
"""
        
        try:
            response = await self.model_router.generate(
                prompt=prompt,
                model="claude-3-5-sonnet-20241022",
                temperature=0.3,
                max_tokens=500
            )
            
            import json
            decision = json.loads(response.get("content", "{}"))
            
            if decision.get("confidence", 0) < 0.7:
                decision["should_act"] = False
            
            return decision
        
        except Exception as e:
            logger.error(f"Decision making failed: {e}")
            return {"should_act": False, "reasoning": "Error in decision making"}
    
    async def _execute_decision(self, decision: Dict[str, Any]):
        """Execute AI decision"""
        
        if not decision.get("should_act"):
            return
        
        action = decision.get("action")
        params = decision.get("params", {})
        
        logger.info(f"🎯 AI Decision: {action} - {decision.get('reasoning')}")
        
        try:
            result = await self.desktop_automation.execute_command(action, params)
            
            self.task_history.append({
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "params": params,
                "result": result,
                "reasoning": decision.get("reasoning")
            })
            
            logger.info(f"✅ Task completed: {action}")
        
        except Exception as e:
            logger.error(f"Task execution failed: {e}")
            self.task_history.append({
                "timestamp": datetime.now().isoformat(),
                "action": action,
                "error": str(e)
            })
    
    async def execute_user_command(self, command: str) -> Dict[str, Any]:
        """Execute user's natural language command"""
        
        prompt = f"""
User command: "{command}"

Convert this natural language command into a desktop automation action.

Available actions:
- File ops: create_file, read_file, write_file, delete_file, move_file, copy_file, list_files, search_files
- Folder ops: create_folder, delete_folder, list_folders  
- Apps: launch_app, close_app, list_running_apps, switch_window
- Browser: open_url, search_google, open_youtube
- Input: click, type_text, press_key, screenshot
- System: run_command, get_system_info
- Clipboard: copy_to_clipboard, paste_from_clipboard

Respond in JSON format:
{{
    "action": "action_name",
    "params": {{}},
    "explanation": "what this will do"
}}
"""
        
        try:
            response = await self.model_router.generate(
                prompt=prompt,
                model="claude-3-5-sonnet-20241022",
                temperature=0.2,
                max_tokens=300
            )
            
            import json
            action_plan = json.loads(response.get("content", "{}"))
            
            result = await self.desktop_automation.execute_command(
                action_plan["action"],
                action_plan["params"]
            )
            
            return {
                "success": True,
                "command": command,
                "action": action_plan["action"],
                "explanation": action_plan.get("explanation"),
                "result": result
            }
        
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                "success": False,
                "command": command,
                "error": str(e)
            }
    
    async def get_task_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent task history"""
        return self.task_history[-limit:]
    
    async def suggest_next_action(self) -> Dict[str, Any]:
        """AI suggests what to do next"""
        
        context = {
            "recent_tasks": self.task_history[-5:],
            "time": datetime.now().strftime("%H:%M")
        }
        
        prompt = f"""
Based on recent activity and current time, suggest a helpful action for the user.

Context: {context}

Suggest something proactive like:
- Organizing files
- Checking system health
- Opening frequently used apps
- Reminding about tasks

Respond in JSON:
{{
    "suggestion": "description",
    "action": "action_name",
    "params": {{}},
    "priority": "low/medium/high"
}}
"""
        
        try:
            response = await self.model_router.generate(
                prompt=prompt,
                model="claude-3-5-sonnet-20241022",
                temperature=0.5
            )
            
            import json
            return json.loads(response.get("content", "{}"))
        
        except Exception as e:
            return {"suggestion": "No suggestions at the moment"}


_agent_instance = None

def get_desktop_agent() -> DesktopAIAgent:
    """Get singleton instance"""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = DesktopAIAgent()
    return _agent_instance
