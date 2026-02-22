"""
Live HUD Broadcaster

Sends real-time status updates to the Electron/React UI via stdout JSON.
The UI reads these and shows a live Jarvis-style HUD overlay.

Data format:
{
  "type": "hud_update",
  "task": "Bug bounty hunt running...",
  "step": 3,
  "total": 8,
  "narration": "BurpSuite ready hai!",
  "bugs_found": 2,
  "status": "executing"
}
"""

import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class HUDBroadcaster:
    """
    Broadcasts real-time status to the frontend UI.
    
    The Electron UI reads stdout JSON messages and renders
    a live Jarvis-style overlay HUD.
    """

    def __init__(self):
        self.current_state: Dict[str, Any] = {
            "status": "idle",
            "task": None,
            "step": 0,
            "total": 0,
            "narration": "",
            "bugs_found": 0,
            "timestamp": None
        }
        logger.info("🖥️ HUD Broadcaster initialized")

    def update(self, data: Dict[str, Any]):
        """
        Update HUD state and broadcast to UI.
        
        Args:
            data: Dict with any of: status, task, step, total,
                  narration, bugs_found, scan_progress
        """
        self.current_state.update(data)
        self.current_state["timestamp"] = datetime.now().isoformat()
        self._broadcast()

    def _broadcast(self):
        """Send state to UI via stdout JSON"""
        message = {
            "type": "hud_update",
            **self.current_state
        }
        try:
            print(json.dumps(message), flush=True)
        except Exception as e:
            logger.error(f"HUD broadcast failed: {e}")

    def set_task(self, task_name: str, total_steps: int = 0):
        """Start a new task display"""
        self.update({
            "status": "executing",
            "task": task_name,
            "step": 0,
            "total": total_steps,
            "narration": f"Starting: {task_name}"
        })

    def step_complete(self, step: int, narration: str = ""):
        """Mark a step as done"""
        self.update({
            "step": step,
            "narration": narration,
            "status": "executing"
        })

    def bug_found(self, bug_name: str, severity: str = "high"):
        """Alert UI of a new bug finding"""
        current_bugs = self.current_state.get("bugs_found", 0) + 1
        self.update({
            "bugs_found": current_bugs,
            "narration": f"🚨 Bug found: {bug_name} ({severity})",
            "status": "bug_found",
            "latest_bug": {
                "name": bug_name,
                "severity": severity,
                "time": datetime.now().isoformat()
            }
        })

    def complete(self, summary: str = ""):
        """Mark task as complete"""
        self.update({
            "status": "complete",
            "narration": summary or "Task complete!",
            "step": self.current_state.get("total", 0)
        })

    def error(self, message: str):
        """Mark task as errored"""
        self.update({
            "status": "error",
            "narration": f"Error: {message}"
        })

    def idle(self):
        """Reset to idle state"""
        self.current_state = {
            "status": "idle",
            "task": None,
            "step": 0,
            "total": 0,
            "narration": "",
            "bugs_found": 0,
            "timestamp": datetime.now().isoformat()
        }
        self._broadcast()


# Global instance
_hud_broadcaster: Optional[HUDBroadcaster] = None


def get_hud_broadcaster() -> HUDBroadcaster:
    """Get or create global HUD broadcaster"""
    global _hud_broadcaster
    if _hud_broadcaster is None:
        _hud_broadcaster = HUDBroadcaster()
    return _hud_broadcaster


logger.info("🖥️ HUD Broadcaster module loaded")
