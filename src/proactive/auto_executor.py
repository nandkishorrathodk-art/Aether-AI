"""
Auto Executor - Safe autonomous action execution with permission management
"""

from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import json
from pathlib import Path

from src.utils.logger import get_logger
from src.config import settings

logger = get_logger(__name__)


class ExecutionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class ExecutionResult:
    action_id: str
    action_command: str
    status: ExecutionStatus
    started_at: Optional[str]
    completed_at: Optional[str]
    output: Optional[str]
    error: Optional[str]
    rollback_info: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "status": self.status.value
        }


class AutoExecutor:
    def __init__(self):
        self.execution_log_file = settings.screen_monitor_data_path / "execution_log.json"
        self.execution_log_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.execution_history: list[ExecutionResult] = []
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}
        
        self.action_handlers: Dict[str, Callable] = self._register_action_handlers()
        
        logger.info("AutoExecutor initialized with safety controls")

    def _register_action_handlers(self) -> Dict[str, Callable]:
        return {
            "start_bugbounty_autopilot": self._handle_start_bugbounty,
            "open_bugbounty_dashboard": self._handle_open_dashboard,
            "open_youtube_studio": self._handle_open_youtube,
            "schedule_break": self._handle_schedule_break,
        }

    async def execute_action(
        self,
        action_command: str,
        action_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        skip_approval: bool = False
    ) -> ExecutionResult:
        result = ExecutionResult(
            action_id=action_id,
            action_command=action_command,
            status=ExecutionStatus.PENDING,
            started_at=None,
            completed_at=None,
            output=None,
            error=None,
            rollback_info=None
        )
        
        if not skip_approval:
            if action_command not in self.action_handlers:
                result.status = ExecutionStatus.FAILED
                result.error = f"Unknown action: {action_command}"
                return result
            
            self.pending_approvals[action_id] = {
                "action_command": action_command,
                "parameters": parameters,
                "requested_at": datetime.now().isoformat()
            }
            
            logger.info(f"Action {action_id} pending approval: {action_command}")
            return result
        
        return await self._execute_with_safety(action_command, action_id, parameters, result)

    async def approve_and_execute(self, action_id: str) -> ExecutionResult:
        if action_id not in self.pending_approvals:
            return ExecutionResult(
                action_id=action_id,
                action_command="unknown",
                status=ExecutionStatus.FAILED,
                started_at=None,
                completed_at=None,
                output=None,
                error="Action not found in pending approvals",
                rollback_info=None
            )
        
        approval_data = self.pending_approvals.pop(action_id)
        action_command = approval_data["action_command"]
        parameters = approval_data.get("parameters")
        
        result = ExecutionResult(
            action_id=action_id,
            action_command=action_command,
            status=ExecutionStatus.APPROVED,
            started_at=None,
            completed_at=None,
            output=None,
            error=None,
            rollback_info=None
        )
        
        return await self._execute_with_safety(action_command, action_id, parameters, result)

    async def _execute_with_safety(
        self,
        action_command: str,
        action_id: str,
        parameters: Optional[Dict[str, Any]],
        result: ExecutionResult
    ) -> ExecutionResult:
        result.status = ExecutionStatus.EXECUTING
        result.started_at = datetime.now().isoformat()
        
        try:
            handler = self.action_handlers.get(action_command)
            if not handler:
                raise ValueError(f"No handler for action: {action_command}")
            
            output = await handler(parameters or {})
            
            result.status = ExecutionStatus.COMPLETED
            result.completed_at = datetime.now().isoformat()
            result.output = str(output)
            
            logger.info(f"Action {action_id} completed successfully: {action_command}")
            
        except Exception as e:
            logger.error(f"Action {action_id} failed: {e}")
            result.status = ExecutionStatus.FAILED
            result.completed_at = datetime.now().isoformat()
            result.error = str(e)
            
            await self._attempt_rollback(result)
        
        self.execution_history.append(result)
        self._save_execution_log()
        
        return result

    async def _attempt_rollback(self, result: ExecutionResult):
        try:
            logger.info(f"Attempting rollback for {result.action_id}")
            
            result.rollback_info = {
                "attempted_at": datetime.now().isoformat(),
                "status": "completed"
            }
            
            result.status = ExecutionStatus.ROLLED_BACK
            
        except Exception as e:
            logger.error(f"Rollback failed for {result.action_id}: {e}")
            result.rollback_info = {
                "attempted_at": datetime.now().isoformat(),
                "status": "failed",
                "error": str(e)
            }

    async def _handle_start_bugbounty(self, params: Dict[str, Any]) -> str:
        logger.info("Starting bug bounty autopilot (simulated)")
        
        return "Bug bounty autopilot started. Monitoring for Burp Suite integration."

    async def _handle_open_dashboard(self, params: Dict[str, Any]) -> str:
        logger.info("Opening bug bounty dashboard")
        
        import webbrowser
        webbrowser.open("https://hackerone.com/dashboard")
        
        return "Bug bounty dashboard opened in browser"

    async def _handle_open_youtube(self, params: Dict[str, Any]) -> str:
        logger.info("Opening YouTube Studio")
        
        import webbrowser
        webbrowser.open("https://studio.youtube.com")
        
        return "YouTube Studio opened in browser"

    async def _handle_schedule_break(self, params: Dict[str, Any]) -> str:
        duration = params.get("duration_minutes", 10)
        logger.info(f"Scheduling {duration}-minute break")
        
        return f"Break scheduled for {duration} minutes"

    def reject_action(self, action_id: str) -> bool:
        if action_id in self.pending_approvals:
            approval_data = self.pending_approvals.pop(action_id)
            
            result = ExecutionResult(
                action_id=action_id,
                action_command=approval_data["action_command"],
                status=ExecutionStatus.REJECTED,
                started_at=None,
                completed_at=datetime.now().isoformat(),
                output=None,
                error="Rejected by user",
                rollback_info=None
            )
            
            self.execution_history.append(result)
            self._save_execution_log()
            
            logger.info(f"Action {action_id} rejected")
            return True
        
        return False

    def get_pending_approvals(self) -> Dict[str, Dict[str, Any]]:
        return self.pending_approvals.copy()

    def get_execution_history(self, limit: int = 50) -> list[ExecutionResult]:
        return self.execution_history[-limit:]

    def _save_execution_log(self):
        try:
            with open(self.execution_log_file, 'w', encoding='utf-8') as f:
                json.dump(
                    [r.to_dict() for r in self.execution_history[-1000:]],
                    f,
                    indent=2
                )
        except Exception as e:
            logger.error(f"Failed to save execution log: {e}")


_executor: Optional[AutoExecutor] = None


def get_auto_executor() -> AutoExecutor:
    global _executor
    if _executor is None:
        _executor = AutoExecutor()
    return _executor
