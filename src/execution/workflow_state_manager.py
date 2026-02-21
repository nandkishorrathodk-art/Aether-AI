"""
Workflow State Manager
Unified state management with SQLite persistence for workflow tracking and resumption
"""
import sqlite3
import json
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


class WorkflowState(Enum):
    """Workflow execution states"""
    QUEUED = "queued"
    PLANNING = "planning"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    PAUSED = "paused"
    RESUMING = "resuming"


class StepState(Enum):
    """Individual step states"""
    PENDING = "pending"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    """Single workflow step"""
    step_id: str
    workflow_id: str
    step_number: int
    description: str
    action_type: str
    parameters: Dict[str, Any]
    state: StepState = StepState.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    verification_status: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            "step_id": self.step_id,
            "workflow_id": self.workflow_id,
            "step_number": self.step_number,
            "description": self.description,
            "action_type": self.action_type,
            "parameters": json.dumps(self.parameters),
            "state": self.state.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": json.dumps(self.result) if self.result else None,
            "error": self.error,
            "verification_status": self.verification_status,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries
        }


@dataclass
class Workflow:
    """Complete workflow definition"""
    workflow_id: str
    name: str
    description: str
    state: WorkflowState = WorkflowState.QUEUED
    created_at: datetime = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step_number: int = 0
    total_steps: int = 0
    metadata: Dict[str, Any] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "current_step_number": self.current_step_number,
            "total_steps": self.total_steps,
            "metadata": json.dumps(self.metadata),
            "error": self.error
        }
    
    def get_progress_percentage(self) -> int:
        """Calculate progress percentage"""
        if self.total_steps == 0:
            return 0
        return int((self.current_step_number / self.total_steps) * 100)


class WorkflowStateManager:
    """
    Manages workflow state with SQLite persistence
    Enables workflow tracking, resumption, and state synchronization
    """
    
    def __init__(self, db_path: str = "workflow_state.db"):
        self.db_path = db_path
        self._init_database()
        logger.info(f"WorkflowStateManager initialized with database: {db_path}")
    
    def _init_database(self):
        """Initialize SQLite database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Workflows table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS workflows (
                workflow_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                current_step_number INTEGER DEFAULT 0,
                total_steps INTEGER DEFAULT 0,
                metadata TEXT,
                error TEXT
            )
        """)
        
        # Workflow steps table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS workflow_steps (
                step_id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                step_number INTEGER NOT NULL,
                description TEXT,
                action_type TEXT NOT NULL,
                parameters TEXT,
                state TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                result TEXT,
                error TEXT,
                verification_status TEXT,
                retry_count INTEGER DEFAULT 0,
                max_retries INTEGER DEFAULT 3,
                FOREIGN KEY (workflow_id) REFERENCES workflows (workflow_id)
            )
        """)
        
        # Execution events table (for detailed logging)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS execution_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_id TEXT NOT NULL,
                step_id TEXT,
                event_type TEXT NOT NULL,
                event_data TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (workflow_id) REFERENCES workflows (workflow_id)
            )
        """)
        
        # State transitions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS state_transitions (
                transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_id TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                reason TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (workflow_id) REFERENCES workflows (workflow_id)
            )
        """)
        
        conn.commit()
        conn.close()
        
        logger.info("Database schema initialized")
    
    def create_workflow(self, workflow: Workflow) -> str:
        """Create new workflow"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        workflow_dict = workflow.to_dict()
        
        cursor.execute("""
            INSERT INTO workflows (
                workflow_id, name, description, state, created_at,
                started_at, completed_at, current_step_number,
                total_steps, metadata, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            workflow_dict["workflow_id"],
            workflow_dict["name"],
            workflow_dict["description"],
            workflow_dict["state"],
            workflow_dict["created_at"],
            workflow_dict["started_at"],
            workflow_dict["completed_at"],
            workflow_dict["current_step_number"],
            workflow_dict["total_steps"],
            workflow_dict["metadata"],
            workflow_dict["error"]
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created workflow: {workflow.workflow_id} - {workflow.name}")
        return workflow.workflow_id
    
    def add_step(self, step: WorkflowStep):
        """Add step to workflow"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        step_dict = step.to_dict()
        
        cursor.execute("""
            INSERT INTO workflow_steps (
                step_id, workflow_id, step_number, description,
                action_type, parameters, state, started_at,
                completed_at, result, error, verification_status,
                retry_count, max_retries
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            step_dict["step_id"],
            step_dict["workflow_id"],
            step_dict["step_number"],
            step_dict["description"],
            step_dict["action_type"],
            step_dict["parameters"],
            step_dict["state"],
            step_dict["started_at"],
            step_dict["completed_at"],
            step_dict["result"],
            step_dict["error"],
            step_dict["verification_status"],
            step_dict["retry_count"],
            step_dict["max_retries"]
        ))
        
        # Update workflow total_steps
        cursor.execute("""
            UPDATE workflows
            SET total_steps = (SELECT COUNT(*) FROM workflow_steps WHERE workflow_id = ?)
            WHERE workflow_id = ?
        """, (step.workflow_id, step.workflow_id))
        
        conn.commit()
        conn.close()
        
        logger.debug(f"Added step {step.step_number} to workflow {step.workflow_id}")
    
    def update_workflow_state(
        self,
        workflow_id: str,
        new_state: WorkflowState,
        reason: Optional[str] = None,
        error: Optional[str] = None
    ):
        """Update workflow state with transition tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get current state
        cursor.execute("SELECT state FROM workflows WHERE workflow_id = ?", (workflow_id,))
        row = cursor.fetchone()
        old_state = row[0] if row else None
        
        # Update workflow state
        update_data = {"state": new_state.value}
        
        if new_state == WorkflowState.EXECUTING and old_state != WorkflowState.EXECUTING:
            update_data["started_at"] = datetime.now().isoformat()
        elif new_state in [WorkflowState.COMPLETED, WorkflowState.FAILED]:
            update_data["completed_at"] = datetime.now().isoformat()
        
        if error:
            update_data["error"] = error
        
        set_clause = ", ".join([f"{k} = ?" for k in update_data.keys()])
        cursor.execute(
            f"UPDATE workflows SET {set_clause} WHERE workflow_id = ?",
            (*update_data.values(), workflow_id)
        )
        
        # Record state transition
        if old_state:
            cursor.execute("""
                INSERT INTO state_transitions (workflow_id, from_state, to_state, reason, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (workflow_id, old_state, new_state.value, reason, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Workflow {workflow_id}: {old_state} → {new_state.value}")
    
    def update_step_state(
        self,
        step_id: str,
        new_state: StepState,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        verification_status: Optional[str] = None
    ):
        """Update step state"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        update_data = {"state": new_state.value}
        
        if new_state == StepState.EXECUTING:
            update_data["started_at"] = datetime.now().isoformat()
        elif new_state in [StepState.COMPLETED, StepState.FAILED, StepState.SKIPPED]:
            update_data["completed_at"] = datetime.now().isoformat()
        
        if result:
            update_data["result"] = json.dumps(result)
        if error:
            update_data["error"] = error
        if verification_status:
            update_data["verification_status"] = verification_status
        
        set_clause = ", ".join([f"{k} = ?" for k in update_data.keys()])
        cursor.execute(
            f"UPDATE workflow_steps SET {set_clause} WHERE step_id = ?",
            (*update_data.values(), step_id)
        )
        
        # Update workflow current_step_number if step completed
        if new_state in [StepState.COMPLETED, StepState.SKIPPED]:
            cursor.execute("""
                UPDATE workflows
                SET current_step_number = (
                    SELECT COUNT(*)
                    FROM workflow_steps
                    WHERE workflow_id = (SELECT workflow_id FROM workflow_steps WHERE step_id = ?)
                    AND state IN ('completed', 'skipped')
                )
                WHERE workflow_id = (SELECT workflow_id FROM workflow_steps WHERE step_id = ?)
            """, (step_id, step_id))
        
        conn.commit()
        conn.close()
        
        logger.debug(f"Step {step_id}: state → {new_state.value}")
    
    def log_event(
        self,
        workflow_id: str,
        event_type: str,
        event_data: Dict[str, Any],
        step_id: Optional[str] = None
    ):
        """Log execution event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO execution_events (workflow_id, step_id, event_type, event_data, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (workflow_id, step_id, event_type, json.dumps(event_data), datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get workflow by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM workflows WHERE workflow_id = ?", (workflow_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return Workflow(
            workflow_id=row["workflow_id"],
            name=row["name"],
            description=row["description"],
            state=WorkflowState(row["state"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            current_step_number=row["current_step_number"],
            total_steps=row["total_steps"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            error=row["error"]
        )
    
    def get_workflow_steps(self, workflow_id: str) -> List[WorkflowStep]:
        """Get all steps for a workflow"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM workflow_steps
            WHERE workflow_id = ?
            ORDER BY step_number
        """, (workflow_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        steps = []
        for row in rows:
            step = WorkflowStep(
                step_id=row["step_id"],
                workflow_id=row["workflow_id"],
                step_number=row["step_number"],
                description=row["description"],
                action_type=row["action_type"],
                parameters=json.loads(row["parameters"]) if row["parameters"] else {},
                state=StepState(row["state"]),
                started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
                completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
                result=json.loads(row["result"]) if row["result"] else None,
                error=row["error"],
                verification_status=row["verification_status"],
                retry_count=row["retry_count"],
                max_retries=row["max_retries"]
            )
            steps.append(step)
        
        return steps
    
    def get_active_workflows(self) -> List[Workflow]:
        """Get all active workflows"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM workflows
            WHERE state IN ('queued', 'planning', 'executing', 'verifying', 'retrying', 'paused', 'resuming')
            ORDER BY created_at DESC
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        workflows = []
        for row in rows:
            workflow = Workflow(
                workflow_id=row["workflow_id"],
                name=row["name"],
                description=row["description"],
                state=WorkflowState(row["state"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
                completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
                current_step_number=row["current_step_number"],
                total_steps=row["total_steps"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                error=row["error"]
            )
            workflows.append(workflow)
        
        return workflows
    
    def get_workflow_summary(self, workflow_id: str) -> Dict[str, Any]:
        """Get comprehensive workflow summary"""
        workflow = self.get_workflow(workflow_id)
        if not workflow:
            return {}
        
        steps = self.get_workflow_steps(workflow_id)
        
        completed_steps = [s for s in steps if s.state == StepState.COMPLETED]
        failed_steps = [s for s in steps if s.state == StepState.FAILED]
        pending_steps = [s for s in steps if s.state == StepState.PENDING]
        
        return {
            "workflow_id": workflow_id,
            "name": workflow.name,
            "state": workflow.state.value,
            "progress_percentage": workflow.get_progress_percentage(),
            "current_step": workflow.current_step_number,
            "total_steps": workflow.total_steps,
            "completed_steps": len(completed_steps),
            "failed_steps": len(failed_steps),
            "pending_steps": len(pending_steps),
            "created_at": workflow.created_at.isoformat(),
            "started_at": workflow.started_at.isoformat() if workflow.started_at else None,
            "duration": (datetime.now() - workflow.started_at).total_seconds() if workflow.started_at else 0,
            "error": workflow.error
        }


# Global instance
workflow_state_manager = WorkflowStateManager()
