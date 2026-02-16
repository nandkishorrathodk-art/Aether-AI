"""
Task Execution Engine
Breaks complex tasks into steps and executes them completely
"""
import asyncio
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

class TaskStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"

@dataclass
class TaskStep:
    """Single step in a task"""
    step_id: str
    description: str
    action: Callable
    params: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: float = 0
    
    async def execute(self) -> bool:
        """Execute this step"""
        try:
            self.status = TaskStatus.IN_PROGRESS
            start_time = time.time()
            
            # Execute action
            if asyncio.iscoroutinefunction(self.action):
                self.result = await self.action(**self.params)
            else:
                self.result = self.action(**self.params)
            
            self.duration_ms = (time.time() - start_time) * 1000
            self.status = TaskStatus.COMPLETED
            return True
            
        except Exception as e:
            self.error = str(e)
            self.status = TaskStatus.FAILED
            return False

@dataclass
class Task:
    """Complex multi-step task"""
    task_id: str
    name: str
    description: str
    steps: List[TaskStep] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    current_step_index: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_duration_ms: float = 0
    
    def add_step(self, step: TaskStep):
        """Add a step to this task"""
        self.steps.append(step)
    
    def get_current_step(self) -> Optional[TaskStep]:
        """Get the current step being executed"""
        if self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None
    
    def get_progress(self) -> Dict[str, Any]:
        """Get task progress"""
        completed = sum(1 for s in self.steps if s.status == TaskStatus.COMPLETED)
        failed = sum(1 for s in self.steps if s.status == TaskStatus.FAILED)
        
        return {
            "task_id": self.task_id,
            "name": self.name,
            "status": self.status.value,
            "total_steps": len(self.steps),
            "completed_steps": completed,
            "failed_steps": failed,
            "current_step": self.current_step_index + 1,
            "current_step_description": self.get_current_step().description if self.get_current_step() else None,
            "progress_percent": int((completed / len(self.steps)) * 100) if self.steps else 0
        }

class TaskExecutor:
    """Executes complex multi-step tasks"""
    
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}
    
    async def execute_task(
        self,
        task: Task,
        callback: Optional[Callable] = None
    ) -> bool:
        """Execute a task step by step"""
        task.status = TaskStatus.IN_PROGRESS
        task.started_at = datetime.now()
        self.tasks[task.task_id] = task
        
        start_time = time.time()
        success = True
        
        try:
            for i, step in enumerate(task.steps):
                task.current_step_index = i
                
                # Report progress
                if callback:
                    await callback(task.get_progress())
                
                # Execute step
                step_success = await step.execute()
                
                if not step_success:
                    success = False
                    task.status = TaskStatus.FAILED
                    break
                
                # Small delay between steps
                await asyncio.sleep(0.5)
            
            if success:
                task.status = TaskStatus.COMPLETED
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            success = False
        
        finally:
            task.completed_at = datetime.now()
            task.total_duration_ms = (time.time() - start_time) * 1000
        
        return success
    
    async def execute_task_async(
        self,
        task: Task,
        callback: Optional[Callable] = None
    ) -> str:
        """Execute task in background and return task_id"""
        async_task = asyncio.create_task(
            self.execute_task(task, callback)
        )
        self.running_tasks[task.task_id] = async_task
        return task.task_id
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a running task"""
        if task_id in self.tasks:
            return self.tasks[task_id].get_progress()
        return None
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task"""
        if task_id in self.running_tasks:
            self.running_tasks[task_id].cancel()
            if task_id in self.tasks:
                self.tasks[task_id].status = TaskStatus.PAUSED
            return True
        return False

# Global task executor
task_executor = TaskExecutor()
