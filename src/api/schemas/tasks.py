from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum


class TaskStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class TaskType(str, Enum):
    automation = "automation"
    script = "script"
    gui_control = "gui_control"
    file_operation = "file_operation"
    system_command = "system_command"


class CreateTaskRequest(BaseModel):
    task_type: TaskType = Field(..., description="Type of task to execute")
    command: str = Field(..., min_length=1, description="Task command or description")
    parameters: Optional[Dict[str, Any]] = Field(default=None, description="Task parameters")
    timeout: Optional[int] = Field(default=60, ge=1, le=600, description="Timeout in seconds")
    auto_approve: bool = Field(default=False, description="Auto-approve task execution")


class TaskResponse(BaseModel):
    task_id: str
    task_type: TaskType
    command: str
    status: TaskStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = {}


class TaskListResponse(BaseModel):
    tasks: List[TaskResponse]
    total: int
    page: int
    page_size: int


class TaskCancelRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Cancellation reason")
