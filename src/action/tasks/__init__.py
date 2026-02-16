"""
Task Execution System
Handles complex multi-step tasks
"""
from .task_executor import Task, TaskStep, TaskStatus, task_executor
from .burpsuite_tasks import create_burpsuite_setup_task, setup_burpsuite_and_scan

__all__ = [
    'Task',
    'TaskStep',
    'TaskStatus',
    'task_executor',
    'create_burpsuite_setup_task',
    'setup_burpsuite_and_scan',
]
