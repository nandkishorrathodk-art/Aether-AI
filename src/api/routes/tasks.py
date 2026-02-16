from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, List, Optional
import uuid
import time
from datetime import datetime
from src.api.schemas.tasks import (
    CreateTaskRequest,
    TaskResponse,
    TaskListResponse,
    TaskStatus,
    TaskType,
    TaskCancelRequest
)
from src.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])

tasks_store: Dict[str, dict] = {}


class TaskExecutor:
    @staticmethod
    async def execute_automation(task_id: str, command: str, parameters: dict):
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"Executing automation task {task_id}: {command}")
            
            result = {
                "command": command,
                "parameters": parameters,
                "output": f"Automation task '{command}' completed successfully"
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = result
            
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)
    
    @staticmethod
    async def execute_script(task_id: str, command: str, parameters: dict):
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"Executing script task {task_id}: {command}")
            
            result = {
                "command": command,
                "parameters": parameters,
                "output": f"Script '{command}' executed successfully"
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = result
            
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)
    
    @staticmethod
    async def execute_gui_control(task_id: str, command: str, parameters: dict):
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"Executing GUI control task {task_id}: {command}")
            
            result = {
                "command": command,
                "parameters": parameters,
                "output": f"GUI control '{command}' executed successfully"
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = result
            
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)
    
    @staticmethod
    async def execute_file_operation(task_id: str, command: str, parameters: dict):
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"Executing file operation task {task_id}: {command}")
            
            result = {
                "command": command,
                "parameters": parameters,
                "output": f"File operation '{command}' completed successfully"
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = result
            
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)
    
    @staticmethod
    async def execute_system_command(task_id: str, command: str, parameters: dict):
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"Executing system command task {task_id}: {command}")
            
            result = {
                "command": command,
                "parameters": parameters,
                "output": f"System command '{command}' executed successfully"
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = result
            
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)


executor = TaskExecutor()


@router.post("/", response_model=TaskResponse)
async def create_task(request: CreateTaskRequest, background_tasks: BackgroundTasks):
    try:
        task_id = str(uuid.uuid4())
        
        task_data = {
            "task_id": task_id,
            "task_type": request.task_type,
            "command": request.command,
            "status": TaskStatus.pending,
            "created_at": datetime.now(),
            "started_at": None,
            "completed_at": None,
            "result": None,
            "error": None,
            "metadata": {
                "parameters": request.parameters,
                "timeout": request.timeout,
                "auto_approve": request.auto_approve
            }
        }
        
        tasks_store[task_id] = task_data
        
        if request.auto_approve:
            if request.task_type == TaskType.automation:
                background_tasks.add_task(
                    executor.execute_automation,
                    task_id,
                    request.command,
                    request.parameters or {}
                )
            elif request.task_type == TaskType.script:
                background_tasks.add_task(
                    executor.execute_script,
                    task_id,
                    request.command,
                    request.parameters or {}
                )
            elif request.task_type == TaskType.gui_control:
                background_tasks.add_task(
                    executor.execute_gui_control,
                    task_id,
                    request.command,
                    request.parameters or {}
                )
            elif request.task_type == TaskType.file_operation:
                background_tasks.add_task(
                    executor.execute_file_operation,
                    task_id,
                    request.command,
                    request.parameters or {}
                )
            elif request.task_type == TaskType.system_command:
                background_tasks.add_task(
                    executor.execute_system_command,
                    task_id,
                    request.command,
                    request.parameters or {}
                )
        
        return TaskResponse(**task_data)
        
    except Exception as e:
        logger.error(f"Error creating task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str):
    try:
        if task_id not in tasks_store:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
        
        return TaskResponse(**tasks_store[task_id])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=TaskListResponse)
async def list_tasks(
    status: Optional[TaskStatus] = None,
    task_type: Optional[TaskType] = None,
    page: int = 1,
    page_size: int = 20
):
    try:
        filtered_tasks = list(tasks_store.values())
        
        if status:
            filtered_tasks = [t for t in filtered_tasks if t["status"] == status]
        
        if task_type:
            filtered_tasks = [t for t in filtered_tasks if t["task_type"] == task_type]
        
        filtered_tasks.sort(key=lambda x: x["created_at"], reverse=True)
        
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paginated_tasks = filtered_tasks[start_idx:end_idx]
        
        return TaskListResponse(
            tasks=[TaskResponse(**t) for t in paginated_tasks],
            total=len(filtered_tasks),
            page=page,
            page_size=page_size
        )
        
    except Exception as e:
        logger.error(f"Error listing tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{task_id}/execute", response_model=TaskResponse)
async def execute_task(task_id: str, background_tasks: BackgroundTasks):
    try:
        if task_id not in tasks_store:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
        
        task = tasks_store[task_id]
        
        if task["status"] != TaskStatus.pending:
            raise HTTPException(
                status_code=400,
                detail=f"Task is in {task['status']} state, cannot execute"
            )
        
        task_type = task["task_type"]
        command = task["command"]
        parameters = task["metadata"].get("parameters", {})
        
        if task_type == TaskType.automation:
            background_tasks.add_task(executor.execute_automation, task_id, command, parameters)
        elif task_type == TaskType.script:
            background_tasks.add_task(executor.execute_script, task_id, command, parameters)
        elif task_type == TaskType.gui_control:
            background_tasks.add_task(executor.execute_gui_control, task_id, command, parameters)
        elif task_type == TaskType.file_operation:
            background_tasks.add_task(executor.execute_file_operation, task_id, command, parameters)
        elif task_type == TaskType.system_command:
            background_tasks.add_task(executor.execute_system_command, task_id, command, parameters)
        
        return TaskResponse(**tasks_store[task_id])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{task_id}/cancel", response_model=TaskResponse)
async def cancel_task(task_id: str, request: TaskCancelRequest):
    try:
        if task_id not in tasks_store:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
        
        task = tasks_store[task_id]
        
        if task["status"] in [TaskStatus.completed, TaskStatus.failed, TaskStatus.cancelled]:
            raise HTTPException(
                status_code=400,
                detail=f"Task is already in {task['status']} state"
            )
        
        tasks_store[task_id]["status"] = TaskStatus.cancelled
        tasks_store[task_id]["completed_at"] = datetime.now()
        tasks_store[task_id]["metadata"]["cancel_reason"] = request.reason
        
        logger.info(f"Task {task_id} cancelled: {request.reason}")
        
        return TaskResponse(**tasks_store[task_id])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{task_id}")
async def delete_task(task_id: str):
    try:
        if task_id not in tasks_store:
            raise HTTPException(status_code=404, detail=f"Task {task_id} not found")
        
        del tasks_store[task_id]
        
        return {"message": f"Task {task_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/summary")
async def get_task_stats():
    try:
        total_tasks = len(tasks_store)
        
        stats_by_status = {status: 0 for status in TaskStatus}
        stats_by_type = {task_type: 0 for task_type in TaskType}
        
        for task in tasks_store.values():
            stats_by_status[task["status"]] += 1
            stats_by_type[task["task_type"]] += 1
        
        return {
            "total_tasks": total_tasks,
            "by_status": {k.value: v for k, v in stats_by_status.items()},
            "by_type": {k.value: v for k, v in stats_by_type.items()}
        }
        
    except Exception as e:
        logger.error(f"Error getting task stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
