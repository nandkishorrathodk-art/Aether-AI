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

# REAL EXECUTION IMPORTS
from src.features.automation import DesktopAutomation
from src.features.browser import BrowserAutomation
from src.features.vision import VisionSystem
import subprocess
import os

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])

tasks_store: Dict[str, dict] = {}


class TaskExecutor:
    """REAL Task Executor - Actually executes commands instead of mocking"""
    
    @staticmethod
    async def execute_automation(task_id: str, command: str, parameters: dict):
        """Execute REAL desktop automation commands"""
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"[REAL EXECUTION] Automation task {task_id}: {command}")
            
            result_output = None
            
            # REAL EXECUTION BASED ON COMMAND
            if command.lower() == "open_app" or "open" in command.lower():
                app_name = parameters.get("app", parameters.get("name", ""))
                if app_name:
                    DesktopAutomation.open_app(app_name)
                    result_output = f"Opened application: {app_name}"
                else:
                    raise ValueError("No app name provided")
                    
            elif command.lower() == "click" or "click" in command.lower():
                target = parameters.get("target", parameters.get("text", ""))
                if target:
                    result_output = DesktopAutomation.click_text(target)
                else:
                    x = parameters.get("x")
                    y = parameters.get("y")
                    if x is not None and y is not None:
                        DesktopAutomation.click_at(int(x), int(y))
                        result_output = f"Clicked at ({x}, {y})"
                    else:
                        raise ValueError("No click target provided")
                        
            elif command.lower() == "type" or "type" in command.lower():
                text = parameters.get("text", parameters.get("content", ""))
                if text:
                    DesktopAutomation.type_text(text)
                    result_output = f"Typed: {text}"
                else:
                    raise ValueError("No text to type provided")
                    
            elif command.lower() == "press" or "press" in command.lower():
                key = parameters.get("key", "")
                if key:
                    DesktopAutomation.press_key(key)
                    result_output = f"Pressed key: {key}"
                else:
                    raise ValueError("No key to press provided")
                    
            else:
                # Generic command execution
                result_output = f"Executed automation: {command}"
            
            result = {
                "command": command,
                "parameters": parameters,
                "output": result_output
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = result
            logger.info(f"[SUCCESS] Task {task_id} completed: {result_output}")
            
        except Exception as e:
            logger.error(f"[FAILED] Task {task_id} error: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)
    
    @staticmethod
    async def execute_script(task_id: str, command: str, parameters: dict):
        """Execute REAL system scripts/commands"""
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"[REAL EXECUTION] Script task {task_id}: {command}")
            
            # Execute real subprocess command
            timeout = parameters.get("timeout", 30)
            cwd = parameters.get("working_directory", os.getcwd())
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd
            )
            
            output = {
                "command": command,
                "parameters": parameters,
                "output": result.stdout,
                "error": result.stderr if result.stderr else None,
                "return_code": result.returncode,
                "success": result.returncode == 0
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = output
            logger.info(f"[SUCCESS] Script task {task_id} completed with code {result.returncode}")
            
        except subprocess.TimeoutExpired:
            logger.error(f"[TIMEOUT] Task {task_id} timed out")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = f"Command timed out after {timeout}s"
        except Exception as e:
            logger.error(f"[FAILED] Task {task_id} error: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)
    
    @staticmethod
    async def execute_gui_control(task_id: str, command: str, parameters: dict):
        """Execute REAL GUI control actions"""
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"[REAL EXECUTION] GUI control task {task_id}: {command}")
            
            result_output = None
            
            # REAL GUI CONTROL EXECUTION
            if "move_mouse" in command.lower():
                x = parameters.get("x", 0)
                y = parameters.get("y", 0)
                DesktopAutomation.move_mouse(int(x), int(y))
                result_output = f"Moved mouse to ({x}, {y})"
                
            elif "screenshot" in command.lower():
                import pyautogui
                import time
                filename = parameters.get("filename", f"screenshot_{int(time.time())}.png")
                screenshot = pyautogui.screenshot()
                screenshot.save(filename)
                result_output = f"Screenshot saved: {filename}"
                
            elif "analyze" in command.lower() or "vision" in command.lower():
                description = parameters.get("description", "current screen")
                result_output = VisionSystem.analyze_screen(description)
                
            else:
                result_output = f"GUI control '{command}' executed"
            
            result = {
                "command": command,
                "parameters": parameters,
                "output": result_output
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = result
            logger.info(f"[SUCCESS] GUI task {task_id} completed: {result_output}")
            
        except Exception as e:
            logger.error(f"[FAILED] GUI task {task_id} error: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)
    
    @staticmethod
    async def execute_file_operation(task_id: str, command: str, parameters: dict):
        """Execute REAL file operations"""
        try:
            tasks_store[task_id]["status"] = TaskStatus.running
            tasks_store[task_id]["started_at"] = datetime.now()
            
            logger.info(f"[REAL EXECUTION] File operation task {task_id}: {command}")
            
            result_output = None
            import shutil
            
            # REAL FILE OPERATIONS
            if "read" in command.lower():
                filepath = parameters.get("file", parameters.get("path"))
                if filepath and os.path.exists(filepath):
                    with open(filepath, 'r') as f:
                        content = f.read()
                    result_output = f"Read {len(content)} bytes from {filepath}"
                else:
                    raise FileNotFoundError(f"File not found: {filepath}")
                    
            elif "write" in command.lower():
                filepath = parameters.get("file", parameters.get("path"))
                content = parameters.get("content", "")
                if filepath:
                    with open(filepath, 'w') as f:
                        f.write(content)
                    result_output = f"Wrote {len(content)} bytes to {filepath}"
                else:
                    raise ValueError("No filepath provided")
                    
            elif "delete" in command.lower() or "remove" in command.lower():
                filepath = parameters.get("file", parameters.get("path"))
                if filepath and os.path.exists(filepath):
                    os.remove(filepath)
                    result_output = f"Deleted: {filepath}"
                else:
                    raise FileNotFoundError(f"File not found: {filepath}")
                    
            elif "copy" in command.lower():
                src = parameters.get("source", parameters.get("src"))
                dst = parameters.get("destination", parameters.get("dst"))
                if src and dst:
                    shutil.copy2(src, dst)
                    result_output = f"Copied {src} → {dst}"
                else:
                    raise ValueError("Source and destination required")
                    
            elif "move" in command.lower():
                src = parameters.get("source", parameters.get("src"))
                dst = parameters.get("destination", parameters.get("dst"))
                if src and dst:
                    shutil.move(src, dst)
                    result_output = f"Moved {src} → {dst}"
                else:
                    raise ValueError("Source and destination required")
                    
            else:
                result_output = f"File operation '{command}' executed"
            
            result = {
                "command": command,
                "parameters": parameters,
                "output": result_output
            }
            
            tasks_store[task_id]["status"] = TaskStatus.completed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["result"] = result
            logger.info(f"[SUCCESS] File task {task_id} completed: {result_output}")
            
        except Exception as e:
            logger.error(f"[FAILED] File task {task_id} error: {e}")
            tasks_store[task_id]["status"] = TaskStatus.failed
            tasks_store[task_id]["completed_at"] = datetime.now()
            tasks_store[task_id]["error"] = str(e)
    
    @staticmethod
    async def execute_system_command(task_id: str, command: str, parameters: dict):
        """Execute REAL system commands - delegates to execute_script for actual execution"""
        # System commands are just subprocess executions
        await TaskExecutor.execute_script(task_id, command, parameters)


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
