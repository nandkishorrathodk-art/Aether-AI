"""
API Routes for Workflow Automation
Exposes workflow recorder, templates, and execution
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import logging

from src.action.workflows.recorder import WorkflowRecorder
from src.action.workflows.templates import WorkflowTemplates

router = APIRouter(prefix="/api/v1/workflows", tags=["workflows"])
logger = logging.getLogger(__name__)

# Global recorder instance
recorder = WorkflowRecorder()


# Schemas
class RecordRequest(BaseModel):
    workflow_name: Optional[str] = None


class ReplayRequest(BaseModel):
    workflow_name: str
    speed: float = 1.0


class WorkflowInfo(BaseModel):
    name: str
    created: str
    actions: int
    duration: float


class TemplateInfo(BaseModel):
    name: str
    title: str
    category: str
    description: str
    steps: int


# Recording endpoints
@router.post("/record/start")
async def start_recording(request: RecordRequest):
    """Start recording a new workflow"""
    try:
        workflow_name = recorder.start_recording(request.workflow_name)
        return {
            "status": "recording",
            "workflow_name": workflow_name,
            "message": "Recording started. Press ESC to stop."
        }
    except Exception as e:
        logger.error(f"Failed to start recording: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/record/stop")
async def stop_recording():
    """Stop recording current workflow"""
    try:
        filepath = recorder.stop_recording()
        
        if not filepath:
            raise HTTPException(status_code=400, detail="No recording in progress")
        
        return {
            "status": "saved",
            "filepath": str(filepath),
            "message": "Workflow saved successfully"
        }
    except Exception as e:
        logger.error(f"Failed to stop recording: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/list", response_model=List[WorkflowInfo])
async def list_workflows():
    """List all saved workflows"""
    try:
        workflows = recorder.list_workflows()
        return workflows
    except Exception as e:
        logger.error(f"Failed to list workflows: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/replay")
async def replay_workflow(request: ReplayRequest):
    """Replay a saved workflow"""
    try:
        recorder.replay_workflow(request.workflow_name, request.speed)
        return {
            "status": "completed",
            "workflow_name": request.workflow_name,
            "message": "Workflow replayed successfully"
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Workflow not found: {request.workflow_name}")
    except Exception as e:
        logger.error(f"Failed to replay workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{workflow_name}")
async def delete_workflow(workflow_name: str):
    """Delete a workflow"""
    try:
        success = recorder.delete_workflow(workflow_name)
        
        if not success:
            raise HTTPException(status_code=404, detail=f"Workflow not found: {workflow_name}")
        
        return {
            "status": "deleted",
            "workflow_name": workflow_name,
            "message": "Workflow deleted successfully"
        }
    except Exception as e:
        logger.error(f"Failed to delete workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Template endpoints
@router.get("/templates", response_model=List[TemplateInfo])
async def list_templates(category: Optional[str] = None):
    """List all workflow templates"""
    try:
        templates = WorkflowTemplates.list_templates(category)
        return templates
    except Exception as e:
        logger.error(f"Failed to list templates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/{template_name}")
async def get_template(template_name: str):
    """Get a specific template"""
    try:
        template = WorkflowTemplates.get_template(template_name)
        
        if not template:
            raise HTTPException(status_code=404, detail=f"Template not found: {template_name}")
        
        return template
    except Exception as e:
        logger.error(f"Failed to get template: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/categories")
async def get_categories():
    """Get all template categories"""
    try:
        categories = WorkflowTemplates.get_categories()
        return {"categories": categories}
    except Exception as e:
        logger.error(f"Failed to get categories: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates/search/{query}")
async def search_templates(query: str):
    """Search templates by keyword"""
    try:
        results = WorkflowTemplates.search_templates(query)
        return {"results": results}
    except Exception as e:
        logger.error(f"Failed to search templates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_stats():
    """Get workflow statistics"""
    try:
        workflows = recorder.list_workflows()
        templates = WorkflowTemplates.list_templates()
        
        return {
            "saved_workflows": len(workflows),
            "total_templates": len(templates),
            "categories": len(WorkflowTemplates.get_categories()),
            "recording": recorder.recording
        }
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))
