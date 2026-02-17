from fastapi import APIRouter, HTTPException, Depends
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from src.control import (
    get_pc_controller,
    ActionType,
    MouseButton,
    ControlAction,
)
from src.config import settings
from src.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/control", tags=["pc_control"])


class MouseClickRequest(BaseModel):
    button: str = "left"
    x: Optional[int] = None
    y: Optional[int] = None
    auto_confirm: bool = False


class MouseMoveRequest(BaseModel):
    x: int
    y: int
    auto_confirm: bool = False


class KeyboardTypeRequest(BaseModel):
    text: str
    delay: float = 0.0
    auto_confirm: bool = False


class KeyboardPressRequest(BaseModel):
    key: str
    auto_confirm: bool = False


class AppLaunchRequest(BaseModel):
    app_name: str
    args: Optional[List[str]] = None
    auto_confirm: bool = False


class AppCloseRequest(BaseModel):
    app_name: str
    force: bool = False
    auto_confirm: bool = False


def check_pc_control_enabled():
    if not settings.enable_pc_control:
        raise HTTPException(
            status_code=403,
            detail="PC control is disabled in settings"
        )


@router.post("/mouse/click")
async def click_mouse(
    request: MouseClickRequest,
    _: None = Depends(check_pc_control_enabled)
):
    controller = get_pc_controller()
    
    action = ControlAction(
        action_type=ActionType.MOUSE_CLICK,
        parameters={
            "button": request.button,
            "x": request.x,
            "y": request.y
        },
        description=f"Click mouse {request.button} button" + (f" at ({request.x}, {request.y})" if request.x and request.y else "")
    )
    
    result = await controller.execute_action(action, auto_confirm=request.auto_confirm)
    
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    
    return {
        "success": result.success,
        "message": result.message,
        "executed": result.executed,
        "confirmed": result.confirmed
    }


@router.post("/mouse/move")
async def move_mouse(
    request: MouseMoveRequest,
    _: None = Depends(check_pc_control_enabled)
):
    controller = get_pc_controller()
    
    action = ControlAction(
        action_type=ActionType.MOUSE_MOVE,
        parameters={
            "x": request.x,
            "y": request.y
        },
        description=f"Move mouse to ({request.x}, {request.y})"
    )
    
    result = await controller.execute_action(action, auto_confirm=request.auto_confirm)
    
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    
    return {
        "success": result.success,
        "message": result.message,
        "executed": result.executed,
        "confirmed": result.confirmed
    }


@router.post("/keyboard/type")
async def type_text(
    request: KeyboardTypeRequest,
    _: None = Depends(check_pc_control_enabled)
):
    controller = get_pc_controller()
    
    action = ControlAction(
        action_type=ActionType.KEYBOARD_TYPE,
        parameters={
            "text": request.text,
            "delay": request.delay
        },
        description=f"Type text: {request.text[:50]}{'...' if len(request.text) > 50 else ''}"
    )
    
    result = await controller.execute_action(action, auto_confirm=request.auto_confirm)
    
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    
    return {
        "success": result.success,
        "message": result.message,
        "executed": result.executed,
        "confirmed": result.confirmed
    }


@router.post("/keyboard/press")
async def press_key(
    request: KeyboardPressRequest,
    _: None = Depends(check_pc_control_enabled)
):
    controller = get_pc_controller()
    
    action = ControlAction(
        action_type=ActionType.KEYBOARD_PRESS,
        parameters={
            "key": request.key
        },
        description=f"Press key: {request.key}"
    )
    
    result = await controller.execute_action(action, auto_confirm=request.auto_confirm)
    
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    
    return {
        "success": result.success,
        "message": result.message,
        "executed": result.executed,
        "confirmed": result.confirmed
    }


@router.post("/app/launch")
async def launch_app(
    request: AppLaunchRequest,
    _: None = Depends(check_pc_control_enabled)
):
    controller = get_pc_controller()
    
    action = ControlAction(
        action_type=ActionType.APP_LAUNCH,
        parameters={
            "app_name": request.app_name,
            "args": request.args
        },
        description=f"Launch application: {request.app_name}"
    )
    
    result = await controller.execute_action(action, auto_confirm=request.auto_confirm)
    
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    
    return {
        "success": result.success,
        "message": result.message,
        "executed": result.executed,
        "confirmed": result.confirmed
    }


@router.post("/app/close")
async def close_app(
    request: AppCloseRequest,
    _: None = Depends(check_pc_control_enabled)
):
    controller = get_pc_controller()
    
    action = ControlAction(
        action_type=ActionType.APP_CLOSE,
        parameters={
            "app_name": request.app_name,
            "force": request.force
        },
        description=f"Close application: {request.app_name}" + (" (force)" if request.force else "")
    )
    
    result = await controller.execute_action(action, auto_confirm=request.auto_confirm)
    
    if not result.success:
        raise HTTPException(status_code=400, detail=result.error)
    
    return {
        "success": result.success,
        "message": result.message,
        "executed": result.executed,
        "confirmed": result.confirmed
    }


@router.get("/permissions")
async def get_permissions(_: None = Depends(check_pc_control_enabled)):
    controller = get_pc_controller()
    return controller.permission_manager.get_all_permissions()


@router.get("/system-info")
async def get_system_info(_: None = Depends(check_pc_control_enabled)):
    controller = get_pc_controller()
    info = await controller.get_system_info()
    return info


@router.get("/audit-log")
async def get_audit_log(limit: int = 100, _: None = Depends(check_pc_control_enabled)):
    controller = get_pc_controller()
    logs = await controller.permission_manager.get_recent_logs(limit)
    return {"logs": logs, "count": len(logs)}


@router.get("/app-shortcuts")
async def get_app_shortcuts(_: None = Depends(check_pc_control_enabled)):
    controller = get_pc_controller()
    return controller.app_launcher.get_app_shortcuts()


@router.get("/running-apps")
async def get_running_apps(_: None = Depends(check_pc_control_enabled)):
    controller = get_pc_controller()
    apps = await controller.app_launcher.get_running_apps()
    return {"apps": apps, "count": len(apps)}


@router.get("/check-app/{app_name}")
async def check_app_running(app_name: str, _: None = Depends(check_pc_control_enabled)):
    controller = get_pc_controller()
    is_running = await controller.app_launcher.is_app_running(app_name)
    return {"app_name": app_name, "running": is_running}
