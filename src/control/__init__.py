from src.control.models import (
    ActionType,
    MouseButton,
    ControlAction,
    ActionResult,
    PermissionRule,
    AuditLogEntry
)
from src.control.permission_manager import PermissionManager
from src.control.mouse_keyboard import MouseKeyboardController
from src.control.app_launcher import AppLauncher
from src.control.pc_controller import PCController

_permission_manager = None
_mouse_keyboard_controller = None
_app_launcher = None
_pc_controller = None


def get_permission_manager() -> PermissionManager:
    global _permission_manager
    if _permission_manager is None:
        _permission_manager = PermissionManager()
    return _permission_manager


def get_mouse_keyboard_controller() -> MouseKeyboardController:
    global _mouse_keyboard_controller
    if _mouse_keyboard_controller is None:
        _mouse_keyboard_controller = MouseKeyboardController()
    return _mouse_keyboard_controller


def get_app_launcher() -> AppLauncher:
    global _app_launcher
    if _app_launcher is None:
        _app_launcher = AppLauncher()
    return _app_launcher


def get_pc_controller() -> PCController:
    global _pc_controller
    if _pc_controller is None:
        _pc_controller = PCController()
    return _pc_controller


__all__ = [
    "ActionType",
    "MouseButton",
    "ControlAction",
    "ActionResult",
    "PermissionRule",
    "AuditLogEntry",
    "PermissionManager",
    "MouseKeyboardController",
    "AppLauncher",
    "PCController",
    "get_permission_manager",
    "get_mouse_keyboard_controller",
    "get_app_launcher",
    "get_pc_controller",
]
