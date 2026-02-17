from typing import Optional, Dict, Any, Callable
import asyncio

from src.control.models import (
    ActionType,
    MouseButton,
    ControlAction,
    ActionResult
)
from src.control.permission_manager import PermissionManager
from src.control.mouse_keyboard import MouseKeyboardController
from src.control.app_launcher import AppLauncher
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PCController:
    
    def __init__(self):
        self.permission_manager = PermissionManager()
        self.mouse_keyboard = MouseKeyboardController()
        self.app_launcher = AppLauncher()
        self._confirmation_callback: Optional[Callable] = None
    
    def set_confirmation_callback(self, callback: Callable[[ControlAction], bool]):
        self._confirmation_callback = callback
    
    async def execute_action(self, action: ControlAction, user_id: Optional[str] = None, auto_confirm: bool = False) -> ActionResult:
        if not self.permission_manager.is_action_allowed(action):
            result = ActionResult(
                success=False,
                action_type=action.action_type,
                error="Action not allowed by permission rules"
            )
            await self.permission_manager.log_action(action, result, user_id)
            return result
        
        requires_confirmation = self.permission_manager.requires_confirmation(action)
        confirmed = False
        
        if requires_confirmation and not auto_confirm:
            if self._confirmation_callback:
                confirmed = self._confirmation_callback(action)
            else:
                logger.warning(f"Action requires confirmation but no callback set: {action.action_type}")
                result = ActionResult(
                    success=False,
                    action_type=action.action_type,
                    error="Confirmation required but no callback available"
                )
                await self.permission_manager.log_action(action, result, user_id)
                return result
            
            if not confirmed:
                result = ActionResult(
                    success=False,
                    action_type=action.action_type,
                    error="Action not confirmed by user",
                    confirmed=False
                )
                await self.permission_manager.log_action(action, result, user_id)
                return result
        else:
            confirmed = auto_confirm or not requires_confirmation
        
        try:
            result = await self._route_action(action)
            result.confirmed = confirmed
            await self.permission_manager.log_action(action, result, user_id)
            return result
        except Exception as e:
            logger.error(f"Error executing action {action.action_type}: {e}")
            result = ActionResult(
                success=False,
                action_type=action.action_type,
                error=str(e),
                confirmed=confirmed
            )
            await self.permission_manager.log_action(action, result, user_id)
            return result
    
    async def _route_action(self, action: ControlAction) -> ActionResult:
        if action.action_type == ActionType.MOUSE_CLICK:
            return await self._handle_mouse_click(action)
        elif action.action_type == ActionType.MOUSE_MOVE:
            return await self._handle_mouse_move(action)
        elif action.action_type == ActionType.KEYBOARD_TYPE:
            return await self._handle_keyboard_type(action)
        elif action.action_type == ActionType.KEYBOARD_PRESS:
            return await self._handle_keyboard_press(action)
        elif action.action_type == ActionType.APP_LAUNCH:
            return await self._handle_app_launch(action)
        elif action.action_type == ActionType.APP_CLOSE:
            return await self._handle_app_close(action)
        else:
            return ActionResult(
                success=False,
                action_type=action.action_type,
                error=f"Unknown action type: {action.action_type}"
            )
    
    async def _handle_mouse_click(self, action: ControlAction) -> ActionResult:
        button_str = action.parameters.get('button', 'left')
        try:
            button = MouseButton(button_str)
        except ValueError:
            button = MouseButton.LEFT
        
        x = action.parameters.get('x')
        y = action.parameters.get('y')
        
        return await self.mouse_keyboard.click_mouse(button, x, y)
    
    async def _handle_mouse_move(self, action: ControlAction) -> ActionResult:
        x = action.parameters.get('x')
        y = action.parameters.get('y')
        
        if x is None or y is None:
            return ActionResult(
                success=False,
                action_type=ActionType.MOUSE_MOVE,
                error="Missing x or y coordinates"
            )
        
        return await self.mouse_keyboard.move_mouse(int(x), int(y))
    
    async def _handle_keyboard_type(self, action: ControlAction) -> ActionResult:
        text = action.parameters.get('text', '')
        delay = action.parameters.get('delay', 0.0)
        
        return await self.mouse_keyboard.type_text(text, delay)
    
    async def _handle_keyboard_press(self, action: ControlAction) -> ActionResult:
        key = action.parameters.get('key', '')
        
        return await self.mouse_keyboard.press_key(key)
    
    async def _handle_app_launch(self, action: ControlAction) -> ActionResult:
        app_name = action.parameters.get('app_name', '')
        args = action.parameters.get('args')
        
        if not app_name:
            return ActionResult(
                success=False,
                action_type=ActionType.APP_LAUNCH,
                error="Missing app_name parameter"
            )
        
        return await self.app_launcher.launch_app(app_name, args)
    
    async def _handle_app_close(self, action: ControlAction) -> ActionResult:
        app_name = action.parameters.get('app_name', '')
        force = action.parameters.get('force', False)
        
        if not app_name:
            return ActionResult(
                success=False,
                action_type=ActionType.APP_CLOSE,
                error="Missing app_name parameter"
            )
        
        return await self.app_launcher.close_app(app_name, force)
    
    async def get_system_info(self) -> Dict[str, Any]:
        return {
            'mouse_position': self.mouse_keyboard.get_mouse_position(),
            'screen_bounds': self.mouse_keyboard.screen_bounds,
            'app_shortcuts': self.app_launcher.get_app_shortcuts(),
            'permissions': self.permission_manager.get_all_permissions(),
            'whitelisted_actions': [a.value for a in self.permission_manager.get_whitelisted_actions()],
            'blacklisted_actions': [a.value for a in self.permission_manager.get_blacklisted_actions()]
        }
    
    async def rollback_action(self, action: ControlAction) -> ActionResult:
        logger.warning(f"Rollback requested for {action.action_type} - not implemented")
        return ActionResult(
            success=False,
            action_type=action.action_type,
            error="Rollback not implemented for this action type"
        )
