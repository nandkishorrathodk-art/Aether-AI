import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from pathlib import Path
import tempfile
import json

from src.control import (
    get_pc_controller,
    get_permission_manager,
    get_mouse_keyboard_controller,
    get_app_launcher,
    ActionType,
    MouseButton,
    ControlAction,
    ActionResult,
    PermissionRule,
    PermissionManager,
    MouseKeyboardController,
    AppLauncher,
    PCController
)


@pytest.fixture
def temp_permission_path(tmp_path):
    with patch('src.config.settings.pc_control_audit_log', tmp_path / 'audit.log'):
        yield tmp_path


class TestPermissionManager:
    
    def test_load_default_permissions(self, temp_permission_path):
        with patch('src.config.settings.pc_control_audit_log', temp_permission_path / 'audit.log'):
            with patch('src.config.settings.pc_control_allowed_actions', 'mouse_click,keyboard_type'):
                with patch('src.config.settings.pc_control_require_confirmation', True):
                    manager = PermissionManager()
                    
                    assert ActionType.MOUSE_CLICK in manager.permissions
                    assert manager.permissions[ActionType.MOUSE_CLICK].allowed is True
                    assert manager.permissions[ActionType.KEYBOARD_TYPE].allowed is True
    
    def test_is_action_allowed(self, temp_permission_path):
        with patch('src.config.settings.pc_control_audit_log', temp_permission_path / 'audit.log'):
            with patch('src.config.settings.enable_pc_control', True):
                with patch('src.config.settings.pc_control_allowed_actions', 'mouse_click'):
                    manager = PermissionManager()
                    
                    action = ControlAction(
                        action_type=ActionType.MOUSE_CLICK,
                        parameters={}
                    )
                    
                    assert manager.is_action_allowed(action) is True
    
    def test_is_action_blocked(self, temp_permission_path):
        with patch('src.config.settings.pc_control_audit_log', temp_permission_path / 'audit.log'):
            with patch('src.config.settings.enable_pc_control', False):
                manager = PermissionManager()
                
                action = ControlAction(
                    action_type=ActionType.MOUSE_CLICK,
                    parameters={}
                )
                
                assert manager.is_action_allowed(action) is False
    
    @pytest.mark.asyncio
    async def test_log_action(self, temp_permission_path):
        audit_log = temp_permission_path / 'audit.log'
        
        with patch('src.config.settings.pc_control_audit_log', audit_log):
            manager = PermissionManager()
            
            action = ControlAction(
                action_type=ActionType.MOUSE_CLICK,
                parameters={'x': 100, 'y': 200}
            )
            
            result = ActionResult(
                success=True,
                action_type=ActionType.MOUSE_CLICK,
                executed=True,
                confirmed=True
            )
            
            await manager.log_action(action, result)
            
            assert audit_log.exists()
            
            with open(audit_log, 'r') as f:
                logs = f.read()
                assert 'mouse_click' in logs
                assert 'SUCCESS' in logs
    
    def test_update_permission(self, temp_permission_path):
        with patch('src.config.settings.pc_control_audit_log', temp_permission_path / 'audit.log'):
            manager = PermissionManager()
            
            manager.update_permission(
                ActionType.MOUSE_CLICK,
                allowed=False,
                require_confirmation=True,
                reason="Test block"
            )
            
            assert manager.permissions[ActionType.MOUSE_CLICK].allowed is False
            assert manager.permissions[ActionType.MOUSE_CLICK].reason == "Test block"


class TestMouseKeyboardController:
    
    @pytest.mark.asyncio
    async def test_move_mouse(self):
        controller = MouseKeyboardController()
        controller.screen_bounds = (1920, 1080)
        
        with patch('asyncio.to_thread', new_callable=AsyncMock) as mock_thread:
            result = await controller.move_mouse(100, 200)
            
            assert result.success is True
            assert result.action_type == ActionType.MOUSE_MOVE
            assert result.executed is True
    
    @pytest.mark.asyncio
    async def test_move_mouse_out_of_bounds(self):
        controller = MouseKeyboardController()
        
        result = await controller.move_mouse(-100, -200)
        
        assert result.success is False
        assert "out of screen bounds" in result.error
    
    @pytest.mark.asyncio
    async def test_click_mouse(self):
        controller = MouseKeyboardController()
        
        with patch.object(controller.mouse_controller, 'click') as mock_click:
            result = await controller.click_mouse(MouseButton.LEFT)
            
            assert result.success is True
            assert result.action_type == ActionType.MOUSE_CLICK
            assert result.executed is True
    
    @pytest.mark.asyncio
    async def test_type_text(self):
        controller = MouseKeyboardController()
        
        with patch.object(controller.keyboard_controller, 'press') as mock_press:
            with patch.object(controller.keyboard_controller, 'release') as mock_release:
                result = await controller.type_text("Hello")
                
                assert result.success is True
                assert result.action_type == ActionType.KEYBOARD_TYPE
                assert result.executed is True
    
    @pytest.mark.asyncio
    async def test_type_text_empty(self):
        controller = MouseKeyboardController()
        
        result = await controller.type_text("")
        
        assert result.success is False
        assert "Empty text" in result.error
    
    @pytest.mark.asyncio
    async def test_type_text_too_long(self):
        controller = MouseKeyboardController()
        
        result = await controller.type_text("a" * 1001)
        
        assert result.success is False
        assert "too long" in result.error
    
    @pytest.mark.asyncio
    async def test_press_key(self):
        controller = MouseKeyboardController()
        
        with patch.object(controller.keyboard_controller, 'press') as mock_press:
            with patch.object(controller.keyboard_controller, 'release') as mock_release:
                result = await controller.press_key("enter")
                
                assert result.success is True
                assert result.action_type == ActionType.KEYBOARD_PRESS
                assert result.executed is True


class TestAppLauncher:
    
    @pytest.mark.asyncio
    async def test_launch_system_app(self):
        launcher = AppLauncher()
        
        with patch('asyncio.to_thread') as mock_thread:
            mock_process = Mock()
            mock_process.pid = 12345
            mock_thread.return_value = mock_process
            
            result = await launcher.launch_app("notepad")
            
            assert result.success is True
            assert result.action_type == ActionType.APP_LAUNCH
            assert result.executed is True
            assert "12345" in result.message
    
    @pytest.mark.asyncio
    async def test_launch_nonexistent_app(self):
        launcher = AppLauncher()
        
        result = await launcher.launch_app("nonexistentapp123.exe")
        
        assert result.success is False
        assert "not found" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_close_app(self):
        launcher = AppLauncher()
        
        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {'pid': 123, 'name': 'notepad.exe', 'exe': 'C:\\Windows\\notepad.exe'}
            mock_proc.terminate = Mock()
            mock_proc.wait = Mock()
            mock_iter.return_value = [mock_proc]
            
            result = await launcher.close_app("notepad")
            
            assert result.success is True
            assert result.action_type == ActionType.APP_CLOSE
    
    @pytest.mark.asyncio
    async def test_close_app_not_running(self):
        launcher = AppLauncher()
        
        with patch('psutil.process_iter', return_value=[]):
            result = await launcher.close_app("notepad")
            
            assert result.success is False
            assert "No running process" in result.error
    
    @pytest.mark.asyncio
    async def test_is_app_running(self):
        launcher = AppLauncher()
        
        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {'name': 'notepad.exe', 'exe': 'C:\\Windows\\notepad.exe'}
            mock_iter.return_value = [mock_proc]
            
            is_running = await launcher.is_app_running("notepad")
            
            assert is_running is True
    
    @pytest.mark.asyncio
    async def test_get_running_apps(self):
        launcher = AppLauncher()
        
        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 123,
                'name': 'notepad.exe',
                'exe': 'C:\\Windows\\notepad.exe',
                'create_time': 1234567890
            }
            mock_iter.return_value = [mock_proc]
            
            apps = await launcher.get_running_apps()
            
            assert len(apps) > 0
            assert apps[0]['name'] == 'notepad.exe'


class TestPCController:
    
    @pytest.mark.asyncio
    async def test_execute_action_allowed(self, temp_permission_path):
        with patch('src.config.settings.pc_control_audit_log', temp_permission_path / 'audit.log'):
            with patch('src.config.settings.enable_pc_control', True):
                with patch('src.config.settings.pc_control_allowed_actions', 'mouse_click'):
                    controller = PCController()
                    
                    with patch.object(controller.mouse_keyboard, 'click_mouse') as mock_click:
                        mock_click.return_value = ActionResult(
                            success=True,
                            action_type=ActionType.MOUSE_CLICK,
                            executed=True
                        )
                        
                        action = ControlAction(
                            action_type=ActionType.MOUSE_CLICK,
                            parameters={'button': 'left'},
                            require_confirmation=False
                        )
                        
                        result = await controller.execute_action(action, auto_confirm=True)
                        
                        assert result.success is True
                        assert result.executed is True
    
    @pytest.mark.asyncio
    async def test_execute_action_blocked(self, temp_permission_path):
        with patch('src.config.settings.pc_control_audit_log', temp_permission_path / 'audit.log'):
            with patch('src.config.settings.enable_pc_control', False):
                controller = PCController()
                
                action = ControlAction(
                    action_type=ActionType.MOUSE_CLICK,
                    parameters={'button': 'left'}
                )
                
                result = await controller.execute_action(action)
                
                assert result.success is False
                assert "not allowed" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_execute_action_needs_confirmation(self, temp_permission_path):
        with patch('src.config.settings.pc_control_audit_log', temp_permission_path / 'audit.log'):
            with patch('src.config.settings.enable_pc_control', True):
                with patch('src.config.settings.pc_control_allowed_actions', 'mouse_click'):
                    controller = PCController()
                    
                    action = ControlAction(
                        action_type=ActionType.MOUSE_CLICK,
                        parameters={'button': 'left'},
                        require_confirmation=True
                    )
                    
                    result = await controller.execute_action(action, auto_confirm=False)
                    
                    assert result.success is False
                    assert "confirmation" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_get_system_info(self, temp_permission_path):
        with patch('src.config.settings.pc_control_audit_log', temp_permission_path / 'audit.log'):
            controller = PCController()
            
            info = await controller.get_system_info()
            
            assert 'mouse_position' in info
            assert 'screen_bounds' in info
            assert 'app_shortcuts' in info
            assert 'permissions' in info
