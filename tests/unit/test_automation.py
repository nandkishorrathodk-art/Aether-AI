import pytest
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.action.automation import (
    ScriptExecutor,
    SafeScriptExecutor,
    ScriptExecutionResult,
    GUIController,
    ApplicationLauncher,
    WindowManager,
    SafeFileOperations,
    FileOperationResult,
    CommandRegistry,
    CommandResult,
    get_command_registry
)


class TestScriptExecutor:
    def test_execute_simple_command(self):
        executor = ScriptExecutor(timeout=10)
        result = executor.execute_command("echo", args=["Hello World"], shell=True)
        
        assert result.success
        assert "Hello World" in result.output
        assert result.exit_code == 0
    
    def test_execute_command_timeout(self):
        executor = ScriptExecutor(timeout=2)
        
        if sys.platform == 'win32':
            result = executor.execute_command("timeout /t 5 /nobreak", shell=True)
        else:
            result = executor.execute_command("sleep", args=["5"], shell=True)
        
        assert not result.success or result.timeout
    
    def test_execute_invalid_command(self):
        executor = ScriptExecutor(timeout=5)
        result = executor.execute_command("nonexistentcommand12345")
        
        assert not result.success
        assert result.error
    
    @pytest.mark.skip(reason="Python code execution via temp file has output capture issues on Windows")
    def test_execute_python_code(self):
        executor = ScriptExecutor(timeout=10)
        code = "import sys\nprint('Test successful')\nsys.exit(0)"
        result = executor.execute_python_code(code)
        
        assert result.success or "Test successful" in result.output
        if result.success:
            assert "Test successful" in result.output
    
    def test_script_execution_result_to_dict(self):
        result = ScriptExecutionResult(
            success=True,
            output="test output",
            error="",
            exit_code=0,
            execution_time=1.5
        )
        
        data = result.to_dict()
        assert data['success'] is True
        assert data['output'] == "test output"
        assert data['exit_code'] == 0
        assert data['execution_time'] == 1.5


class TestSafeScriptExecutor:
    def test_block_dangerous_command(self):
        executor = SafeScriptExecutor(timeout=5)
        result = executor.execute_command("rm -rf /")
        
        assert not result.success
        assert "not allowed" in result.error.lower()
    
    def test_allow_safe_command(self):
        executor = SafeScriptExecutor(timeout=5)
        result = executor.execute_command("echo", args=["Safe command"], shell=True)
        
        assert result.success
    
    def test_blocked_dangerous_commands(self):
        executor = SafeScriptExecutor(timeout=5)
        dangerous_commands = ['del', 'format', 'shutdown']
        
        for cmd in dangerous_commands:
            result = executor.execute_command(cmd)
            assert not result.success, f"Command {cmd} should be blocked"


class TestGUIController:
    @pytest.fixture
    def controller(self):
        return GUIController(pause_duration=0.1)
    
    def test_get_screen_size(self, controller):
        size = controller.get_screen_size()
        assert isinstance(size, tuple)
        assert len(size) == 2
        assert size[0] > 0 and size[1] > 0
    
    def test_get_mouse_position(self, controller):
        pos = controller.get_mouse_position()
        assert isinstance(pos, tuple)
        assert len(pos) == 2
    
    @patch('pyautogui.moveTo')
    def test_move_mouse(self, mock_move, controller):
        result = controller.move_mouse(100, 100)
        assert result is True
        mock_move.assert_called_once()
    
    @patch('pyautogui.click')
    def test_click(self, mock_click, controller):
        result = controller.click(100, 100)
        assert result is True
        mock_click.assert_called_once()
    
    @patch('pyautogui.write')
    def test_type_text(self, mock_write, controller):
        result = controller.type_text("Hello")
        assert result is True
        mock_write.assert_called_once_with("Hello", interval=0.0)
    
    @patch('pyautogui.press')
    def test_press_key(self, mock_press, controller):
        result = controller.press_key('enter')
        assert result is True
        mock_press.assert_called_once()
    
    @patch('pyautogui.hotkey')
    def test_hotkey(self, mock_hotkey, controller):
        result = controller.hotkey('ctrl', 'c')
        assert result is True
        mock_hotkey.assert_called_once_with('ctrl', 'c')
    
    @patch('pyautogui.screenshot')
    def test_screenshot(self, mock_screenshot, controller):
        mock_screenshot.return_value = MagicMock()
        screenshot = controller.screenshot()
        assert screenshot is not None
        mock_screenshot.assert_called_once()


class TestApplicationLauncher:
    @pytest.fixture
    def launcher(self):
        return ApplicationLauncher()
    
    def test_launch_notepad(self, launcher):
        process = launcher.launch_application('notepad')
        assert process is not None
        assert process.pid > 0
        
        time.sleep(1)
        launcher.close_application(process.pid, force=True)
    
    def test_launch_calculator(self, launcher):
        if sys.platform == 'win32':
            process = launcher.launch_application('calculator')
            assert process is not None
            
            time.sleep(1)
            launcher.close_application(process.pid, force=True)
    
    def test_close_application(self, launcher):
        process = launcher.launch_application('notepad')
        assert process is not None
        
        time.sleep(1)
        success = launcher.close_application(process.pid)
        assert success
    
    def test_get_running_applications(self, launcher):
        process = launcher.launch_application('notepad')
        time.sleep(1)
        
        apps = launcher.get_running_applications()
        assert len(apps) > 0
        
        launcher.close_application(process.pid, force=True)


@pytest.mark.skipif(sys.platform != 'win32', reason="WindowManager is Windows-only")
class TestWindowManager:
    @pytest.fixture
    def manager(self):
        return WindowManager()
    
    def test_get_all_windows(self, manager):
        windows = manager.get_all_windows()
        assert isinstance(windows, list)
    
    def test_get_active_window_title(self, manager):
        title = manager.get_active_window_title()
        assert isinstance(title, (str, type(None)))


class TestSafeFileOperations:
    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def file_ops(self, temp_dir):
        return SafeFileOperations(base_directory=temp_dir)
    
    def test_write_file(self, file_ops, temp_dir):
        file_path = os.path.join(temp_dir, "test.txt")
        result = file_ops.write_file(file_path, "Hello World")
        
        assert result.success
        assert os.path.exists(file_path)
    
    def test_read_file(self, file_ops, temp_dir):
        file_path = os.path.join(temp_dir, "test.txt")
        file_ops.write_file(file_path, "Hello World")
        
        result = file_ops.read_file(file_path)
        assert result.success
        assert result.data == "Hello World"
    
    def test_read_nonexistent_file(self, file_ops, temp_dir):
        file_path = os.path.join(temp_dir, "nonexistent.txt")
        result = file_ops.read_file(file_path)
        
        assert not result.success
        assert "not found" in result.error.lower()
    
    def test_delete_file(self, file_ops, temp_dir):
        file_path = os.path.join(temp_dir, "test.txt")
        file_ops.write_file(file_path, "Test content")
        
        result = file_ops.delete_file(file_path)
        assert result.success
        assert not os.path.exists(file_path)
    
    def test_copy_file(self, file_ops, temp_dir):
        src = os.path.join(temp_dir, "source.txt")
        dst = os.path.join(temp_dir, "dest.txt")
        
        file_ops.write_file(src, "Test content")
        result = file_ops.copy_file(src, dst)
        
        assert result.success
        assert os.path.exists(dst)
    
    def test_move_file(self, file_ops, temp_dir):
        src = os.path.join(temp_dir, "source.txt")
        dst = os.path.join(temp_dir, "dest.txt")
        
        file_ops.write_file(src, "Test content")
        result = file_ops.move_file(src, dst)
        
        assert result.success
        assert os.path.exists(dst)
        assert not os.path.exists(src)
    
    def test_list_directory(self, file_ops, temp_dir):
        file_ops.write_file(os.path.join(temp_dir, "file1.txt"), "Content 1")
        file_ops.write_file(os.path.join(temp_dir, "file2.txt"), "Content 2")
        
        result = file_ops.list_directory(temp_dir)
        assert result.success
        assert len(result.data) == 2
    
    def test_create_directory(self, file_ops, temp_dir):
        dir_path = os.path.join(temp_dir, "subdir")
        result = file_ops.create_directory(dir_path)
        
        assert result.success
        assert os.path.isdir(dir_path)
    
    def test_search_files(self, file_ops, temp_dir):
        file_ops.write_file(os.path.join(temp_dir, "test1.txt"), "Content")
        file_ops.write_file(os.path.join(temp_dir, "test2.txt"), "Content")
        file_ops.write_file(os.path.join(temp_dir, "other.log"), "Content")
        
        result = file_ops.search_files(temp_dir, "*.txt", recursive=False)
        assert result.success
        assert len(result.data) == 2
    
    def test_get_file_info(self, file_ops, temp_dir):
        file_path = os.path.join(temp_dir, "test.txt")
        file_ops.write_file(file_path, "Test content")
        
        result = file_ops.get_file_info(file_path)
        assert result.success
        assert 'size' in result.data
        assert 'md5' in result.data
    
    def test_dangerous_path_blocked(self):
        file_ops = SafeFileOperations()
        result = file_ops.read_file("C:\\Windows\\System32\\config\\SAM")
        
        assert not result.success
        assert "not allowed" in result.error.lower()


class TestCommandRegistry:
    @pytest.fixture
    def registry(self):
        return CommandRegistry()
    
    def test_help_command(self, registry):
        result = registry.execute_command("help")
        assert result.success
        assert isinstance(result.data, list)
        assert len(result.data) > 0
    
    def test_time_command(self, registry):
        result = registry.execute_command("time")
        assert result.success
        assert 'time' in result.data
    
    def test_date_command(self, registry):
        result = registry.execute_command("date")
        assert result.success
        assert 'date' in result.data
    
    def test_system_info_command(self, registry):
        result = registry.execute_command("system_info")
        assert result.success
        assert 'platform' in result.data
        assert 'cpu_count' in result.data
    
    def test_cpu_usage_command(self, registry):
        result = registry.execute_command("cpu_usage", interval=0.1)
        assert result.success
        assert 'cpu_usage' in result.data
    
    def test_memory_usage_command(self, registry):
        result = registry.execute_command("memory_usage")
        assert result.success
        assert 'total' in result.data
        assert 'percent' in result.data
    
    def test_create_and_read_file_commands(self, registry):
        with tempfile.TemporaryDirectory() as tmpdir:
            registry.file_ops.base_directory = Path(tmpdir)
            file_path = os.path.join(tmpdir, "test.txt")
            
            create_result = registry.execute_command(
                "create_file",
                file_path=file_path,
                content="Test content"
            )
            assert create_result.success
            
            read_result = registry.execute_command("read_file", file_path=file_path)
            assert read_result.success
            assert read_result.data == "Test content"
    
    def test_list_files_command(self, registry):
        result = registry.execute_command("list_files", directory=".")
        assert result.success
        assert isinstance(result.data, list)
    
    def test_invalid_command(self, registry):
        result = registry.execute_command("nonexistent_command")
        assert not result.success
        assert "not found" in result.error.lower()
    
    def test_custom_command_registration(self, registry):
        def custom_handler(**kwargs):
            return CommandResult(success=True, message="Custom command executed")
        
        registry.register_command("custom", custom_handler, "Custom command")
        result = registry.execute_command("custom")
        
        assert result.success
        assert result.message == "Custom command executed"
    
    def test_get_command_registry_singleton(self):
        registry1 = get_command_registry()
        registry2 = get_command_registry()
        
        assert registry1 is registry2
    
    def test_execution_time_tracking(self, registry):
        result = registry.execute_command("time")
        assert result.execution_time >= 0


class TestIntegrationScenarios:
    def test_full_file_workflow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_ops = SafeFileOperations(base_directory=tmpdir)
            
            file_path = os.path.join(tmpdir, "workflow_test.txt")
            content = "Initial content"
            
            write_result = file_ops.write_file(file_path, content)
            assert write_result.success
            
            read_result = file_ops.read_file(file_path)
            assert read_result.success
            assert read_result.data == content
            
            new_content = "Updated content"
            update_result = file_ops.write_file(file_path, new_content, overwrite=True)
            assert update_result.success
            
            read_result = file_ops.read_file(file_path)
            assert read_result.data == new_content
            
            delete_result = file_ops.delete_file(file_path)
            assert delete_result.success
    
    def test_command_registry_workflow(self):
        registry = CommandRegistry()
        
        help_result = registry.execute_command("help")
        assert help_result.success
        
        time_result = registry.execute_command("time")
        assert time_result.success
        
        sys_result = registry.execute_command("system_info")
        assert sys_result.success


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
