import os
import sys
import time
import platform
import psutil
from typing import Dict, Any, Callable, Optional, List
from datetime import datetime

from src.action.automation.script_executor import SafeScriptExecutor, ScriptExecutionResult
from src.action.automation.gui_control import ApplicationLauncher, GUIController, WindowManager
from src.action.automation.file_operations import SafeFileOperations, FileOperationResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CommandResult:
    def __init__(
        self,
        success: bool,
        message: str = "",
        data: Optional[Any] = None,
        error: Optional[str] = None,
        execution_time: float = 0.0
    ):
        self.success = success
        self.message = message
        self.data = data
        self.error = error
        self.execution_time = execution_time
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "error": self.error,
            "execution_time": self.execution_time
        }
    
    def __repr__(self):
        return f"CommandResult(success={self.success}, message='{self.message}', time={self.execution_time:.3f}s)"


class CommandRegistry:
    def __init__(self):
        self.commands: Dict[str, Callable] = {}
        self.executor = SafeScriptExecutor(timeout=30)
        self.app_launcher = ApplicationLauncher()
        self.gui_controller = GUIController()
        self.window_manager = WindowManager()
        self.file_ops = SafeFileOperations()
        
        self._register_builtin_commands()
    
    def _register_builtin_commands(self):
        self.register_command("help", self.cmd_help, "Show available commands")
        self.register_command("time", self.cmd_time, "Get current time")
        self.register_command("date", self.cmd_date, "Get current date")
        self.register_command("system_info", self.cmd_system_info, "Get system information")
        self.register_command("open", self.cmd_open_app, "Open an application")
        self.register_command("close", self.cmd_close_app, "Close an application")
        self.register_command("search", self.cmd_search, "Search for files")
        self.register_command("create_file", self.cmd_create_file, "Create a new file")
        self.register_command("read_file", self.cmd_read_file, "Read file contents")
        self.register_command("list_files", self.cmd_list_files, "List files in directory")
        self.register_command("run_command", self.cmd_run_command, "Run a shell command")
        self.register_command("screenshot", self.cmd_screenshot, "Take a screenshot")
        self.register_command("type_text", self.cmd_type_text, "Type text via keyboard")
        self.register_command("press_key", self.cmd_press_key, "Press a keyboard key")
        self.register_command("get_windows", self.cmd_get_windows, "List all open windows")
        self.register_command("focus_window", self.cmd_focus_window, "Focus a window by title")
        self.register_command("cpu_usage", self.cmd_cpu_usage, "Get CPU usage percentage")
        self.register_command("memory_usage", self.cmd_memory_usage, "Get memory usage")
        self.register_command("disk_usage", self.cmd_disk_usage, "Get disk usage")
        self.register_command("network_info", self.cmd_network_info, "Get network information")
    
    def register_command(self, name: str, handler: Callable, description: str = ""):
        self.commands[name] = {
            'handler': handler,
            'description': description
        }
        logger.debug(f"Registered command: {name}")
    
    def execute_command(self, command_name: str, **kwargs) -> CommandResult:
        start_time = time.time()
        
        if command_name not in self.commands:
            return CommandResult(
                success=False,
                error=f"Command not found: {command_name}",
                execution_time=time.time() - start_time
            )
        
        try:
            handler = self.commands[command_name]['handler']
            result = handler(**kwargs)
            
            if isinstance(result, CommandResult):
                result.execution_time = time.time() - start_time
                return result
            elif isinstance(result, (FileOperationResult, ScriptExecutionResult)):
                return CommandResult(
                    success=result.success,
                    message=getattr(result, 'message', ''),
                    data=getattr(result, 'data', getattr(result, 'output', None)),
                    error=result.error,
                    execution_time=time.time() - start_time
                )
            else:
                return CommandResult(
                    success=True,
                    data=result,
                    execution_time=time.time() - start_time
                )
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return CommandResult(
                success=False,
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    def cmd_help(self) -> CommandResult:
        commands_list = []
        for name, info in self.commands.items():
            commands_list.append({
                'name': name,
                'description': info['description']
            })
        
        return CommandResult(
            success=True,
            message=f"Available commands: {len(commands_list)}",
            data=commands_list
        )
    
    def cmd_time(self) -> CommandResult:
        current_time = datetime.now().strftime("%H:%M:%S")
        return CommandResult(
            success=True,
            message=f"Current time: {current_time}",
            data={'time': current_time}
        )
    
    def cmd_date(self) -> CommandResult:
        current_date = datetime.now().strftime("%Y-%m-%d")
        return CommandResult(
            success=True,
            message=f"Current date: {current_date}",
            data={'date': current_date}
        )
    
    def cmd_system_info(self) -> CommandResult:
        info = {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': sys.version,
            'cpu_count': psutil.cpu_count(),
            'total_memory': psutil.virtual_memory().total,
            'available_memory': psutil.virtual_memory().available
        }
        
        return CommandResult(
            success=True,
            message="System information retrieved",
            data=info
        )
    
    def cmd_open_app(self, app_name: str, args: Optional[List[str]] = None) -> CommandResult:
        process = self.app_launcher.launch_application(app_name, args)
        if process:
            return CommandResult(
                success=True,
                message=f"Launched {app_name} (PID: {process.pid})",
                data={'pid': process.pid, 'app_name': app_name}
            )
        else:
            return CommandResult(
                success=False,
                error=f"Failed to launch {app_name}"
            )
    
    def cmd_close_app(self, pid: int, force: bool = False) -> CommandResult:
        success = self.app_launcher.close_application(pid, force)
        if success:
            return CommandResult(
                success=True,
                message=f"Closed application (PID: {pid})"
            )
        else:
            return CommandResult(
                success=False,
                error=f"Failed to close application (PID: {pid})"
            )
    
    def cmd_search(self, directory: str, pattern: str, recursive: bool = True) -> CommandResult:
        result = self.file_ops.search_files(directory, pattern, recursive)
        return CommandResult(
            success=result.success,
            message=result.message,
            data=result.data,
            error=result.error
        )
    
    def cmd_create_file(self, file_path: str, content: str = "", overwrite: bool = False) -> CommandResult:
        result = self.file_ops.write_file(file_path, content, overwrite=overwrite)
        return CommandResult(
            success=result.success,
            message=result.message,
            error=result.error
        )
    
    def cmd_read_file(self, file_path: str) -> CommandResult:
        result = self.file_ops.read_file(file_path)
        return CommandResult(
            success=result.success,
            message=result.message,
            data=result.data,
            error=result.error
        )
    
    def cmd_list_files(self, directory: str = ".", pattern: str = "*") -> CommandResult:
        result = self.file_ops.list_directory(directory, pattern)
        return CommandResult(
            success=result.success,
            message=result.message,
            data=result.data,
            error=result.error
        )
    
    def cmd_run_command(self, command: str, args: Optional[List[str]] = None, timeout: int = 30) -> CommandResult:
        result = self.executor.execute_command(command, args, timeout=timeout)
        return CommandResult(
            success=result.success,
            message=result.output if result.success else result.error,
            data={'output': result.output, 'exit_code': result.exit_code},
            error=result.error if not result.success else None
        )
    
    def cmd_screenshot(self, save_path: Optional[str] = None) -> CommandResult:
        screenshot = self.gui_controller.screenshot()
        if screenshot:
            if save_path:
                screenshot.save(save_path)
                return CommandResult(
                    success=True,
                    message=f"Screenshot saved to {save_path}",
                    data={'path': save_path}
                )
            else:
                return CommandResult(
                    success=True,
                    message="Screenshot captured",
                    data={'screenshot': screenshot}
                )
        else:
            return CommandResult(
                success=False,
                error="Failed to capture screenshot"
            )
    
    def cmd_type_text(self, text: str, interval: float = 0.0) -> CommandResult:
        success = self.gui_controller.type_text(text, interval)
        if success:
            return CommandResult(
                success=True,
                message=f"Typed {len(text)} characters"
            )
        else:
            return CommandResult(
                success=False,
                error="Failed to type text"
            )
    
    def cmd_press_key(self, key: str, presses: int = 1) -> CommandResult:
        success = self.gui_controller.press_key(key, presses)
        if success:
            return CommandResult(
                success=True,
                message=f"Pressed key '{key}' {presses} time(s)"
            )
        else:
            return CommandResult(
                success=False,
                error=f"Failed to press key '{key}'"
            )
    
    def cmd_get_windows(self) -> CommandResult:
        windows = self.window_manager.get_all_windows()
        return CommandResult(
            success=True,
            message=f"Found {len(windows)} open windows",
            data=windows
        )
    
    def cmd_focus_window(self, title: str) -> CommandResult:
        success = self.window_manager.focus_window(title)
        if success:
            return CommandResult(
                success=True,
                message=f"Focused window: {title}"
            )
        else:
            return CommandResult(
                success=False,
                error=f"Failed to focus window: {title}"
            )
    
    def cmd_cpu_usage(self, interval: float = 1.0) -> CommandResult:
        usage = psutil.cpu_percent(interval=interval)
        return CommandResult(
            success=True,
            message=f"CPU usage: {usage}%",
            data={'cpu_usage': usage, 'cpu_count': psutil.cpu_count()}
        )
    
    def cmd_memory_usage(self) -> CommandResult:
        memory = psutil.virtual_memory()
        data = {
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'percent': memory.percent
        }
        return CommandResult(
            success=True,
            message=f"Memory usage: {memory.percent}%",
            data=data
        )
    
    def cmd_disk_usage(self, path: str = "/") -> CommandResult:
        try:
            disk = psutil.disk_usage(path)
            data = {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            }
            return CommandResult(
                success=True,
                message=f"Disk usage for {path}: {disk.percent}%",
                data=data
            )
        except Exception as e:
            return CommandResult(
                success=False,
                error=str(e)
            )
    
    def cmd_network_info(self) -> CommandResult:
        try:
            net_io = psutil.net_io_counters()
            net_if = psutil.net_if_addrs()
            
            data = {
                'io_counters': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv
                },
                'interfaces': {}
            }
            
            for interface, addrs in net_if.items():
                data['interfaces'][interface] = [
                    {'family': str(addr.family), 'address': addr.address}
                    for addr in addrs
                ]
            
            return CommandResult(
                success=True,
                message="Network information retrieved",
                data=data
            )
        except Exception as e:
            return CommandResult(
                success=False,
                error=str(e)
            )


_global_registry = None

def get_command_registry() -> CommandRegistry:
    global _global_registry
    if _global_registry is None:
        _global_registry = CommandRegistry()
    return _global_registry
