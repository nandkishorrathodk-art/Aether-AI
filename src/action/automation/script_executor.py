import subprocess
import os
import sys
import tempfile
import time
from typing import Dict, Any, Optional, List
from pathlib import Path
import threading
import queue

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ScriptExecutionResult:
    def __init__(
        self,
        success: bool,
        output: str = "",
        error: str = "",
        exit_code: int = 0,
        execution_time: float = 0.0,
        timeout: bool = False
    ):
        self.success = success
        self.output = output
        self.error = error
        self.exit_code = exit_code
        self.execution_time = execution_time
        self.timeout = timeout

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "timeout": self.timeout
        }

    def __repr__(self):
        return f"ScriptExecutionResult(success={self.success}, exit_code={self.exit_code}, time={self.execution_time:.2f}s)"


class ScriptExecutor:
    ALLOWED_EXTENSIONS = {'.py', '.bat', '.cmd', '.ps1', '.sh'}
    MAX_OUTPUT_SIZE = 10 * 1024 * 1024  # 10 MB
    
    def __init__(
        self,
        timeout: int = 30,
        max_output_size: int = MAX_OUTPUT_SIZE,
        working_directory: Optional[str] = None,
        allowed_commands: Optional[List[str]] = None
    ):
        self.timeout = timeout
        self.max_output_size = max_output_size
        self.working_directory = working_directory or os.getcwd()
        self.allowed_commands = allowed_commands or []
        
    def execute_script(
        self,
        script_path: str,
        args: Optional[List[str]] = None,
        env_vars: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> ScriptExecutionResult:
        timeout = timeout or self.timeout
        args = args or []
        
        script_path = Path(script_path).resolve()
        
        if not script_path.exists():
            return ScriptExecutionResult(
                success=False,
                error=f"Script not found: {script_path}"
            )
        
        if script_path.suffix not in self.ALLOWED_EXTENSIONS:
            return ScriptExecutionResult(
                success=False,
                error=f"Unsupported script type: {script_path.suffix}"
            )
        
        try:
            return self._execute_subprocess(script_path, args, env_vars, timeout)
        except Exception as e:
            logger.error(f"Script execution failed: {e}")
            return ScriptExecutionResult(
                success=False,
                error=str(e)
            )
    
    def execute_command(
        self,
        command: str,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
        shell: bool = True
    ) -> ScriptExecutionResult:
        timeout = timeout or self.timeout
        args = args or []
        
        if self.allowed_commands and command not in self.allowed_commands:
            return ScriptExecutionResult(
                success=False,
                error=f"Command not allowed: {command}"
            )
        
        cmd_list = [command] + args if not shell else f"{command} {' '.join(args)}"
        
        try:
            return self._execute_subprocess(cmd_list, [], {}, timeout, shell=shell)
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return ScriptExecutionResult(
                success=False,
                error=str(e)
            )
    
    def execute_python_code(
        self,
        code: str,
        timeout: Optional[int] = None,
        globals_dict: Optional[Dict[str, Any]] = None
    ) -> ScriptExecutionResult:
        timeout = timeout or self.timeout
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        try:
            result = self.execute_script(temp_file, timeout=timeout)
            return result
        finally:
            try:
                os.unlink(temp_file)
            except:
                pass
    
    def _execute_subprocess(
        self,
        command,
        args: List[str],
        env_vars: Optional[Dict[str, str]],
        timeout: int,
        shell: bool = False
    ) -> ScriptExecutionResult:
        start_time = time.time()
        
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)
        
        if not shell and isinstance(command, (str, Path)):
            cmd_list = [str(command)] + args
        else:
            cmd_list = command
        
        try:
            process = subprocess.Popen(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.working_directory,
                env=env,
                shell=shell,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                execution_time = time.time() - start_time
                
                if len(stdout) > self.max_output_size:
                    stdout = stdout[:self.max_output_size] + "\n... (output truncated)"
                if len(stderr) > self.max_output_size:
                    stderr = stderr[:self.max_output_size] + "\n... (output truncated)"
                
                success = process.returncode == 0
                
                return ScriptExecutionResult(
                    success=success,
                    output=stdout,
                    error=stderr,
                    exit_code=process.returncode,
                    execution_time=execution_time,
                    timeout=False
                )
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                execution_time = time.time() - start_time
                
                return ScriptExecutionResult(
                    success=False,
                    output=stdout or "",
                    error=f"Execution timed out after {timeout} seconds\n{stderr}",
                    exit_code=-1,
                    execution_time=execution_time,
                    timeout=True
                )
        except Exception as e:
            execution_time = time.time() - start_time
            return ScriptExecutionResult(
                success=False,
                error=str(e),
                execution_time=execution_time
            )


class SafeScriptExecutor(ScriptExecutor):
    DANGEROUS_COMMANDS = {
        'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd',
        'shutdown', 'reboot', 'init', 'halt',
        'chmod', 'chown', 'sudo', 'su'
    }
    
    SAFE_COMMANDS = {
        'echo', 'dir', 'ls', 'pwd', 'cd', 'type', 'cat',
        'whoami', 'hostname', 'date', 'time', 'systeminfo',
        'git', 'python', 'pip', 'npm', 'node'
    }
    
    def __init__(self, **kwargs):
        allowed_commands = kwargs.pop('allowed_commands', list(self.SAFE_COMMANDS))
        super().__init__(allowed_commands=allowed_commands, **kwargs)
    
    def execute_command(self, command: str, **kwargs) -> ScriptExecutionResult:
        base_command = command.split()[0].lower()
        
        if base_command in self.DANGEROUS_COMMANDS:
            logger.warning(f"Blocked dangerous command: {command}")
            return ScriptExecutionResult(
                success=False,
                error=f"Command '{base_command}' is not allowed for safety reasons"
            )
        
        return super().execute_command(command, **kwargs)
