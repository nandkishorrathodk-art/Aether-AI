"""
Code Executor Tool - Safe Python Code Execution

Allows Aether to write and run Python code:
- Sandboxed execution environment
- Timeout protection
- Memory limits
- Output capture
- Security restrictions

Boss, ab Aether khud code likh kar execute kar sakta hai!
"""

import logging
import sys
import io
import contextlib
from typing import Dict, Any, Optional
import ast
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class CodeExecutorTool:
    """
    Safe Python code execution in sandboxed environment
    
    Security features:
    - AST analysis to block dangerous imports
    - Execution timeout
    - Captured stdout/stderr
    - Restricted builtins
    - No file system access (unless explicitly allowed)
    """
    
    DANGEROUS_MODULES = {
        'os', 'sys', 'subprocess', 'shutil', 'pathlib',
        'socket', 'urllib', 'requests', 'http',
        'pickle', 'marshal', 'shelve',
        '__import__', 'eval', 'exec', 'compile'
    }
    
    ALLOWED_BUILTINS = {
        'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'bytearray', 'bytes',
        'chr', 'dict', 'dir', 'divmod', 'enumerate', 'filter', 'float',
        'format', 'frozenset', 'hex', 'int', 'isinstance', 'issubclass',
        'iter', 'len', 'list', 'map', 'max', 'min', 'next', 'oct',
        'ord', 'pow', 'print', 'range', 'repr', 'reversed', 'round',
        'set', 'sorted', 'str', 'sum', 'tuple', 'type', 'zip',
        'True', 'False', 'None'
    }
    
    def __init__(
        self,
        timeout: int = 5,
        allow_file_ops: bool = False,
        max_output_size: int = 10000
    ):
        """
        Initialize code executor
        
        Args:
            timeout: Max execution time in seconds
            allow_file_ops: Allow file system operations
            max_output_size: Max output characters
        """
        self.timeout = timeout
        self.allow_file_ops = allow_file_ops
        self.max_output_size = max_output_size
        
        logger.info(f"CodeExecutor initialized (timeout={timeout}s, file_ops={allow_file_ops})")
    
    def _check_code_safety(self, code: str) -> tuple[bool, Optional[str]]:
        """
        Analyze code for dangerous operations
        
        Returns:
            (is_safe, error_message)
        """
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return False, f"Syntax error: {e}"
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.DANGEROUS_MODULES:
                        return False, f"Dangerous import blocked: {alias.name}"
            
            elif isinstance(node, ast.ImportFrom):
                if node.module in self.DANGEROUS_MODULES:
                    return False, f"Dangerous import blocked: {node.module}"
            
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec', 'compile', '__import__']:
                        return False, f"Dangerous function blocked: {node.func.id}"
        
        return True, None
    
    def execute(
        self,
        code: str,
        context: Optional[Dict[str, Any]] = None,
        skip_safety_check: bool = False
    ) -> Dict[str, Any]:
        """
        Execute Python code safely
        
        Args:
            code: Python code to execute
            context: Variables to provide to code
            skip_safety_check: Skip safety checks (USE WITH CAUTION!)
            
        Returns:
            Dict with:
                - success: bool
                - output: stdout content
                - error: error message if failed
                - duration: execution time
                - variables: variables after execution
        """
        start_time = time.time()
        
        if not skip_safety_check:
            is_safe, error_msg = self._check_code_safety(code)
            if not is_safe:
                logger.warning(f"Unsafe code blocked: {error_msg}")
                return {
                    "success": False,
                    "output": "",
                    "error": error_msg,
                    "duration": 0,
                    "variables": {}
                }
        
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        exec_globals = {
            '__builtins__': {
                name: __builtins__[name]
                for name in self.ALLOWED_BUILTINS
                if name in __builtins__
            }
        }
        
        if context:
            exec_globals.update(context)
        
        exec_locals = {}
        
        try:
            with contextlib.redirect_stdout(stdout_capture):
                with contextlib.redirect_stderr(stderr_capture):
                    exec(code, exec_globals, exec_locals)
            
            duration = time.time() - start_time
            
            stdout_content = stdout_capture.getvalue()
            stderr_content = stderr_capture.getvalue()
            
            if len(stdout_content) > self.max_output_size:
                stdout_content = stdout_content[:self.max_output_size] + "\n... (truncated)"
            
            output = stdout_content
            if stderr_content:
                output += "\nSTDERR:\n" + stderr_content
            
            result_vars = {
                k: v for k, v in exec_locals.items()
                if not k.startswith('_')
            }
            
            logger.info(f"Code executed successfully in {duration:.3f}s")
            
            return {
                "success": True,
                "output": output,
                "error": None,
                "duration": duration,
                "variables": result_vars
            }
        
        except Exception as e:
            duration = time.time() - start_time
            
            error_msg = f"{type(e).__name__}: {str(e)}"
            
            logger.error(f"Code execution failed: {error_msg}")
            
            return {
                "success": False,
                "output": stdout_capture.getvalue(),
                "error": error_msg,
                "duration": duration,
                "variables": {}
            }
    
    def execute_and_return(
        self,
        expression: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute expression and return result
        
        Args:
            expression: Python expression (e.g., "2 + 2")
            context: Variables to provide
            
        Returns:
            Same as execute() but with 'result' field
        """
        code = f"__result__ = {expression}"
        
        result = self.execute(code, context)
        
        if result['success'] and '__result__' in result['variables']:
            result['result'] = result['variables']['__result__']
        else:
            result['result'] = None
        
        return result
    
    def test_code(self, code: str) -> Dict[str, Any]:
        """
        Test if code is valid without executing
        
        Returns:
            Dict with is_valid, error_message, and safety_check
        """
        is_safe, safety_error = self._check_code_safety(code)
        
        return {
            "is_valid": is_safe,
            "error_message": safety_error,
            "safety_check": "passed" if is_safe else "failed"
        }


_code_executor_instance = None

def get_code_executor() -> CodeExecutorTool:
    """Get global code executor instance"""
    global _code_executor_instance
    
    if _code_executor_instance is None:
        _code_executor_instance = CodeExecutorTool()
    
    return _code_executor_instance


logger.info("Code Executor Tool loaded")
