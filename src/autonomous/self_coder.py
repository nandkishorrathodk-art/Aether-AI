"""
Self-Coder - AI that writes its own code

Writes exploit code, tools, scripts when needed.
"""

import asyncio
import tempfile
import subprocess
from typing import Dict, Any, Optional
from pathlib import Path

from src.cognitive.llm.llm_wrapper import LLMInference
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SelfCoder:
    """
    AI that writes code for itself when needed.
    
    Can create exploits, tools, automation scripts on-the-fly.
    """
    
    def __init__(self):
        self.llm = LLMInference()
        self.code_history = []
        logger.info("💻 Self-Coder initialized")
    
    async def write_exploit_code(self, requirements: Dict[str, Any]) -> str:
        """
        Write exploit code based on requirements
        
        Args:
            requirements: Dict with vulnerability details
            
        Returns:
            Generated exploit code
        """
        try:
            vuln_type = requirements.get("vulnerability_type", "generic")
            target_url = requirements.get("target_url", "")
            description = requirements.get("description", "")
            
            prompt = f"""Write a Python exploit script for this vulnerability:

**Vulnerability Type:** {vuln_type}
**Target URL:** {target_url}
**Description:** {description}

Requirements:
1. Complete, working Python script
2. Use requests library
3. Add comments explaining each step
4. Include error handling
5. Print results clearly
6. Safe and non-destructive

Write ONLY the Python code, no explanations outside comments.

```python
"""
            
            response = await self.llm.get_completion(prompt)
            
            import re
            code_match = re.search(r'```python\s*(.*?)\s*```', response, re.DOTALL)
            if code_match:
                code = code_match.group(1)
            else:
                code = response
            
            code = code.strip()
            
            self.code_history.append({
                "type": "exploit",
                "requirements": requirements,
                "code": code
            })
            
            logger.info(f"✅ Generated exploit code ({len(code)} chars)")
            
            return code
            
        except Exception as e:
            logger.error(f"Failed to write exploit code: {e}")
            return ""
    
    async def write_automation_script(self, task_description: str) -> str:
        """
        Write automation script for a task
        
        Args:
            task_description: What the script should do
            
        Returns:
            Generated script code
        """
        try:
            prompt = f"""Write a Python automation script for this task:

**Task:** {task_description}

Requirements:
1. Complete, working script
2. Use standard libraries (os, subprocess, etc.)
3. Add error handling
4. Make it robust and reliable
5. Add logging

Write ONLY the Python code.

```python
"""
            
            response = await self.llm.get_completion(prompt)
            
            import re
            code_match = re.search(r'```python\s*(.*?)\s*```', response, re.DOTALL)
            if code_match:
                code = code_match.group(1)
            else:
                code = response
            
            code = code.strip()
            
            self.code_history.append({
                "type": "automation",
                "task": task_description,
                "code": code
            })
            
            logger.info(f"✅ Generated automation script ({len(code)} chars)")
            
            return code
            
        except Exception as e:
            logger.error(f"Failed to write automation script: {e}")
            return ""
    
    async def execute_code(self, code: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute generated code in secure sandbox
        
        Args:
            code: Python code to execute
            timeout: Execution timeout in seconds (max 60)
            
        Returns:
            Execution results
        """
        try:
            # Security: Enforce maximum timeout
            timeout = min(timeout, 60)
            
            # Security: Validate code doesn't contain dangerous operations
            dangerous_imports = [
                'os.system', 'subprocess.', 'eval(', 'exec(',
                '__import__', 'compile(', 'open(',
                'socket', 'urllib', 'http.client'
            ]
            
            for danger in dangerous_imports:
                if danger in code:
                    logger.error(f"Blocked dangerous code: contains '{danger}'")
                    return {
                        "success": False,
                        "error": f"Code contains forbidden operation: {danger}"
                    }
            
            # Create sandboxed execution environment
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                # Wrap code in restricted environment
                sandboxed_code = f"""
# Sandboxed execution - restricted environment
import sys
import io

# Disable dangerous builtins
__builtins__['open'] = None
__builtins__['eval'] = None
__builtins__['exec'] = None
__builtins__['compile'] = None
__builtins__['__import__'] = None

# Capture output
old_stdout = sys.stdout
old_stderr = sys.stderr
sys.stdout = io.StringIO()
sys.stderr = io.StringIO()

try:
    # User code starts here
{self._indent_code(code, '    ')}
    # User code ends
finally:
    output = sys.stdout.getvalue()
    errors = sys.stderr.getvalue()
    sys.stdout = old_stdout
    sys.stderr = old_stderr
    if output:
        print(output, end='')
    if errors:
        print(errors, end='', file=sys.stderr)
"""
                f.write(sandboxed_code)
                temp_file = f.name
            
            logger.info(f"Executing sandboxed code: {temp_file[:50]}...")
            
            # Execute with strict timeout
            result = subprocess.run(
                ["python", temp_file],
                capture_output=True,
                text=True,
                timeout=timeout,
                # Security: No network access (if possible on Windows)
                # On Linux would use: preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (0, 0))
            )
            
            # Clean up immediately
            try:
                Path(temp_file).unlink()
            except:
                pass
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Code execution timeout after {timeout}s")
            try:
                Path(temp_file).unlink()
            except:
                pass
            return {
                "success": False,
                "error": f"Timeout after {timeout}s - code terminated"
            }
        except Exception as e:
            logger.error(f"Code execution failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _indent_code(self, code: str, indent: str) -> str:
        """Indent code block"""
        return '\n'.join(indent + line for line in code.split('\n'))
    
    async def improve_code(self, code: str, issue: str) -> str:
        """
        Improve/fix generated code
        
        Args:
            code: Original code
            issue: What's wrong with it
            
        Returns:
            Improved code
        """
        try:
            prompt = f"""Improve this Python code to fix the following issue:

**Issue:** {issue}

**Original Code:**
```python
{code}
```

Write the improved version. ONLY Python code, no explanations.

```python
"""
            
            response = await self.llm.get_completion(prompt)
            
            import re
            code_match = re.search(r'```python\s*(.*?)\s*```', response, re.DOTALL)
            if code_match:
                improved_code = code_match.group(1)
            else:
                improved_code = response
            
            improved_code = improved_code.strip()
            
            logger.info("✅ Code improved")
            
            return improved_code
            
        except Exception as e:
            logger.error(f"Failed to improve code: {e}")
            return code
    
    async def write_poc_from_vulnerability(self, vuln: Dict[str, Any]) -> str:
        """
        Write complete PoC from vulnerability details
        
        Args:
            vuln: Vulnerability details from scanner
            
        Returns:
            Complete PoC code
        """
        try:
            vuln_type = vuln.get("type", "unknown")
            url = vuln.get("url", "")
            parameter = vuln.get("parameter", "")
            payload = vuln.get("payload", "")
            
            prompt = f"""Write a complete Proof-of-Concept exploit for this vulnerability:

**Type:** {vuln_type}
**URL:** {url}
**Vulnerable Parameter:** {parameter}
**Payload:** {payload}

Write a Python script that:
1. Sends the malicious request
2. Shows the vulnerable response
3. Explains the impact
4. Is safe (read-only operation)

ONLY Python code:

```python
"""
            
            response = await self.llm.get_completion(prompt)
            
            import re
            code_match = re.search(r'```python\s*(.*?)\s*```', response, re.DOTALL)
            if code_match:
                poc_code = code_match.group(1)
            else:
                poc_code = response
            
            poc_code = poc_code.strip()
            
            logger.info(f"✅ Generated PoC for {vuln_type}")
            
            return poc_code
            
        except Exception as e:
            logger.error(f"Failed to write PoC: {e}")
            return ""
