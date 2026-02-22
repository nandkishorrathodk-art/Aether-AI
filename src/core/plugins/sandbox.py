import asyncio
import json
import sys
import subprocess
from typing import Any, Dict
from loguru import logger

class PluginSandbox:
    """
    Executes Python plugin code in an isolated subprocess to prevent 
    crashes or hanging operations from taking down the main Ironclaw server.
    """
    
    def __init__(self, timeout_seconds: int = 10):
        self.timeout_seconds = timeout_seconds

    async def execute_isolated(self, module_name: str, class_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Spawns a new Python process to run a specific plugin's execute method.
        Requires the plugin to be importable by the subprocess.
        """
        # A tiny script that directly instantiates the plugin and runs it, 
        # then prints the JSON result to stdout.
        wrapper_script = f"""
import sys
import json
import asyncio
from {module_name} import {class_name}

async def run():
    try:
        plugin = {class_name}()
        params = {json.dumps(params)}
        # Await execution if it's async
        result = await plugin.execute(params)
        print(json.dumps({{"status": "success", "data": result}}))
    except Exception as e:
        print(json.dumps({{"status": "error", "error": str(e)}}))

asyncio.run(run())
"""
        
        try:
            # Run the wrapper script in a subprocess
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-c", wrapper_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                # Wait for the process to finish with a timeout
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout_seconds)
                
                if process.returncode != 0:
                    err_message = stderr.decode().strip()
                    logger.error(f"Sandbox execution failed: {err_message}")
                    return {"status": "error", "error": f"Subprocess failed: {err_message}"}
                
                output_str = stdout.decode().strip()
                
                # Parse the last line as JSON (in case the plugin logs anything else to stdout)
                for line in reversed(output_str.splitlines()):
                    line = line.strip()
                    if line.startswith('{'):
                        return json.loads(line)
                        
                return {"status": "error", "error": "No valid JSON output from sandbox."}
                
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"Sandbox execution timed out after {self.timeout_seconds}s for {class_name}")
                return {"status": "error", "error": f"Execution timed out after {self.timeout_seconds} seconds"}
                
        except Exception as e:
            logger.error(f"Sandbox runtime error: {e}")
            return {"status": "error", "error": str(e)}

# Global sandbox instance
sandbox = PluginSandbox()
