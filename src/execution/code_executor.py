import subprocess
import tempfile
import os
import asyncio
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import shutil

logger = logging.getLogger(__name__)


class MultiLanguageExecutor:
    """
    Ultra-fast multi-language code executor
    Supports: Python, JavaScript, TypeScript, Go, Rust, C++, Java, Ruby, PHP, Shell
    """
    
    LANGUAGE_CONFIG = {
        "python": {
            "ext": ".py",
            "cmd": ["python", "-u"],
            "compile": False,
            "version_check": ["python", "--version"]
        },
        "javascript": {
            "ext": ".js",
            "cmd": ["node"],
            "compile": False,
            "version_check": ["node", "--version"]
        },
        "typescript": {
            "ext": ".ts",
            "cmd": ["ts-node"],
            "compile": False,
            "version_check": ["ts-node", "--version"]
        },
        "go": {
            "ext": ".go",
            "cmd": ["go", "run"],
            "compile": False,
            "version_check": ["go", "version"]
        },
        "rust": {
            "ext": ".rs",
            "cmd": None,
            "compile": True,
            "compile_cmd": ["rustc", "-O"],
            "version_check": ["rustc", "--version"]
        },
        "cpp": {
            "ext": ".cpp",
            "cmd": None,
            "compile": True,
            "compile_cmd": ["g++", "-O3", "-std=c++20"],
            "version_check": ["g++", "--version"]
        },
        "c": {
            "ext": ".c",
            "cmd": None,
            "compile": True,
            "compile_cmd": ["gcc", "-O3"],
            "version_check": ["gcc", "--version"]
        },
        "java": {
            "ext": ".java",
            "cmd": None,
            "compile": True,
            "compile_cmd": ["javac"],
            "run_cmd": ["java"],
            "version_check": ["java", "--version"]
        },
        "ruby": {
            "ext": ".rb",
            "cmd": ["ruby"],
            "compile": False,
            "version_check": ["ruby", "--version"]
        },
        "php": {
            "ext": ".php",
            "cmd": ["php"],
            "compile": False,
            "version_check": ["php", "--version"]
        },
        "shell": {
            "ext": ".sh",
            "cmd": ["bash"],
            "compile": False,
            "version_check": ["bash", "--version"]
        }
    }
    
    def __init__(self):
        self.available_languages = self._detect_available_languages()
        logger.info(f"Available languages: {', '.join(self.available_languages)}")
    
    def _detect_available_languages(self) -> list:
        """Detect which language runtimes are installed"""
        available = []
        for lang, config in self.LANGUAGE_CONFIG.items():
            try:
                subprocess.run(
                    config["version_check"],
                    capture_output=True,
                    timeout=2
                )
                available.append(lang)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug(f"{lang} runtime not available")
        return available
    
    async def execute(
        self,
        code: str,
        language: str,
        timeout: int = 30,
        stdin: Optional[str] = None,
        args: Optional[list] = None
    ) -> Dict[str, Any]:
        """
        Execute code in specified language with ultra-fast performance
        
        Args:
            code: Source code to execute
            language: Programming language
            timeout: Max execution time in seconds
            stdin: Standard input for the program
            args: Command line arguments
        
        Returns:
            Dict with stdout, stderr, return_code, execution_time, language
        """
        language = language.lower()
        
        if language not in self.LANGUAGE_CONFIG:
            return {
                "error": f"Unsupported language: {language}",
                "available": list(self.LANGUAGE_CONFIG.keys())
            }
        
        if language not in self.available_languages:
            return {
                "error": f"{language} runtime not installed",
                "available": self.available_languages
            }
        
        config = self.LANGUAGE_CONFIG[language]
        
        try:
            if config["compile"]:
                return await self._execute_compiled(
                    code, language, config, timeout, stdin, args
                )
            else:
                return await self._execute_interpreted(
                    code, language, config, timeout, stdin, args
                )
        except Exception as e:
            logger.error(f"Execution error: {e}")
            return {
                "error": str(e),
                "language": language
            }
    
    async def _execute_interpreted(
        self,
        code: str,
        language: str,
        config: dict,
        timeout: int,
        stdin: Optional[str],
        args: Optional[list]
    ) -> Dict[str, Any]:
        """Execute interpreted languages (Python, JS, Ruby, etc.)"""
        import time
        
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix=config["ext"],
            delete=False
        ) as f:
            f.write(code)
            temp_path = f.name
        
        try:
            start_time = time.time()
            
            cmd = config["cmd"] + [temp_path]
            if args:
                cmd.extend(args)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=stdin.encode() if stdin else None),
                    timeout=timeout
                )
                
                execution_time = time.time() - start_time
                
                return {
                    "stdout": stdout.decode('utf-8', errors='replace'),
                    "stderr": stderr.decode('utf-8', errors='replace'),
                    "return_code": process.returncode,
                    "execution_time": round(execution_time, 3),
                    "language": language,
                    "success": process.returncode == 0
                }
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    "error": f"Execution timeout ({timeout}s exceeded)",
                    "language": language,
                    "success": False
                }
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    async def _execute_compiled(
        self,
        code: str,
        language: str,
        config: dict,
        timeout: int,
        stdin: Optional[str],
        args: Optional[list]
    ) -> Dict[str, Any]:
        """Execute compiled languages (C++, Rust, Go with compilation, etc.)"""
        import time
        
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Create source file
            if language == "java":
                # Java requires class name matching filename
                import re
                class_match = re.search(r'class\s+(\w+)', code)
                class_name = class_match.group(1) if class_match else "Main"
                source_path = os.path.join(temp_dir, f"{class_name}.java")
            else:
                source_path = os.path.join(temp_dir, f"program{config['ext']}")
            
            with open(source_path, 'w') as f:
                f.write(code)
            
            # Compile
            start_time = time.time()
            
            if language == "java":
                compile_cmd = config["compile_cmd"] + [source_path]
                output_name = class_name
            else:
                output_path = os.path.join(temp_dir, "program.exe" if os.name == 'nt' else "program")
                compile_cmd = config["compile_cmd"] + [source_path, "-o", output_path]
            
            compile_process = await asyncio.create_subprocess_exec(
                *compile_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=temp_dir
            )
            
            compile_stdout, compile_stderr = await asyncio.wait_for(
                compile_process.communicate(),
                timeout=timeout
            )
            
            if compile_process.returncode != 0:
                return {
                    "error": "Compilation failed",
                    "compile_stderr": compile_stderr.decode('utf-8', errors='replace'),
                    "language": language,
                    "success": False
                }
            
            # Run
            if language == "java":
                run_cmd = config["run_cmd"] + [output_name]
            else:
                run_cmd = [output_path]
            
            if args:
                run_cmd.extend(args)
            
            run_process = await asyncio.create_subprocess_exec(
                *run_cmd,
                stdin=asyncio.subprocess.PIPE if stdin else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=temp_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                run_process.communicate(input=stdin.encode() if stdin else None),
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            
            return {
                "stdout": stdout.decode('utf-8', errors='replace'),
                "stderr": stderr.decode('utf-8', errors='replace'),
                "return_code": run_process.returncode,
                "execution_time": round(execution_time, 3),
                "language": language,
                "compiled": True,
                "success": run_process.returncode == 0
            }
        
        except asyncio.TimeoutError:
            return {
                "error": f"Execution timeout ({timeout}s exceeded)",
                "language": language,
                "success": False
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def benchmark(self, language: str) -> Dict[str, Any]:
        """Benchmark language execution speed"""
        test_code = {
            "python": "for i in range(1000000): pass",
            "javascript": "for(let i=0; i<1000000; i++);",
            "go": "package main\nfunc main() { for i:=0; i<1000000; i++ {} }",
            "rust": "fn main() { for _ in 0..1000000 {} }",
            "cpp": "#include <iostream>\nint main() { for(int i=0; i<1000000; i++); return 0; }",
            "c": "#include <stdio.h>\nint main() { for(int i=0; i<1000000; i++); return 0; }",
            "java": "public class Main { public static void main(String[] args) { for(int i=0; i<1000000; i++); } }",
            "ruby": "1000000.times {}"
        }
        
        if language not in test_code:
            return {"error": "No benchmark available for this language"}
        
        result = await self.execute(test_code[language], language, timeout=10)
        
        if result.get("success"):
            return {
                "language": language,
                "execution_time": result["execution_time"],
                "performance_rating": "excellent" if result["execution_time"] < 0.1 else
                                     "good" if result["execution_time"] < 1 else "slow"
            }
        return result


# Singleton instance
_executor = None

def get_executor() -> MultiLanguageExecutor:
    global _executor
    if _executor is None:
        _executor = MultiLanguageExecutor()
    return _executor
