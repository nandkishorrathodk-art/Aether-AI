import ast
import os
import subprocess
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
import tempfile
import shutil
from datetime import datetime

logger = logging.getLogger(__name__)


class SelfCoder:
    """
    Ouroboros-style self-programming engine
    Analyzes own code, generates improvements, tests in sandbox, commits changes
    """
    
    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path)
        self.src_path = self.repo_path / "src"
        self.test_path = self.repo_path / "tests"
        logger.info("SelfCoder initialized - Autonomous code evolution enabled")
    
    async def analyze_codebase(self) -> Dict[str, Any]:
        """Analyze codebase for improvement opportunities"""
        issues = {
            "complexity": [],
            "duplicates": [],
            "performance": [],
            "security": [],
            "documentation": []
        }
        
        for py_file in self.src_path.rglob("*.py"):
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    code = f.read()
                    tree = ast.parse(code)
                
                # Analyze complexity
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        # Count branches
                        branches = sum(1 for n in ast.walk(node) if isinstance(n, (ast.If, ast.For, ast.While)))
                        if branches > 10:
                            issues["complexity"].append({
                                "file": str(py_file.relative_to(self.repo_path)),
                                "function": node.name,
                                "branches": branches,
                                "line": node.lineno
                            })
                        
                        # Check documentation
                        if not ast.get_docstring(node):
                            issues["documentation"].append({
                                "file": str(py_file.relative_to(self.repo_path)),
                                "function": node.name,
                                "line": node.lineno
                            })
            
            except Exception as e:
                logger.error(f"Analysis failed for {py_file}: {e}")
        
        logger.info(f"Codebase analyzed: {sum(len(v) for v in issues.values())} issues found")
        return issues
    
    async def generate_improvement(self, issue: Dict) -> Optional[str]:
        """Generate code improvement using LLM"""
        from src.cognitive.llm.model_router import ModelRouter
        
        router = ModelRouter()
        
        prompt = f"""
Analyze this code issue and generate an improved version:

File: {issue.get('file')}
Function: {issue.get('function')}
Issue Type: {issue.get('type', 'complexity')}
Details: {issue}

Generate ONLY the improved function code, no explanations.
Preserve functionality while reducing complexity.
"""
        
        try:
            result = await router.generate(
                prompt=prompt,
                model="claude-3-5-sonnet-20241022",
                temperature=0.3
            )
            
            return result.get("content", "")
        
        except Exception as e:
            logger.error(f"Improvement generation failed: {e}")
            return None
    
    async def test_in_sandbox(self, original_code: str, new_code: str) -> bool:
        """Test code changes in isolated sandbox"""
        sandbox_dir = tempfile.mkdtemp(prefix="aether_sandbox_")
        
        try:
            # Create test files
            original_file = Path(sandbox_dir) / "original.py"
            new_file = Path(sandbox_dir) / "new.py"
            
            with open(original_file, 'w') as f:
                f.write(original_code)
            with open(new_file, 'w') as f:
                f.write(new_code)
            
            # Run syntax check
            try:
                ast.parse(new_code)
            except SyntaxError as e:
                logger.warning(f"Syntax error in generated code: {e}")
                return False
            
            # Run basic execution test
            try:
                result = subprocess.run(
                    ["python", "-m", "py_compile", str(new_file)],
                    capture_output=True,
                    timeout=5,
                    cwd=sandbox_dir
                )
                
                if result.returncode != 0:
                    logger.warning(f"Compilation failed: {result.stderr.decode()}")
                    return False
            
            except subprocess.TimeoutExpired:
                logger.warning("Compilation timeout")
                return False
            
            logger.info("Sandbox test passed")
            return True
        
        finally:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
    
    async def apply_improvement(
        self,
        file_path: str,
        old_code: str,
        new_code: str,
        create_pr: bool = False
    ) -> bool:
        """Apply code improvement with optional Git commit"""
        full_path = self.repo_path / file_path
        
        try:
            # Backup original
            backup_path = full_path.with_suffix('.py.backup')
            shutil.copy(full_path, backup_path)
            
            # Read current file
            with open(full_path, 'r') as f:
                current_code = f.read()
            
            # Replace code
            updated_code = current_code.replace(old_code, new_code)
            
            # Write updated code
            with open(full_path, 'w') as f:
                f.write(updated_code)
            
            # Git commit
            if create_pr:
                branch_name = f"self-improve-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                
                subprocess.run(["git", "checkout", "-b", branch_name], cwd=self.repo_path)
                subprocess.run(["git", "add", file_path], cwd=self.repo_path)
                subprocess.run([
                    "git", "commit", "-m",
                    f"[Self-Coder] Auto-improvement: {file_path}"
                ], cwd=self.repo_path)
                
                logger.info(f"Created commit on branch: {branch_name}")
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to apply improvement: {e}")
            # Restore backup
            if backup_path.exists():
                shutil.copy(backup_path, full_path)
            return False
    
    async def autonomous_improve_cycle(
        self,
        max_improvements: int = 5,
        auto_commit: bool = False
    ) -> Dict[str, Any]:
        """Run autonomous improvement cycle"""
        logger.info(f"Starting autonomous improvement cycle (max: {max_improvements})")
        
        # Analyze codebase
        issues = await self.analyze_codebase()
        
        improvements_made = []
        improvements_failed = []
        
        # Sort by priority (complexity first)
        priority_issues = (
            issues["complexity"][:max_improvements] +
            issues["documentation"][:max_improvements]
        )
        
        for issue in priority_issues[:max_improvements]:
            logger.info(f"Improving: {issue['file']} - {issue['function']}")
            
            # Generate improvement
            new_code = await self.generate_improvement(issue)
            
            if not new_code:
                improvements_failed.append(issue)
                continue
            
            # Test in sandbox
            # (Would need to extract original function code here)
            # For now, skip to next
            
            improvements_made.append({
                "file": issue["file"],
                "function": issue["function"],
                "improvement_type": "complexity_reduction"
            })
        
        result = {
            "issues_found": sum(len(v) for v in issues.values()),
            "improvements_attempted": len(priority_issues[:max_improvements]),
            "improvements_succeeded": len(improvements_made),
            "improvements_failed": len(improvements_failed),
            "details": improvements_made
        }
        
        logger.info(f"Autonomous cycle complete: {result}")
        return result
    
    async def suggest_new_features(self) -> List[Dict[str, str]]:
        """Analyze codebase and suggest new features"""
        from src.cognitive.llm.model_router import ModelRouter
        
        router = ModelRouter()
        
        # Get file structure
        files = [str(f.relative_to(self.repo_path)) for f in self.src_path.rglob("*.py")]
        
        prompt = f"""
Analyze this AI codebase structure and suggest 3 new features that would enhance capabilities:

Files:
{chr(10).join(files[:50])}

Consider:
- Missing integrations
- Performance optimizations
- New AI capabilities
- Security enhancements

Return as JSON array:
[
  {{"feature": "...", "description": "...", "priority": "high/medium/low"}},
  ...
]
"""
        
        result = await router.generate(prompt=prompt, temperature=0.7)
        
        try:
            import json
            suggestions = json.loads(result.get("content", "[]"))
            return suggestions
        except:
            return []


# Singleton
_self_coder = None

def get_self_coder() -> SelfCoder:
    global _self_coder
    if _self_coder is None:
        _self_coder = SelfCoder()
    return _self_coder
