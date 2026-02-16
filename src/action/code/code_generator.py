"""
Code Generation Assistant - Multi-language code generation, debugging, and analysis.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import re


class ProgrammingLanguage(Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    CPP = "cpp"
    C = "c"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    SWIFT = "swift"
    KOTLIN = "kotlin"
    SCALA = "scala"
    R = "r"
    MATLAB = "matlab"
    SQL = "sql"
    HTML = "html"
    CSS = "css"
    BASH = "bash"
    POWERSHELL = "powershell"


@dataclass
class GeneratedCode:
    """Generated code with metadata."""
    code: str
    language: str
    explanation: str
    complexity: str
    best_practices: List[str]
    potential_issues: List[str]
    dependencies: List[str]


@dataclass
class CodeAnalysis:
    """Code analysis result."""
    issues: List[Dict[str, Any]]
    suggestions: List[str]
    complexity_score: float
    quality_score: float
    security_issues: List[str]
    performance_tips: List[str]


class CodeGenerator:
    """
    Multi-language code generation and analysis assistant.
    
    Generates code, debugs issues, refactors, and provides explanations.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize code generator.
        
        Args:
            llm_provider: Language model for code generation
        """
        self.llm_provider = llm_provider
        self.language_extensions = {
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts',
            'java': '.java',
            'csharp': '.cs',
            'cpp': '.cpp',
            'c': '.c',
            'go': '.go',
            'rust': '.rs',
            'php': '.php',
            'ruby': '.rb',
            'swift': '.swift',
            'kotlin': '.kt',
            'scala': '.scala',
            'r': '.r',
            'matlab': '.m',
            'sql': '.sql',
            'html': '.html',
            'css': '.css',
            'bash': '.sh',
            'powershell': '.ps1'
        }
    
    def generate_code(self, task_description: str, language: str,
                     include_tests: bool = False, 
                     style_guide: Optional[str] = None) -> GeneratedCode:
        """
        Generate code from natural language description.
        
        Args:
            task_description: What the code should do
            language: Target programming language
            include_tests: Generate unit tests
            style_guide: Coding style preferences
            
        Returns:
            GeneratedCode with implementation
        """
        language = language.lower()
        
        if language not in self.language_extensions:
            raise ValueError(f"Unsupported language: {language}")
        
        if not self.llm_provider:
            return self._generate_code_template(task_description, language)
        
        prompt = self._build_generation_prompt(task_description, language, 
                                               include_tests, style_guide)
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=2000,
                temperature=0.3,
                task_type='code'
            )
            
            code_content = response.get('content', '')
            
            code = self._extract_code_from_response(code_content, language)
            
            explanation = self._generate_explanation(code, language, task_description)
            
            analysis = self.analyze_code(code, language)
            
            dependencies = self._extract_dependencies(code, language)
            
            return GeneratedCode(
                code=code,
                language=language,
                explanation=explanation,
                complexity=self._assess_complexity(analysis.complexity_score),
                best_practices=self._extract_best_practices(language),
                potential_issues=analysis.issues[:3] if analysis.issues else [],
                dependencies=dependencies
            )
            
        except Exception as e:
            print(f"Code generation error: {e}")
            return self._generate_code_template(task_description, language)
    
    def _build_generation_prompt(self, task: str, language: str,
                                include_tests: bool, style_guide: Optional[str]) -> str:
        """Build prompt for code generation."""
        prompt = f"""Generate production-ready {language} code for the following task:

Task: {task}

Requirements:
1. Write clean, well-documented code
2. Follow {language} best practices and conventions
3. Include error handling
4. Add helpful comments"""
        
        if style_guide:
            prompt += f"\n5. Follow this style guide: {style_guide}"
        
        if include_tests:
            prompt += f"\n6. Include unit tests"
        
        prompt += f"\n\nGenerate the complete {language} code:\n\n```{language}\n"
        
        return prompt
    
    def _extract_code_from_response(self, response: str, language: str) -> str:
        """Extract code from LLM response."""
        pattern = rf"```{language}(.*?)```"
        matches = re.findall(pattern, response, re.DOTALL | re.IGNORECASE)
        
        if matches:
            return matches[0].strip()
        
        pattern = r"```(.*?)```"
        matches = re.findall(pattern, response, re.DOTALL)
        
        if matches:
            return matches[0].strip()
        
        return response.strip()
    
    def analyze_code(self, code: str, language: str) -> CodeAnalysis:
        """
        Analyze code for issues, quality, and security.
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            CodeAnalysis with findings
        """
        issues = self._detect_code_issues(code, language)
        
        suggestions = self._generate_suggestions(code, language, issues)
        
        complexity = self._calculate_complexity(code, language)
        
        quality = self._assess_quality(code, language)
        
        security_issues = self._detect_security_issues(code, language)
        
        performance_tips = self._generate_performance_tips(code, language)
        
        return CodeAnalysis(
            issues=issues,
            suggestions=suggestions,
            complexity_score=complexity,
            quality_score=quality,
            security_issues=security_issues,
            performance_tips=performance_tips
        )
    
    def _detect_code_issues(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Detect common code issues."""
        issues = []
        
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            if len(line) > 120:
                issues.append({
                    'line': i,
                    'type': 'style',
                    'severity': 'low',
                    'message': f'Line too long ({len(line)} chars, recommended < 120)'
                })
            
            if language in ['python', 'javascript', 'java']:
                if 'TODO' in line or 'FIXME' in line:
                    issues.append({
                        'line': i,
                        'type': 'todo',
                        'severity': 'info',
                        'message': 'TODO comment found - needs implementation'
                    })
        
        if language == 'python':
            if 'eval(' in code:
                issues.append({
                    'type': 'security',
                    'severity': 'high',
                    'message': 'Use of eval() is dangerous - consider alternatives'
                })
            
            if 'exec(' in code:
                issues.append({
                    'type': 'security',
                    'severity': 'high',
                    'message': 'Use of exec() is dangerous - avoid if possible'
                })
        
        if language in ['javascript', 'typescript']:
            if '== ' in code or ' == ' in code:
                issues.append({
                    'type': 'best_practice',
                    'severity': 'medium',
                    'message': 'Use === instead of == for strict equality'
                })
            
            if 'var ' in code:
                issues.append({
                    'type': 'best_practice',
                    'severity': 'low',
                    'message': 'Use let or const instead of var'
                })
        
        if 'password' in code.lower() and ('=' in code or 'password' in code.lower()):
            issues.append({
                'type': 'security',
                'severity': 'critical',
                'message': 'Possible hardcoded password detected - use environment variables'
            })
        
        return issues
    
    def _generate_suggestions(self, code: str, language: str, 
                             issues: List[Dict[str, Any]]) -> List[str]:
        """Generate improvement suggestions."""
        suggestions = []
        
        if len(code.split('\n')) > 100:
            suggestions.append("Consider breaking this into smaller functions/modules")
        
        if language == 'python':
            if 'import *' in code:
                suggestions.append("Avoid wildcard imports - import specific items")
            
            if not any(line.strip().startswith('"""') or line.strip().startswith("'''") 
                      for line in code.split('\n')):
                suggestions.append("Add docstrings to document functions/classes")
        
        if language in ['javascript', 'typescript']:
            if 'console.log' in code:
                suggestions.append("Remove console.log statements in production code")
        
        if any(issue['severity'] == 'critical' for issue in issues):
            suggestions.append("Address critical security issues immediately")
        
        if not suggestions:
            suggestions.append("Code looks good - no major suggestions")
        
        return suggestions
    
    def _calculate_complexity(self, code: str, language: str) -> float:
        """Calculate cyclomatic complexity."""
        complexity = 1.0
        
        control_flow_keywords = {
            'python': ['if', 'elif', 'for', 'while', 'except', 'and', 'or'],
            'javascript': ['if', 'else if', 'for', 'while', 'catch', '&&', '||'],
            'java': ['if', 'else if', 'for', 'while', 'catch', '&&', '||'],
            'csharp': ['if', 'else if', 'for', 'while', 'catch', '&&', '||']
        }
        
        keywords = control_flow_keywords.get(language, ['if', 'for', 'while'])
        
        for keyword in keywords:
            complexity += code.count(f' {keyword} ') + code.count(f'\n{keyword} ')
        
        return min(complexity / 10.0, 10.0)
    
    def _assess_quality(self, code: str, language: str) -> float:
        """Assess code quality (0-10)."""
        quality = 5.0
        
        lines = code.split('\n')
        non_empty = [l for l in lines if l.strip()]
        
        if len(non_empty) == 0:
            return 0.0
        
        comment_lines = sum(1 for l in lines if l.strip().startswith('#') or 
                          l.strip().startswith('//') or '"""' in l or "'''" in l)
        
        comment_ratio = comment_lines / len(non_empty)
        
        if 0.1 <= comment_ratio <= 0.3:
            quality += 2.0
        elif comment_ratio > 0:
            quality += 1.0
        
        avg_line_length = sum(len(l) for l in non_empty) / len(non_empty)
        
        if 20 <= avg_line_length <= 80:
            quality += 1.5
        
        if language == 'python':
            if 'try:' in code and 'except' in code:
                quality += 1.0
            
            if 'def ' in code or 'class ' in code:
                quality += 0.5
        
        return min(quality, 10.0)
    
    def _detect_security_issues(self, code: str, language: str) -> List[str]:
        """Detect security vulnerabilities."""
        security_issues = []
        
        dangerous_patterns = {
            'hardcoded_secrets': r'(password|api_key|secret|token)\s*=\s*["\'][^"\']+["\']',
            'sql_injection': r'(execute|query).*\+.*[\'"]\s*%\s*',
            'command_injection': r'(os\.system|subprocess|exec|eval)\s*\(',
            'insecure_random': r'random\.(random|randint)',
        }
        
        for issue_type, pattern in dangerous_patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                security_issues.append(
                    f"Potential {issue_type.replace('_', ' ')} detected"
                )
        
        return security_issues
    
    def _generate_performance_tips(self, code: str, language: str) -> List[str]:
        """Generate performance optimization tips."""
        tips = []
        
        if language == 'python':
            if code.count('for ') > 3:
                tips.append("Consider list comprehensions or vectorization for better performance")
            
            if '+=' in code and 'str' in code.lower():
                tips.append("Use join() instead of += for string concatenation in loops")
        
        if language in ['javascript', 'typescript']:
            if '.forEach(' in code:
                tips.append("Consider for...of loops for better performance")
        
        if len(code.split('\n')) > 200:
            tips.append("Large code block - consider profiling to identify bottlenecks")
        
        return tips
    
    def _assess_complexity(self, score: float) -> str:
        """Convert complexity score to human-readable."""
        if score < 2:
            return "Simple"
        elif score < 5:
            return "Moderate"
        elif score < 7:
            return "Complex"
        else:
            return "Very Complex"
    
    def _extract_best_practices(self, language: str) -> List[str]:
        """Get best practices for language."""
        practices = {
            'python': [
                "Follow PEP 8 style guide",
                "Use type hints for better code clarity",
                "Write comprehensive docstrings",
                "Use context managers (with statements)"
            ],
            'javascript': [
                "Use const/let instead of var",
                "Follow Airbnb JavaScript style guide",
                "Use async/await for asynchronous code",
                "Implement proper error handling"
            ],
            'java': [
                "Follow Oracle code conventions",
                "Use meaningful variable names",
                "Implement proper exception handling",
                "Use interfaces for abstraction"
            ]
        }
        
        return practices.get(language, [
            "Follow language-specific conventions",
            "Write clean, readable code",
            "Include proper error handling",
            "Add comments where needed"
        ])
    
    def _extract_dependencies(self, code: str, language: str) -> List[str]:
        """Extract code dependencies."""
        dependencies = []
        
        if language == 'python':
            import_pattern = r'(?:from|import)\s+([a-zA-Z0-9_\.]+)'
            imports = re.findall(import_pattern, code)
            dependencies = list(set([imp.split('.')[0] for imp in imports]))
        
        elif language in ['javascript', 'typescript']:
            import_pattern = r'(?:import|require)\s*\(?["\']([^"\']+)["\']'
            imports = re.findall(import_pattern, code)
            dependencies = list(set(imports))
        
        return dependencies[:10]
    
    def _generate_code_template(self, task: str, language: str) -> GeneratedCode:
        """Generate basic code template without LLM."""
        templates = {
            'python': f'''# {task}

def main():
    """
    Implementation for: {task}
    """
    # TODO: Implement the logic here
    pass

if __name__ == "__main__":
    main()
''',
            'javascript': f'''// {task}

function main() {{
    // TODO: Implement the logic here
}}

main();
''',
            'java': f'''// {task}

public class Main {{
    public static void main(String[] args) {{
        // TODO: Implement the logic here
    }}
}}
'''
        }
        
        code = templates.get(language, f'// {task}\n// TODO: Implement')
        
        return GeneratedCode(
            code=code,
            language=language,
            explanation=f"Basic template for: {task}",
            complexity="Simple",
            best_practices=self._extract_best_practices(language),
            potential_issues=[],
            dependencies=[]
        )
    
    def _generate_explanation(self, code: str, language: str, task: str) -> str:
        """Generate code explanation."""
        if not self.llm_provider:
            return f"Code implementation for: {task}"
        
        prompt = f"""Explain this {language} code in 2-3 sentences:

{code[:500]}

Explanation:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=150,
                temperature=0.5,
                task_type='code'
            )
            
            return response.get('content', '').strip()
        except:
            return f"Implementation for: {task}"
    
    def debug_code(self, code: str, language: str, error_message: Optional[str] = None) -> Dict[str, Any]:
        """
        Debug code and suggest fixes.
        
        Args:
            code: Code with issues
            language: Programming language
            error_message: Error message if available
            
        Returns:
            Debug analysis with suggested fixes
        """
        analysis = self.analyze_code(code, language)
        
        if not self.llm_provider:
            return {
                'issues': analysis.issues,
                'suggestions': analysis.suggestions,
                'fixed_code': code,
                'explanation': "Run code analysis complete. Review issues and suggestions."
            }
        
        prompt = f"""Debug this {language} code and suggest fixes:

Code:
```{language}
{code}
```
"""
        
        if error_message:
            prompt += f"\nError Message: {error_message}"
        
        prompt += "\n\nProvide:\n1. Problem diagnosis\n2. Fixed code\n3. Explanation of changes"
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=1500,
                temperature=0.3,
                task_type='code'
            )
            
            content = response.get('content', '')
            
            fixed_code = self._extract_code_from_response(content, language)
            
            return {
                'issues': analysis.issues,
                'suggestions': analysis.suggestions,
                'fixed_code': fixed_code if fixed_code != content else code,
                'explanation': content,
                'security_issues': analysis.security_issues
            }
            
        except Exception as e:
            return {
                'issues': analysis.issues,
                'suggestions': analysis.suggestions,
                'fixed_code': code,
                'explanation': f"Debug analysis complete. Error: {str(e)}",
                'security_issues': analysis.security_issues
            }
    
    def refactor_code(self, code: str, language: str, goal: str = "improve readability") -> Dict[str, Any]:
        """
        Refactor code for better quality.
        
        Args:
            code: Original code
            language: Programming language
            goal: Refactoring goal
            
        Returns:
            Refactored code with explanation
        """
        if not self.llm_provider:
            return {
                'refactored_code': code,
                'changes': ["No LLM available for refactoring"],
                'improvements': []
            }
        
        prompt = f"""Refactor this {language} code to {goal}:

```{language}
{code}
```

Provide:
1. Refactored code
2. List of changes made
3. Benefits of refactoring

Refactored code:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=1500,
                temperature=0.3,
                task_type='code'
            )
            
            content = response.get('content', '')
            
            refactored = self._extract_code_from_response(content, language)
            
            return {
                'refactored_code': refactored,
                'changes': [f"Refactored to {goal}"],
                'improvements': ["Code structure improved", "Readability enhanced"],
                'explanation': content
            }
            
        except Exception as e:
            return {
                'refactored_code': code,
                'changes': [],
                'improvements': [],
                'explanation': f"Refactoring error: {str(e)}"
            }
    
    def explain_code(self, code: str, language: str, detail_level: str = "moderate") -> str:
        """
        Explain what code does.
        
        Args:
            code: Code to explain
            language: Programming language
            detail_level: "brief", "moderate", or "detailed"
            
        Returns:
            Code explanation
        """
        if not self.llm_provider:
            lines = code.split('\n')
            return f"Code has {len(lines)} lines in {language}. Contains {code.count('def ')} functions."
        
        detail_instructions = {
            'brief': "Provide a 1-2 sentence overview",
            'moderate': "Explain main functionality and key components",
            'detailed': "Provide line-by-line explanation of logic"
        }
        
        instruction = detail_instructions.get(detail_level, detail_instructions['moderate'])
        
        prompt = f"""Explain this {language} code. {instruction}:

```{language}
{code[:1500]}
```

Explanation:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=500,
                temperature=0.5,
                task_type='code'
            )
            
            return response.get('content', '').strip()
            
        except Exception as e:
            return f"Explanation error: {str(e)}"
    
    def generate_tests(self, code: str, language: str, framework: Optional[str] = None) -> str:
        """
        Generate unit tests for code.
        
        Args:
            code: Code to test
            language: Programming language
            framework: Testing framework (pytest, jest, junit, etc.)
            
        Returns:
            Test code
        """
        if not framework:
            framework_defaults = {
                'python': 'pytest',
                'javascript': 'jest',
                'typescript': 'jest',
                'java': 'junit',
                'csharp': 'NUnit'
            }
            framework = framework_defaults.get(language, 'unit test framework')
        
        if not self.llm_provider:
            return self._generate_test_template(code, language, framework)
        
        prompt = f"""Generate comprehensive unit tests for this {language} code using {framework}:

```{language}
{code}
```

Include:
1. Test cases for normal operation
2. Edge cases
3. Error handling tests

Test code:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=1500,
                temperature=0.3,
                task_type='code'
            )
            
            content = response.get('content', '')
            
            test_code = self._extract_code_from_response(content, language)
            
            return test_code if test_code != content else content
            
        except Exception as e:
            return self._generate_test_template(code, language, framework)
    
    def _generate_test_template(self, code: str, language: str, framework: str) -> str:
        """Generate basic test template."""
        if language == 'python':
            return f'''import pytest

def test_basic():
    """Test basic functionality."""
    # TODO: Implement test
    assert True

def test_edge_cases():
    """Test edge cases."""
    # TODO: Implement test
    pass
'''
        else:
            return f'// TODO: Generate tests using {framework}\n// Test code here'
