"""
Leon-inspired Skills Engine - Modular skill system with workflow orchestration.

Architecture: Skills > Actions > Tools > Functions
Based on Leon AI's design philosophy.
"""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import importlib
import inspect
from datetime import datetime


class SkillStatus(Enum):
    """Skill execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ToolDefinition:
    """Atomic tool definition."""
    name: str
    description: str
    function: Callable
    parameters: Dict[str, Any]
    returns: str


@dataclass
class ActionDefinition:
    """Action composed of multiple tools."""
    name: str
    description: str
    tools: List[str]
    workflow: List[Dict[str, Any]]


@dataclass
class SkillDefinition:
    """Skill composed of multiple actions."""
    name: str
    category: str
    description: str
    version: str
    author: str
    actions: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SkillExecutionResult:
    """Result of skill execution."""
    skill_name: str
    action_name: str
    status: SkillStatus
    output: Any
    execution_time: float
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SkillEngine:
    """
    Leon-inspired skill engine with workflow orchestration.
    
    Implements Skills > Actions > Tools > Functions architecture.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize skill engine.
        
        Args:
            llm_provider: LLM for autonomous skill generation
        """
        self.llm_provider = llm_provider
        self.tools: Dict[str, ToolDefinition] = {}
        self.actions: Dict[str, ActionDefinition] = {}
        self.skills: Dict[str, SkillDefinition] = {}
        self.execution_history: List[SkillExecutionResult] = []
        
        self._register_builtin_tools()
    
    def _register_builtin_tools(self):
        """Register built-in atomic tools."""
        self.register_tool(
            name="string_transform",
            description="Transform string (uppercase, lowercase, capitalize)",
            function=lambda text, mode: getattr(text, mode)(),
            parameters={"text": "string", "mode": "string"},
            returns="string"
        )
        
        self.register_tool(
            name="math_calculate",
            description="Perform mathematical calculation",
            function=lambda expression: eval(expression, {"__builtins__": {}}),
            parameters={"expression": "string"},
            returns="number"
        )
        
        self.register_tool(
            name="list_filter",
            description="Filter list by condition",
            function=lambda items, condition: [item for item in items if condition(item)],
            parameters={"items": "list", "condition": "function"},
            returns="list"
        )
    
    def register_tool(self, name: str, description: str, function: Callable,
                     parameters: Dict[str, Any], returns: str):
        """
        Register an atomic tool.
        
        Args:
            name: Tool name
            description: Tool description
            function: Tool implementation function
            parameters: Parameter definitions
            returns: Return type description
        """
        tool = ToolDefinition(
            name=name,
            description=description,
            function=function,
            parameters=parameters,
            returns=returns
        )
        
        self.tools[name] = tool
    
    def register_action(self, name: str, description: str, tools: List[str],
                       workflow: List[Dict[str, Any]]):
        """
        Register an action (workflow of tools).
        
        Args:
            name: Action name
            description: Action description
            tools: List of tool names used
            workflow: Workflow steps definition
        """
        for tool_name in tools:
            if tool_name not in self.tools:
                raise ValueError(f"Tool not found: {tool_name}")
        
        action = ActionDefinition(
            name=name,
            description=description,
            tools=tools,
            workflow=workflow
        )
        
        self.actions[name] = action
    
    def register_skill(self, name: str, category: str, description: str,
                      version: str, author: str, actions: List[str],
                      metadata: Optional[Dict[str, Any]] = None):
        """
        Register a skill (collection of actions).
        
        Args:
            name: Skill name
            category: Skill category
            description: Skill description
            version: Skill version
            author: Skill author
            actions: List of action names
            metadata: Additional metadata
        """
        for action_name in actions:
            if action_name not in self.actions:
                raise ValueError(f"Action not found: {action_name}")
        
        skill = SkillDefinition(
            name=name,
            category=category,
            description=description,
            version=version,
            author=author,
            actions=actions,
            metadata=metadata or {}
        )
        
        self.skills[name] = skill
    
    def execute_tool(self, tool_name: str, **kwargs) -> Any:
        """
        Execute an atomic tool.
        
        Args:
            tool_name: Tool to execute
            **kwargs: Tool parameters
            
        Returns:
            Tool execution result
        """
        if tool_name not in self.tools:
            raise ValueError(f"Tool not found: {tool_name}")
        
        tool = self.tools[tool_name]
        
        try:
            result = tool.function(**kwargs)
            return result
        except Exception as e:
            raise Exception(f"Tool execution failed: {str(e)}")
    
    def execute_action(self, action_name: str, inputs: Dict[str, Any]) -> Any:
        """
        Execute an action workflow.
        
        Args:
            action_name: Action to execute
            inputs: Input parameters
            
        Returns:
            Action execution result
        """
        if action_name not in self.actions:
            raise ValueError(f"Action not found: {action_name}")
        
        action = self.actions[action_name]
        
        context = inputs.copy()
        
        for step in action.workflow:
            tool_name = step['tool']
            tool_inputs = {}
            
            for param_name, param_source in step.get('inputs', {}).items():
                if isinstance(param_source, str) and param_source.startswith('$'):
                    context_key = param_source[1:]
                    tool_inputs[param_name] = context.get(context_key)
                else:
                    tool_inputs[param_name] = param_source
            
            result = self.execute_tool(tool_name, **tool_inputs)
            
            output_name = step.get('output', 'result')
            context[output_name] = result
        
        return context.get('result', context)
    
    def execute_skill(self, skill_name: str, action_name: str,
                     inputs: Dict[str, Any]) -> SkillExecutionResult:
        """
        Execute a skill action.
        
        Args:
            skill_name: Skill to execute
            action_name: Action within skill
            inputs: Input parameters
            
        Returns:
            SkillExecutionResult
        """
        if skill_name not in self.skills:
            raise ValueError(f"Skill not found: {skill_name}")
        
        skill = self.skills[skill_name]
        
        if action_name not in skill.actions:
            raise ValueError(f"Action {action_name} not in skill {skill_name}")
        
        start_time = datetime.now()
        
        try:
            output = self.execute_action(action_name, inputs)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            result = SkillExecutionResult(
                skill_name=skill_name,
                action_name=action_name,
                status=SkillStatus.COMPLETED,
                output=output,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            
            result = SkillExecutionResult(
                skill_name=skill_name,
                action_name=action_name,
                status=SkillStatus.FAILED,
                output=None,
                execution_time=execution_time,
                error=str(e)
            )
        
        self.execution_history.append(result)
        
        return result
    
    def find_skill_for_intent(self, intent: str) -> Optional[str]:
        """
        Find appropriate skill for user intent.
        
        Args:
            intent: User intent/query
            
        Returns:
            Best matching skill name or None
        """
        intent_lower = intent.lower()
        
        best_match = None
        best_score = 0
        
        for skill_name, skill in self.skills.items():
            score = 0
            
            if skill_name.lower() in intent_lower:
                score += 5
            
            if skill.category.lower() in intent_lower:
                score += 3
            
            keywords = skill.description.lower().split()
            for keyword in keywords:
                if keyword in intent_lower:
                    score += 1
            
            if score > best_score:
                best_score = score
                best_match = skill_name
        
        return best_match if best_score > 0 else None
    
    def generate_skill_code(self, skill_description: str) -> str:
        """
        Autonomous skill generation (Leon's self-coding feature).
        
        Args:
            skill_description: What the skill should do
            
        Returns:
            Generated skill code
        """
        if not self.llm_provider:
            return self._generate_skill_template(skill_description)
        
        available_tools = '\n'.join([
            f"- {name}: {tool.description}"
            for name, tool in self.tools.items()
        ])
        
        prompt = f"""Generate a complete skill definition in Python for: {skill_description}

Available Tools:
{available_tools}

Generate skill code following this structure:

```python
# Skill: [skill_name]
# Category: [category]
# Description: [description]

# 1. Register actions
skill_engine.register_action(
    name="action_name",
    description="What this action does",
    tools=["tool1", "tool2"],
    workflow=[
        {{"tool": "tool1", "inputs": {{"param": "$input"}}, "output": "intermediate"}},
        {{"tool": "tool2", "inputs": {{"param": "$intermediate"}}, "output": "result"}}
    ]
)

# 2. Register skill
skill_engine.register_skill(
    name="skill_name",
    category="category",
    description="Full description",
    version="1.0.0",
    author="Aether AI",
    actions=["action_name"]
)
```

Generate the complete skill code:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=1000,
                temperature=0.3,
                task_type='code'
            )
            
            code = response.get('content', '')
            
            code_match = code
            if '```python' in code:
                import re
                match = re.search(r'```python\n(.*?)```', code, re.DOTALL)
                if match:
                    code_match = match.group(1)
            
            return code_match
            
        except Exception as e:
            print(f"Autonomous skill generation error: {e}")
            return self._generate_skill_template(skill_description)
    
    def _generate_skill_template(self, description: str) -> str:
        """Generate basic skill template."""
        return f'''# Skill: custom_skill
# Description: {description}

# TODO: Implement skill actions and workflow
skill_engine.register_action(
    name="custom_action",
    description="{description}",
    tools=[],
    workflow=[]
)

skill_engine.register_skill(
    name="custom_skill",
    category="custom",
    description="{description}",
    version="1.0.0",
    author="User Generated",
    actions=["custom_action"]
)
'''
    
    def load_skill_from_code(self, code: str) -> bool:
        """
        Load skill from generated code.
        
        Args:
            code: Skill code
            
        Returns:
            True if loaded successfully
        """
        try:
            namespace = {'skill_engine': self}
            exec(code, namespace)
            return True
        except Exception as e:
            print(f"Skill loading error: {e}")
            return False
    
    def list_skills(self) -> List[Dict[str, Any]]:
        """List all registered skills."""
        return [
            {
                'name': skill.name,
                'category': skill.category,
                'description': skill.description,
                'version': skill.version,
                'author': skill.author,
                'actions': skill.actions
            }
            for skill in self.skills.values()
        ]
    
    def list_actions(self) -> List[Dict[str, str]]:
        """List all registered actions."""
        return [
            {
                'name': action.name,
                'description': action.description,
                'tools': action.tools
            }
            for action in self.actions.values()
        ]
    
    def list_tools(self) -> List[Dict[str, str]]:
        """List all registered tools."""
        return [
            {
                'name': tool.name,
                'description': tool.description,
                'returns': tool.returns
            }
            for tool in self.tools.values()
        ]
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get skill execution statistics."""
        if not self.execution_history:
            return {'total_executions': 0}
        
        total = len(self.execution_history)
        completed = sum(1 for r in self.execution_history if r.status == SkillStatus.COMPLETED)
        failed = sum(1 for r in self.execution_history if r.status == SkillStatus.FAILED)
        
        avg_time = sum(r.execution_time for r in self.execution_history) / total
        
        return {
            'total_executions': total,
            'completed': completed,
            'failed': failed,
            'success_rate': round(completed / total, 2),
            'avg_execution_time': round(avg_time, 2)
        }
