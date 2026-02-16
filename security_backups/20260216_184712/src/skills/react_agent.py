"""
ReAct Agent - Reason + Act loop for autonomous problem solving.

Based on Leon AI's agentic behavior architecture.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import time


class AgentState(Enum):
    """Agent cognitive state."""
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    COMPLETE = "complete"
    STUCK = "stuck"


@dataclass
class Thought:
    """Agent thought."""
    content: str
    reasoning: str
    confidence: float
    timestamp: float


@dataclass
class Action:
    """Agent action."""
    tool: str
    parameters: Dict[str, Any]
    rationale: str


@dataclass
class Observation:
    """Action observation."""
    success: bool
    result: Any
    feedback: str


class ReActAgent:
    """
    ReAct (Reason + Act) agent for autonomous problem solving.
    
    Implements thought-action-observation loop with local LLM optimization.
    """
    
    def __init__(self, llm_provider, skill_engine, max_iterations: int = 10):
        """
        Initialize ReAct agent.
        
        Args:
            llm_provider: LLM for reasoning
            skill_engine: Skill engine for actions
            max_iterations: Maximum thought-action loops
        """
        self.llm_provider = llm_provider
        self.skill_engine = skill_engine
        self.max_iterations = max_iterations
        
        self.state = AgentState.THINKING
        self.thoughts: List[Thought] = []
        self.actions: List[Action] = []
        self.observations: List[Observation] = []
        self.final_answer: Optional[str] = None
    
    def solve(self, problem: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Solve problem using ReAct loop.
        
        Args:
            problem: Problem to solve
            context: Additional context
            
        Returns:
            Solution with reasoning trace
        """
        context = context or {}
        
        self._reset()
        
        for iteration in range(self.max_iterations):
            self.state = AgentState.THINKING
            thought = self._think(problem, context, iteration)
            self.thoughts.append(thought)
            
            if self._should_conclude(thought):
                self.state = AgentState.COMPLETE
                self.final_answer = thought.content
                break
            
            self.state = AgentState.ACTING
            action = self._decide_action(thought, problem)
            self.actions.append(action)
            
            self.state = AgentState.OBSERVING
            observation = self._execute_and_observe(action)
            self.observations.append(observation)
            
            context['last_observation'] = observation.result
            context['iteration'] = iteration + 1
            
            if not observation.success:
                if iteration >= self.max_iterations - 1:
                    self.state = AgentState.STUCK
                    break
        
        return {
            'problem': problem,
            'final_answer': self.final_answer,
            'thoughts': [self._thought_to_dict(t) for t in self.thoughts],
            'actions': [self._action_to_dict(a) for a in self.actions],
            'observations': [self._observation_to_dict(o) for o in self.observations],
            'iterations': len(self.thoughts),
            'state': self.state.value,
            'reasoning_trace': self._format_reasoning_trace()
        }
    
    def _think(self, problem: str, context: Dict[str, Any], iteration: int) -> Thought:
        """Generate thought about next step."""
        available_tools = self._get_available_tools_context()
        
        history = self._format_history()
        
        prompt = f"""You are an autonomous agent solving a problem. Think step-by-step.

Problem: {problem}

Available Tools:
{available_tools}

{history}

Current Iteration: {iteration + 1}/{self.max_iterations}

Think about:
1. What have we learned so far?
2. What should we do next?
3. Should we conclude with an answer or take another action?

If you have enough information, start your thought with "CONCLUDE:" followed by the final answer.
Otherwise, describe what action to take next.

Thought:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=300,
                temperature=0.7,
                task_type='analysis'
            )
            
            content = response.get('content', '').strip()
            
            confidence = 0.8 if 'CONCLUDE:' in content else 0.6
            
            reasoning = self._extract_reasoning(content)
            
            return Thought(
                content=content,
                reasoning=reasoning,
                confidence=confidence,
                timestamp=time.time()
            )
            
        except Exception as e:
            return Thought(
                content=f"Error in thinking: {str(e)}",
                reasoning="Failed to generate thought",
                confidence=0.0,
                timestamp=time.time()
            )
    
    def _should_conclude(self, thought: Thought) -> bool:
        """Check if agent should conclude."""
        return 'CONCLUDE:' in thought.content.upper() or thought.confidence > 0.95
    
    def _decide_action(self, thought: Thought, problem: str) -> Action:
        """Decide which action to take based on thought."""
        tools_list = '\n'.join([
            f"- {tool['name']}: {tool['description']}"
            for tool in self.skill_engine.list_tools()
        ])
        
        prompt = f"""Based on this thought, decide which tool to use and with what parameters.

Thought: {thought.content}

Available Tools:
{tools_list}

Provide action in format:
TOOL: [tool_name]
PARAMETERS: {{"param1": "value1", "param2": "value2"}}
RATIONALE: Why this action helps solve the problem

Action:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=200,
                temperature=0.3,
                task_type='analysis'
            )
            
            content = response.get('content', '')
            
            import re
            
            tool_match = re.search(r'TOOL:\s*(\w+)', content)
            tool_name = tool_match.group(1) if tool_match else "string_transform"
            
            params_match = re.search(r'PARAMETERS:\s*({.*?})', content, re.DOTALL)
            params = eval(params_match.group(1)) if params_match else {}
            
            rationale_match = re.search(r'RATIONALE:\s*(.+)', content)
            rationale = rationale_match.group(1).strip() if rationale_match else "Default action"
            
            return Action(
                tool=tool_name,
                parameters=params,
                rationale=rationale
            )
            
        except Exception as e:
            return Action(
                tool="string_transform",
                parameters={"text": problem, "mode": "lower"},
                rationale=f"Fallback action due to error: {str(e)}"
            )
    
    def _execute_and_observe(self, action: Action) -> Observation:
        """Execute action and observe result."""
        try:
            result = self.skill_engine.execute_tool(action.tool, **action.parameters)
            
            return Observation(
                success=True,
                result=result,
                feedback=f"Tool {action.tool} executed successfully"
            )
            
        except Exception as e:
            return Observation(
                success=False,
                result=None,
                feedback=f"Action failed: {str(e)}"
            )
    
    def _get_available_tools_context(self) -> str:
        """Get context about available tools."""
        tools = self.skill_engine.list_tools()
        
        return '\n'.join([
            f"- {tool['name']}: {tool['description']}"
            for tool in tools[:10]
        ])
    
    def _format_history(self) -> str:
        """Format reasoning history."""
        if not self.thoughts:
            return "History: (This is the first iteration)"
        
        history_parts = ["Previous Steps:"]
        
        for i, (thought, action, obs) in enumerate(zip(
            self.thoughts, self.actions, self.observations
        )):
            history_parts.append(f"\nStep {i+1}:")
            history_parts.append(f"  Thought: {thought.content[:100]}...")
            history_parts.append(f"  Action: {action.tool} with {action.parameters}")
            history_parts.append(f"  Result: {obs.result}")
        
        return '\n'.join(history_parts)
    
    def _extract_reasoning(self, content: str) -> str:
        """Extract core reasoning from thought."""
        lines = content.split('\n')
        reasoning_lines = [line for line in lines if line.strip() and not line.startswith('CONCLUDE:')]
        return ' '.join(reasoning_lines[:3])
    
    def _format_reasoning_trace(self) -> str:
        """Format complete reasoning trace."""
        trace_parts = []
        
        for i, thought in enumerate(self.thoughts, 1):
            trace_parts.append(f"**Thought {i}**: {thought.content}")
            
            if i <= len(self.actions):
                action = self.actions[i-1]
                trace_parts.append(f"  → **Action**: {action.tool}({action.parameters})")
                trace_parts.append(f"  → **Rationale**: {action.rationale}")
            
            if i <= len(self.observations):
                obs = self.observations[i-1]
                trace_parts.append(f"  → **Observation**: {obs.feedback}")
        
        if self.final_answer:
            trace_parts.append(f"\n**Final Answer**: {self.final_answer}")
        
        return '\n'.join(trace_parts)
    
    def _reset(self):
        """Reset agent state."""
        self.state = AgentState.THINKING
        self.thoughts = []
        self.actions = []
        self.observations = []
        self.final_answer = None
    
    def _thought_to_dict(self, thought: Thought) -> Dict[str, Any]:
        """Convert Thought to dict."""
        return {
            'content': thought.content,
            'reasoning': thought.reasoning,
            'confidence': thought.confidence,
            'timestamp': thought.timestamp
        }
    
    def _action_to_dict(self, action: Action) -> Dict[str, Any]:
        """Convert Action to dict."""
        return {
            'tool': action.tool,
            'parameters': action.parameters,
            'rationale': action.rationale
        }
    
    def _observation_to_dict(self, obs: Observation) -> Dict[str, Any]:
        """Convert Observation to dict."""
        return {
            'success': obs.success,
            'result': str(obs.result) if obs.result is not None else None,
            'feedback': obs.feedback
        }
    
    def get_agent_state(self) -> Dict[str, Any]:
        """Get current agent state."""
        return {
            'state': self.state.value,
            'iterations_used': len(self.thoughts),
            'max_iterations': self.max_iterations,
            'has_answer': self.final_answer is not None,
            'success_rate': sum(1 for o in self.observations if o.success) / max(len(self.observations), 1)
        }
