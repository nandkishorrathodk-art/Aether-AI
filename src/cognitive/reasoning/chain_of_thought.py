"""Chain-of-Thought reasoning implementation for step-by-step problem solving."""

import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import re


@dataclass
class ReasoningStep:
    """A single step in chain-of-thought reasoning."""
    step_number: int
    thought: str
    action: Optional[str] = None
    observation: Optional[str] = None
    confidence: float = 1.0


class ChainOfThoughtReasoner:
    """
    Implements Chain-of-Thought (CoT) reasoning for complex problem solving.
    
    CoT breaks down problems into explicit reasoning steps, making the
    AI's thinking process transparent and more accurate.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize Chain-of-Thought reasoner.
        
        Args:
            llm_provider: Language model provider for generating reasoning steps
        """
        self.llm_provider = llm_provider
        self.reasoning_history: List[List[ReasoningStep]] = []
        
    def reason(self, problem: str, context: Optional[Dict[str, Any]] = None,
               max_steps: int = 10) -> Dict[str, Any]:
        """
        Apply chain-of-thought reasoning to solve a problem.
        
        Args:
            problem: The problem to solve
            context: Additional context information
            max_steps: Maximum reasoning steps to take
            
        Returns:
            Dictionary with reasoning steps and final answer
        """
        context = context or {}
        steps: List[ReasoningStep] = []
        
        prompt = self._build_cot_prompt(problem, context)
        
        if self.llm_provider:
            response = self._get_llm_reasoning(prompt, max_steps)
            steps = self._parse_reasoning_steps(response)
        else:
            steps = self._heuristic_reasoning(problem, max_steps)
        
        self.reasoning_history.append(steps)
        
        return {
            'problem': problem,
            'steps': [self._step_to_dict(s) for s in steps],
            'answer': self._extract_answer(steps),
            'confidence': self._calculate_confidence(steps),
            'reasoning_path': self._format_reasoning_path(steps)
        }
    
    def _build_cot_prompt(self, problem: str, context: Dict[str, Any]) -> str:
        """Build a chain-of-thought prompt."""
        prompt = f"""Let's solve this problem step by step.

Problem: {problem}

"""
        if context:
            prompt += f"Context: {json.dumps(context, indent=2)}\n\n"
        
        prompt += """Please think through this carefully:
1. Break down the problem into smaller parts
2. Reason through each part systematically
3. Show your work at each step
4. Arrive at a final answer

Let's begin:
"""
        return prompt
    
    def _get_llm_reasoning(self, prompt: str, max_steps: int) -> str:
        """Get reasoning from LLM provider."""
        if not self.llm_provider:
            return ""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=2000,
                temperature=0.7,
                task_type='analysis'
            )
            return response.get('content', '')
        except Exception as e:
            print(f"LLM reasoning error: {e}")
            return ""
    
    def _parse_reasoning_steps(self, response: str) -> List[ReasoningStep]:
        """Parse reasoning steps from LLM response."""
        steps = []
        
        lines = response.split('\n')
        step_num = 1
        current_thought = []
        
        for line in lines:
            line = line.strip()
            if not line:
                if current_thought:
                    steps.append(ReasoningStep(
                        step_number=step_num,
                        thought=' '.join(current_thought)
                    ))
                    current_thought = []
                    step_num += 1
            else:
                step_match = re.match(r'^(?:Step\s+)?(\d+)[\.:]\s*(.+)$', line, re.IGNORECASE)
                if step_match:
                    if current_thought:
                        steps.append(ReasoningStep(
                            step_number=step_num,
                            thought=' '.join(current_thought)
                        ))
                        current_thought = []
                    step_num = int(step_match.group(1))
                    current_thought.append(step_match.group(2))
                else:
                    current_thought.append(line)
        
        if current_thought:
            steps.append(ReasoningStep(
                step_number=step_num,
                thought=' '.join(current_thought)
            ))
        
        if not steps:
            steps.append(ReasoningStep(
                step_number=1,
                thought=response
            ))
        
        return steps
    
    def _heuristic_reasoning(self, problem: str, max_steps: int) -> List[ReasoningStep]:
        """Fallback heuristic reasoning when no LLM available."""
        steps = []
        
        steps.append(ReasoningStep(
            step_number=1,
            thought=f"Understand the problem: {problem}"
        ))
        
        steps.append(ReasoningStep(
            step_number=2,
            thought="Identify key components and requirements"
        ))
        
        steps.append(ReasoningStep(
            step_number=3,
            thought="Consider possible approaches"
        ))
        
        steps.append(ReasoningStep(
            step_number=4,
            thought="Select most appropriate solution strategy"
        ))
        
        steps.append(ReasoningStep(
            step_number=5,
            thought="Formulate final answer based on reasoning"
        ))
        
        return steps[:max_steps]
    
    def _extract_answer(self, steps: List[ReasoningStep]) -> str:
        """Extract final answer from reasoning steps."""
        if not steps:
            return "Unable to determine answer"
        
        last_step = steps[-1].thought
        
        answer_keywords = ['therefore', 'thus', 'answer is', 'conclusion', 'final answer', 'result']
        for keyword in answer_keywords:
            if keyword in last_step.lower():
                parts = last_step.lower().split(keyword)
                if len(parts) > 1:
                    return parts[-1].strip().capitalize()
        
        return last_step
    
    def _calculate_confidence(self, steps: List[ReasoningStep]) -> float:
        """Calculate confidence in reasoning."""
        if not steps:
            return 0.0
        
        avg_confidence = sum(s.confidence for s in steps) / len(steps)
        
        length_penalty = max(0.8, 1.0 - (len(steps) - 5) * 0.02)
        
        return min(1.0, avg_confidence * length_penalty)
    
    def _format_reasoning_path(self, steps: List[ReasoningStep]) -> str:
        """Format reasoning steps as readable text."""
        if not steps:
            return "No reasoning path available"
        
        path = []
        for step in steps:
            path.append(f"Step {step.step_number}: {step.thought}")
            if step.action:
                path.append(f"  → Action: {step.action}")
            if step.observation:
                path.append(f"  → Observation: {step.observation}")
        
        return '\n'.join(path)
    
    def _step_to_dict(self, step: ReasoningStep) -> Dict[str, Any]:
        """Convert reasoning step to dictionary."""
        return {
            'step_number': step.step_number,
            'thought': step.thought,
            'action': step.action,
            'observation': step.observation,
            'confidence': step.confidence
        }
    
    def get_reasoning_history(self) -> List[Dict[str, Any]]:
        """Get history of all reasoning sessions."""
        return [
            {
                'steps': [self._step_to_dict(s) for s in session],
                'num_steps': len(session)
            }
            for session in self.reasoning_history
        ]
    
    def clear_history(self):
        """Clear reasoning history."""
        self.reasoning_history.clear()
