"""Tree-of-Thought reasoning for exploring multiple solution paths."""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
import heapq
from enum import Enum


class ThoughtState(Enum):
    """State of a thought node."""
    ACTIVE = "active"
    PRUNED = "pruned"
    TERMINAL = "terminal"
    OPTIMAL = "optimal"


@dataclass
class ThoughtNode:
    """A node in the tree of thoughts."""
    id: str
    thought: str
    parent_id: Optional[str] = None
    depth: int = 0
    value: float = 0.0
    state: ThoughtState = ThoughtState.ACTIVE
    children: List[str] = field(default_factory=list)
    reasoning: str = ""
    
    def __lt__(self, other):
        """Compare nodes by value for priority queue."""
        return self.value > other.value


class TreeOfThoughtReasoner:
    """
    Implements Tree-of-Thought (ToT) reasoning for complex problem solving.
    
    ToT explores multiple reasoning paths simultaneously, evaluating and
    pruning branches to find optimal solutions.
    """
    
    def __init__(self, llm_provider=None, max_depth: int = 5, 
                 branches_per_node: int = 3):
        """
        Initialize Tree-of-Thought reasoner.
        
        Args:
            llm_provider: Language model provider
            max_depth: Maximum depth of thought tree
            branches_per_node: Number of branches to explore per node
        """
        self.llm_provider = llm_provider
        self.max_depth = max_depth
        self.branches_per_node = branches_per_node
        self.nodes: Dict[str, ThoughtNode] = {}
        self.node_counter = 0
        
    def reason(self, problem: str, context: Optional[Dict[str, Any]] = None,
               strategy: str = 'best_first') -> Dict[str, Any]:
        """
        Apply tree-of-thought reasoning to solve a problem.
        
        Args:
            problem: The problem to solve
            context: Additional context
            strategy: Search strategy ('best_first', 'breadth_first', 'beam')
            
        Returns:
            Dictionary with reasoning tree and optimal solution
        """
        context = context or {}
        
        root = self._create_node(
            thought=f"Problem: {problem}",
            reasoning="Initial problem statement"
        )
        
        if strategy == 'best_first':
            solution = self._best_first_search(root, problem, context)
        elif strategy == 'breadth_first':
            solution = self._breadth_first_search(root, problem, context)
        elif strategy == 'beam':
            solution = self._beam_search(root, problem, context)
        else:
            solution = self._best_first_search(root, problem, context)
        
        return {
            'problem': problem,
            'strategy': strategy,
            'tree': self._serialize_tree(),
            'optimal_path': solution['path'],
            'answer': solution['answer'],
            'value': solution['value'],
            'nodes_explored': len(self.nodes),
            'reasoning_trace': solution['trace']
        }
    
    def _create_node(self, thought: str, parent_id: Optional[str] = None,
                    reasoning: str = "") -> ThoughtNode:
        """Create a new thought node."""
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        
        depth = 0
        if parent_id and parent_id in self.nodes:
            parent = self.nodes[parent_id]
            depth = parent.depth + 1
            parent.children.append(node_id)
        
        node = ThoughtNode(
            id=node_id,
            thought=thought,
            parent_id=parent_id,
            depth=depth,
            reasoning=reasoning
        )
        
        self.nodes[node_id] = node
        return node
    
    def _best_first_search(self, root: ThoughtNode, problem: str,
                           context: Dict[str, Any]) -> Dict[str, Any]:
        """Best-first search using priority queue."""
        pq = [root]
        heapq.heapify(pq)
        
        best_solution = None
        best_value = float('-inf')
        
        while pq and len(self.nodes) < 100:
            current = heapq.heappop(pq)
            
            if current.state != ThoughtState.ACTIVE:
                continue
            
            if current.depth >= self.max_depth:
                current.state = ThoughtState.TERMINAL
                if current.value > best_value:
                    best_value = current.value
                    best_solution = current
                continue
            
            children = self._generate_thoughts(current, problem, context)
            
            for child in children:
                self._evaluate_thought(child, problem, context)
                
                if child.value > 0.3:
                    heapq.heappush(pq, child)
                else:
                    child.state = ThoughtState.PRUNED
            
            if not children:
                current.state = ThoughtState.TERMINAL
                if current.value > best_value:
                    best_value = current.value
                    best_solution = current
        
        if best_solution:
            best_solution.state = ThoughtState.OPTIMAL
            path = self._extract_path(best_solution)
            trace = self._format_trace(path)
            
            return {
                'path': path,
                'answer': best_solution.thought,
                'value': best_solution.value,
                'trace': trace
            }
        
        return {
            'path': [root.id],
            'answer': "Unable to find solution",
            'value': 0.0,
            'trace': "No viable reasoning path found"
        }
    
    def _breadth_first_search(self, root: ThoughtNode, problem: str,
                             context: Dict[str, Any]) -> Dict[str, Any]:
        """Breadth-first exploration of thought tree."""
        queue = [root]
        best_solution = None
        best_value = float('-inf')
        
        while queue and len(self.nodes) < 100:
            current = queue.pop(0)
            
            if current.depth >= self.max_depth:
                current.state = ThoughtState.TERMINAL
                if current.value > best_value:
                    best_value = current.value
                    best_solution = current
                continue
            
            children = self._generate_thoughts(current, problem, context)
            
            for child in children:
                self._evaluate_thought(child, problem, context)
                if child.value > 0.3:
                    queue.append(child)
                else:
                    child.state = ThoughtState.PRUNED
        
        if best_solution:
            best_solution.state = ThoughtState.OPTIMAL
            path = self._extract_path(best_solution)
            trace = self._format_trace(path)
            
            return {
                'path': path,
                'answer': best_solution.thought,
                'value': best_solution.value,
                'trace': trace
            }
        
        return {
            'path': [root.id],
            'answer': "Unable to find solution",
            'value': 0.0,
            'trace': "No viable reasoning path found"
        }
    
    def _beam_search(self, root: ThoughtNode, problem: str,
                     context: Dict[str, Any], beam_width: int = 3) -> Dict[str, Any]:
        """Beam search with limited width."""
        beam = [root]
        
        for depth in range(self.max_depth):
            candidates = []
            
            for node in beam:
                children = self._generate_thoughts(node, problem, context)
                for child in children:
                    self._evaluate_thought(child, problem, context)
                    candidates.append(child)
            
            if not candidates:
                break
            
            candidates.sort(key=lambda n: n.value, reverse=True)
            beam = candidates[:beam_width]
        
        if beam:
            best = max(beam, key=lambda n: n.value)
            best.state = ThoughtState.OPTIMAL
            path = self._extract_path(best)
            trace = self._format_trace(path)
            
            return {
                'path': path,
                'answer': best.thought,
                'value': best.value,
                'trace': trace
            }
        
        return {
            'path': [root.id],
            'answer': "Unable to find solution",
            'value': 0.0,
            'trace': "No viable reasoning path found"
        }
    
    def _generate_thoughts(self, node: ThoughtNode, problem: str,
                          context: Dict[str, Any]) -> List[ThoughtNode]:
        """Generate child thoughts from current node."""
        if self.llm_provider:
            return self._generate_thoughts_llm(node, problem, context)
        else:
            return self._generate_thoughts_heuristic(node, problem, context)
    
    def _generate_thoughts_llm(self, node: ThoughtNode, problem: str,
                              context: Dict[str, Any]) -> List[ThoughtNode]:
        """Generate thoughts using LLM."""
        prompt = f"""Given this problem and current reasoning:

Problem: {problem}
Current thought: {node.thought}

Generate {self.branches_per_node} possible next steps or thoughts to continue reasoning.
Format each as a separate line starting with a number.

Next thoughts:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=500,
                temperature=0.8,
                task_type='analysis'
            )
            
            thoughts = self._parse_thought_list(response.get('content', ''))
            
            return [
                self._create_node(
                    thought=t,
                    parent_id=node.id,
                    reasoning=f"Branching from: {node.thought[:50]}..."
                )
                for t in thoughts[:self.branches_per_node]
            ]
        except Exception as e:
            print(f"LLM thought generation error: {e}")
            return self._generate_thoughts_heuristic(node, problem, context)
    
    def _generate_thoughts_heuristic(self, node: ThoughtNode, problem: str,
                                    context: Dict[str, Any]) -> List[ThoughtNode]:
        """Fallback heuristic thought generation."""
        strategies = [
            "Break down the problem into smaller components",
            "Consider alternative approaches",
            "Apply domain-specific knowledge",
            "Look for patterns or analogies",
            "Test edge cases and constraints"
        ]
        
        thoughts = []
        for i, strategy in enumerate(strategies[:self.branches_per_node]):
            thoughts.append(
                self._create_node(
                    thought=f"{strategy} for: {problem[:50]}...",
                    parent_id=node.id,
                    reasoning=f"Heuristic strategy {i+1}"
                )
            )
        
        return thoughts
    
    def _evaluate_thought(self, node: ThoughtNode, problem: str,
                         context: Dict[str, Any]):
        """Evaluate the value/promise of a thought."""
        if self.llm_provider:
            node.value = self._evaluate_thought_llm(node, problem, context)
        else:
            node.value = self._evaluate_thought_heuristic(node, problem, context)
    
    def _evaluate_thought_llm(self, node: ThoughtNode, problem: str,
                             context: Dict[str, Any]) -> float:
        """Evaluate thought using LLM."""
        prompt = f"""Rate how promising this reasoning step is for solving the problem.

Problem: {problem}
Reasoning step: {node.thought}

Rate from 0.0 (not helpful) to 1.0 (very promising).
Just provide the number.

Rating:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=10,
                temperature=0.3,
                task_type='analysis'
            )
            
            content = response.get('content', '0.5').strip()
            
            try:
                value = float(content.split()[0])
                return max(0.0, min(1.0, value))
            except ValueError:
                return 0.5
        except Exception:
            return 0.5
    
    def _evaluate_thought_heuristic(self, node: ThoughtNode, problem: str,
                                   context: Dict[str, Any]) -> float:
        """Heuristic thought evaluation."""
        value = 0.5
        
        thought_lower = node.thought.lower()
        problem_words = set(problem.lower().split())
        thought_words = set(thought_lower.split())
        overlap = len(problem_words & thought_words)
        
        value += min(0.2, overlap * 0.02)
        
        depth_penalty = node.depth * 0.05
        value -= depth_penalty
        
        positive_words = ['solution', 'answer', 'result', 'conclusion', 'therefore']
        if any(word in thought_lower for word in positive_words):
            value += 0.1
        
        return max(0.0, min(1.0, value))
    
    def _parse_thought_list(self, text: str) -> List[str]:
        """Parse list of thoughts from text."""
        thoughts = []
        lines = text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line[0].isdigit():
                parts = line.split('.', 1)
                if len(parts) > 1:
                    thoughts.append(parts[1].strip())
                else:
                    thoughts.append(line)
            else:
                thoughts.append(line)
        
        return thoughts
    
    def _extract_path(self, node: ThoughtNode) -> List[str]:
        """Extract path from root to node."""
        path = []
        current = node
        
        while current:
            path.append(current.id)
            if current.parent_id and current.parent_id in self.nodes:
                current = self.nodes[current.parent_id]
            else:
                break
        
        return list(reversed(path))
    
    def _format_trace(self, path: List[str]) -> str:
        """Format reasoning trace for path."""
        trace_lines = []
        
        for i, node_id in enumerate(path):
            if node_id in self.nodes:
                node = self.nodes[node_id]
                trace_lines.append(
                    f"Level {i}: {node.thought} (value: {node.value:.2f})"
                )
        
        return '\n'.join(trace_lines)
    
    def _serialize_tree(self) -> Dict[str, Any]:
        """Serialize tree structure."""
        return {
            node_id: {
                'thought': node.thought,
                'parent': node.parent_id,
                'depth': node.depth,
                'value': node.value,
                'state': node.state.value,
                'children': node.children,
                'reasoning': node.reasoning
            }
            for node_id, node in self.nodes.items()
        }
    
    def visualize_tree(self) -> str:
        """Create ASCII visualization of tree."""
        if not self.nodes:
            return "Empty tree"
        
        root_id = [n.id for n in self.nodes.values() if n.parent_id is None][0]
        return self._visualize_node(root_id, prefix="", is_last=True)
    
    def _visualize_node(self, node_id: str, prefix: str, is_last: bool) -> str:
        """Recursively visualize tree nodes."""
        if node_id not in self.nodes:
            return ""
        
        node = self.nodes[node_id]
        
        connector = "└── " if is_last else "├── "
        thought_preview = node.thought[:60] + "..." if len(node.thought) > 60 else node.thought
        state_symbol = {"active": "○", "pruned": "✗", "terminal": "●", "optimal": "★"}
        
        result = f"{prefix}{connector}{state_symbol[node.state.value]} {thought_preview} ({node.value:.2f})\n"
        
        if node.children:
            extension = "    " if is_last else "│   "
            for i, child_id in enumerate(node.children):
                is_last_child = (i == len(node.children) - 1)
                result += self._visualize_node(child_id, prefix + extension, is_last_child)
        
        return result
    
    def reset(self):
        """Reset the tree."""
        self.nodes.clear()
        self.node_counter = 0
