"""Problem decomposition for breaking complex tasks into manageable parts."""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class SubproblemType(Enum):
    """Type of subproblem."""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CONDITIONAL = "conditional"
    ITERATIVE = "iterative"


@dataclass
class Subproblem:
    """A decomposed subproblem."""
    id: str
    description: str
    type: SubproblemType
    dependencies: List[str]
    priority: int
    complexity: float
    estimated_effort: float


class ProblemDecomposer:
    """
    Decomposes complex problems into manageable subproblems.
    
    Uses divide-and-conquer strategies to break down tasks that would
    be too complex to solve directly.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize problem decomposer.
        
        Args:
            llm_provider: Language model provider for decomposition
        """
        self.llm_provider = llm_provider
        self.decomposition_history: List[Dict[str, Any]] = []
        
    def decompose(self, problem: str, max_depth: int = 3,
                 context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Decompose a problem into subproblems.
        
        Args:
            problem: The problem to decompose
            max_depth: Maximum decomposition depth
            context: Additional context
            
        Returns:
            Dictionary with subproblems and execution plan
        """
        context = context or {}
        
        if self.llm_provider:
            subproblems = self._decompose_llm(problem, max_depth, context)
        else:
            subproblems = self._decompose_heuristic(problem, max_depth, context)
        
        execution_order = self._determine_execution_order(subproblems)
        
        critical_path = self._identify_critical_path(subproblems, execution_order)
        
        result = {
            'problem': problem,
            'subproblems': [self._subproblem_to_dict(sp) for sp in subproblems],
            'execution_order': execution_order,
            'critical_path': critical_path,
            'total_complexity': sum(sp.complexity for sp in subproblems),
            'estimated_total_effort': sum(sp.estimated_effort for sp in subproblems)
        }
        
        self.decomposition_history.append(result)
        
        return result
    
    def _decompose_llm(self, problem: str, max_depth: int,
                      context: Dict[str, Any]) -> List[Subproblem]:
        """Decompose using LLM."""
        prompt = f"""Break down this complex problem into smaller, manageable subproblems.

Problem: {problem}

Decompose into 3-7 subproblems. For each subproblem, provide:
1. Clear description
2. Type (sequential/parallel/conditional/iterative)
3. Dependencies (other subproblem numbers)
4. Priority (1-5, where 5 is highest)

Format each as:
Subproblem N: [description] | Type: [type] | Dependencies: [list] | Priority: [number]

Subproblems:"""
        
        try:
            response = self.llm_provider.generate(
                prompt,
                max_tokens=1000,
                temperature=0.7,
                task_type='analysis'
            )
            
            content = response.get('content', '')
            return self._parse_subproblems(content)
        except Exception as e:
            print(f"LLM decomposition error: {e}")
            return self._decompose_heuristic(problem, max_depth, context)
    
    def _decompose_heuristic(self, problem: str, max_depth: int,
                            context: Dict[str, Any]) -> List[Subproblem]:
        """Heuristic problem decomposition."""
        subproblems = []
        
        subproblems.append(Subproblem(
            id="sp1",
            description=f"Understand and analyze: {problem[:100]}...",
            type=SubproblemType.SEQUENTIAL,
            dependencies=[],
            priority=5,
            complexity=0.3,
            estimated_effort=1.0
        ))
        
        subproblems.append(Subproblem(
            id="sp2",
            description="Gather necessary information and resources",
            type=SubproblemType.SEQUENTIAL,
            dependencies=["sp1"],
            priority=4,
            complexity=0.4,
            estimated_effort=2.0
        ))
        
        subproblems.append(Subproblem(
            id="sp3",
            description="Design solution approach",
            type=SubproblemType.SEQUENTIAL,
            dependencies=["sp1", "sp2"],
            priority=5,
            complexity=0.6,
            estimated_effort=3.0
        ))
        
        subproblems.append(Subproblem(
            id="sp4",
            description="Implement solution",
            type=SubproblemType.PARALLEL,
            dependencies=["sp3"],
            priority=4,
            complexity=0.8,
            estimated_effort=5.0
        ))
        
        subproblems.append(Subproblem(
            id="sp5",
            description="Test and validate solution",
            type=SubproblemType.SEQUENTIAL,
            dependencies=["sp4"],
            priority=4,
            complexity=0.4,
            estimated_effort=2.0
        ))
        
        subproblems.append(Subproblem(
            id="sp6",
            description="Refine and optimize",
            type=SubproblemType.ITERATIVE,
            dependencies=["sp5"],
            priority=3,
            complexity=0.5,
            estimated_effort=2.0
        ))
        
        return subproblems
    
    def _parse_subproblems(self, content: str) -> List[Subproblem]:
        """Parse subproblems from LLM output."""
        subproblems = []
        lines = content.strip().split('\n')
        
        counter = 1
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if 'subproblem' in line.lower():
                parts = line.split('|')
                if len(parts) >= 2:
                    desc_part = parts[0].split(':', 1)
                    description = desc_part[1].strip() if len(desc_part) > 1 else line
                    
                    sp_type = SubproblemType.SEQUENTIAL
                    if 'parallel' in line.lower():
                        sp_type = SubproblemType.PARALLEL
                    elif 'conditional' in line.lower():
                        sp_type = SubproblemType.CONDITIONAL
                    elif 'iterative' in line.lower():
                        sp_type = SubproblemType.ITERATIVE
                    
                    priority = 3
                    for part in parts:
                        if 'priority' in part.lower():
                            try:
                                priority = int(''.join(c for c in part if c.isdigit()))
                            except ValueError:
                                priority = 3
                    
                    dependencies = []
                    for part in parts:
                        if 'depend' in part.lower():
                            deps_text = part.split(':')[1] if ':' in part else part
                            dependencies = [
                                f"sp{d.strip()}" 
                                for d in deps_text.replace('[', '').replace(']', '').split(',')
                                if d.strip().isdigit()
                            ]
                    
                    subproblems.append(Subproblem(
                        id=f"sp{counter}",
                        description=description,
                        type=sp_type,
                        dependencies=dependencies,
                        priority=priority,
                        complexity=0.5,
                        estimated_effort=float(priority)
                    ))
                    counter += 1
        
        if not subproblems:
            return self._decompose_heuristic("", 3, {})
        
        return subproblems
    
    def _determine_execution_order(self, subproblems: List[Subproblem]) -> List[str]:
        """Determine optimal execution order using topological sort."""
        graph = {sp.id: sp.dependencies for sp in subproblems}
        
        in_degree = {sp.id: 0 for sp in subproblems}
        for sp in subproblems:
            for dep in sp.dependencies:
                if dep in in_degree:
                    in_degree[sp.id] += 1
        
        queue = [sp_id for sp_id, degree in in_degree.items() if degree == 0]
        order = []
        
        while queue:
            queue.sort(key=lambda sp_id: next(
                (sp.priority for sp in subproblems if sp.id == sp_id), 0
            ), reverse=True)
            
            current = queue.pop(0)
            order.append(current)
            
            for sp in subproblems:
                if current in sp.dependencies:
                    in_degree[sp.id] -= 1
                    if in_degree[sp.id] == 0 and sp.id not in queue:
                        queue.append(sp.id)
        
        return order
    
    def _identify_critical_path(self, subproblems: List[Subproblem],
                               execution_order: List[str]) -> List[str]:
        """Identify critical path through subproblems."""
        sp_dict = {sp.id: sp for sp in subproblems}
        
        earliest_start = {sp.id: 0.0 for sp in subproblems}
        for sp_id in execution_order:
            sp = sp_dict[sp_id]
            if sp.dependencies:
                earliest_start[sp_id] = max(
                    earliest_start[dep] + sp_dict[dep].estimated_effort
                    for dep in sp.dependencies
                    if dep in sp_dict
                )
        
        critical_path = []
        current = execution_order[-1] if execution_order else None
        
        while current:
            critical_path.insert(0, current)
            sp = sp_dict[current]
            
            if not sp.dependencies:
                break
            
            critical_deps = [
                dep for dep in sp.dependencies
                if dep in sp_dict and earliest_start[dep] + sp_dict[dep].estimated_effort == earliest_start[current]
            ]
            
            current = critical_deps[0] if critical_deps else None
        
        return critical_path
    
    def _subproblem_to_dict(self, sp: Subproblem) -> Dict[str, Any]:
        """Convert subproblem to dictionary."""
        return {
            'id': sp.id,
            'description': sp.description,
            'type': sp.type.value,
            'dependencies': sp.dependencies,
            'priority': sp.priority,
            'complexity': sp.complexity,
            'estimated_effort': sp.estimated_effort
        }
    
    def visualize_decomposition(self, decomposition: Dict[str, Any]) -> str:
        """Create text visualization of problem decomposition."""
        viz = f"Problem: {decomposition['problem']}\n\n"
        viz += f"Total Complexity: {decomposition['total_complexity']:.1f}\n"
        viz += f"Estimated Effort: {decomposition['estimated_total_effort']:.1f} units\n\n"
        
        viz += "Subproblems:\n"
        for sp in decomposition['subproblems']:
            viz += f"  [{sp['id']}] {sp['description']}\n"
            viz += f"       Type: {sp['type']}, Priority: {sp['priority']}\n"
            if sp['dependencies']:
                viz += f"       Depends on: {', '.join(sp['dependencies'])}\n"
            viz += "\n"
        
        viz += f"Execution Order: {' → '.join(decomposition['execution_order'])}\n"
        viz += f"Critical Path: {' → '.join(decomposition['critical_path'])}\n"
        
        return viz
