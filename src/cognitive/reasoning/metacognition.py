"""Metacognitive monitoring - thinking about thinking."""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import time


class CognitiveState(Enum):
    """Current cognitive state."""
    EXPLORING = "exploring"
    FOCUSED = "focused"
    UNCERTAIN = "uncertain"
    CONFIDENT = "confident"
    STUCK = "stuck"
    BREAKTHROUGH = "breakthrough"


@dataclass
class CognitiveMetrics:
    """Metrics about cognitive process."""
    processing_time: float
    complexity_score: float
    certainty_level: float
    attention_focus: float
    cognitive_load: float
    state: CognitiveState


class MetacognitiveMonitor:
    """
    Monitors and manages the AI's own thinking process.
    
    Implements metacognition - awareness and control of cognitive processes,
    allowing the AI to optimize its reasoning strategies.
    """
    
    def __init__(self):
        """Initialize metacognitive monitor."""
        self.current_state = CognitiveState.EXPLORING
        self.metrics_history: List[CognitiveMetrics] = []
        self.task_history: List[Dict[str, Any]] = []
        self.strategy_effectiveness: Dict[str, float] = {}
        
    def monitor_task(self, task: str, strategy: str) -> Dict[str, Any]:
        """
        Monitor cognitive process for a task.
        
        Args:
            task: The task being performed
            strategy: Reasoning strategy being used
            
        Returns:
            Monitoring results and recommendations
        """
        start_time = time.time()
        
        initial_state = self._assess_cognitive_state(task, strategy)
        self.current_state = initial_state
        
        complexity = self._estimate_complexity(task)
        
        recommended_strategy = self._recommend_strategy(task, complexity)
        
        monitoring_data = {
            'task': task,
            'initial_state': initial_state.value,
            'complexity': complexity,
            'current_strategy': strategy,
            'recommended_strategy': recommended_strategy,
            'should_switch': strategy != recommended_strategy,
            'timestamp': time.time()
        }
        
        self.task_history.append(monitoring_data)
        
        return monitoring_data
    
    def update_progress(self, progress: float, intermediate_result: Any) -> Dict[str, Any]:
        """
        Update monitoring based on progress.
        
        Args:
            progress: Progress percentage (0.0 to 1.0)
            intermediate_result: Current intermediate result
            
        Returns:
            Updated monitoring data with recommendations
        """
        certainty = self._assess_certainty(intermediate_result)
        attention = self._assess_attention_focus(progress)
        cognitive_load = self._estimate_cognitive_load(progress, certainty)
        
        new_state = self._update_cognitive_state(progress, certainty, cognitive_load)
        self.current_state = new_state
        
        metrics = CognitiveMetrics(
            processing_time=time.time(),
            complexity_score=0.5,
            certainty_level=certainty,
            attention_focus=attention,
            cognitive_load=cognitive_load,
            state=new_state
        )
        
        self.metrics_history.append(metrics)
        
        recommendations = self._generate_recommendations(metrics, progress)
        
        return {
            'state': new_state.value,
            'certainty': certainty,
            'attention': attention,
            'cognitive_load': cognitive_load,
            'recommendations': recommendations,
            'should_continue': self._should_continue(metrics, progress),
            'progress': progress
        }
    
    def _assess_cognitive_state(self, task: str, strategy: str) -> CognitiveState:
        """Assess initial cognitive state for task."""
        task_lower = task.lower()
        
        if any(word in task_lower for word in ['explore', 'discover', 'brainstorm']):
            return CognitiveState.EXPLORING
        elif any(word in task_lower for word in ['solve', 'calculate', 'determine']):
            return CognitiveState.FOCUSED
        else:
            return CognitiveState.EXPLORING
    
    def _estimate_complexity(self, task: str) -> float:
        """Estimate task complexity."""
        complexity = 0.5
        
        task_lower = task.lower()
        
        complex_indicators = ['multiple', 'complex', 'advanced', 'intricate', 'sophisticated']
        complexity += sum(0.1 for word in complex_indicators if word in task_lower)
        
        simple_indicators = ['simple', 'basic', 'easy', 'straightforward']
        complexity -= sum(0.1 for word in simple_indicators if word in task_lower)
        
        word_count = len(task.split())
        if word_count > 50:
            complexity += 0.2
        elif word_count < 10:
            complexity -= 0.1
        
        return max(0.0, min(1.0, complexity))
    
    def _recommend_strategy(self, task: str, complexity: float) -> str:
        """Recommend reasoning strategy based on task."""
        task_lower = task.lower()
        
        if complexity > 0.7:
            if 'explore' in task_lower or 'options' in task_lower:
                return 'tree_of_thought'
            else:
                return 'chain_of_thought'
        elif complexity > 0.4:
            return 'chain_of_thought'
        else:
            return 'direct'
        
        if 'analyze' in task_lower or 'evaluate' in task_lower:
            return 'self_reflection'
        
        return 'chain_of_thought'
    
    def _assess_certainty(self, result: Any) -> float:
        """Assess certainty in intermediate result."""
        if result is None:
            return 0.0
        
        certainty = 0.7
        
        if isinstance(result, str):
            uncertain_words = ['maybe', 'possibly', 'might', 'unclear', 'unsure']
            for word in uncertain_words:
                if word in result.lower():
                    certainty -= 0.1
            
            confident_words = ['definitely', 'certainly', 'clearly', 'obviously']
            for word in confident_words:
                if word in result.lower():
                    certainty += 0.05
        
        return max(0.0, min(1.0, certainty))
    
    def _assess_attention_focus(self, progress: float) -> float:
        """Assess attention focus level."""
        if progress < 0.2:
            return 0.9
        elif progress < 0.5:
            return 0.95
        elif progress < 0.8:
            return 0.85
        else:
            return 0.8
    
    def _estimate_cognitive_load(self, progress: float, certainty: float) -> float:
        """Estimate current cognitive load."""
        base_load = 0.5
        
        if progress < 0.3:
            base_load += 0.2
        elif progress > 0.7:
            base_load -= 0.1
        
        if certainty < 0.5:
            base_load += 0.2
        
        return max(0.0, min(1.0, base_load))
    
    def _update_cognitive_state(self, progress: float, certainty: float,
                               cognitive_load: float) -> CognitiveState:
        """Update cognitive state based on metrics."""
        if progress < 0.2 and cognitive_load > 0.7:
            return CognitiveState.STUCK
        
        if certainty < 0.4:
            return CognitiveState.UNCERTAIN
        
        if certainty > 0.8 and progress > 0.5:
            return CognitiveState.CONFIDENT
        
        if progress > 0.3 and certainty > 0.6:
            return CognitiveState.FOCUSED
        
        if progress < 0.5:
            return CognitiveState.EXPLORING
        
        return CognitiveState.FOCUSED
    
    def _generate_recommendations(self, metrics: CognitiveMetrics,
                                 progress: float) -> List[str]:
        """Generate recommendations based on cognitive state."""
        recommendations = []
        
        if metrics.state == CognitiveState.STUCK:
            recommendations.append("Consider switching reasoning strategy")
            recommendations.append("Break problem into smaller sub-problems")
            recommendations.append("Seek alternative perspectives")
        
        if metrics.certainty_level < 0.4:
            recommendations.append("Gather more information before proceeding")
            recommendations.append("Consider using self-reflection to validate reasoning")
        
        if metrics.cognitive_load > 0.8:
            recommendations.append("Simplify the current approach")
            recommendations.append("Focus on one aspect at a time")
        
        if progress > 0.7 and metrics.certainty_level > 0.7:
            recommendations.append("You're on the right track - continue current approach")
        
        if not recommendations:
            recommendations.append("Continue with current strategy")
        
        return recommendations
    
    def _should_continue(self, metrics: CognitiveMetrics, progress: float) -> bool:
        """Determine if should continue with current approach."""
        if metrics.state == CognitiveState.STUCK and progress < 0.3:
            return False
        
        if metrics.cognitive_load > 0.9 and metrics.certainty_level < 0.3:
            return False
        
        return True
    
    def analyze_performance(self) -> Dict[str, Any]:
        """Analyze overall cognitive performance."""
        if not self.metrics_history:
            return {
                'avg_certainty': 0.0,
                'avg_cognitive_load': 0.0,
                'state_distribution': {},
                'trend': 'insufficient_data'
            }
        
        avg_certainty = sum(m.certainty_level for m in self.metrics_history) / len(self.metrics_history)
        avg_load = sum(m.cognitive_load for m in self.metrics_history) / len(self.metrics_history)
        
        state_counts = {}
        for metrics in self.metrics_history:
            state = metrics.state.value
            state_counts[state] = state_counts.get(state, 0) + 1
        
        recent_certainty = [m.certainty_level for m in self.metrics_history[-5:]]
        if len(recent_certainty) >= 2:
            if recent_certainty[-1] > recent_certainty[0]:
                trend = 'improving'
            elif recent_certainty[-1] < recent_certainty[0]:
                trend = 'declining'
            else:
                trend = 'stable'
        else:
            trend = 'insufficient_data'
        
        return {
            'avg_certainty': avg_certainty,
            'avg_cognitive_load': avg_load,
            'state_distribution': state_counts,
            'trend': trend,
            'total_tasks': len(self.task_history),
            'total_metrics': len(self.metrics_history)
        }
    
    def get_learning_insights(self) -> List[str]:
        """Get insights for learning and improvement."""
        insights = []
        
        performance = self.analyze_performance()
        
        if performance['avg_certainty'] < 0.5:
            insights.append("Average certainty is low - consider gathering more knowledge")
        
        if performance['avg_cognitive_load'] > 0.7:
            insights.append("High cognitive load detected - consider simplifying tasks")
        
        if performance.get('trend') == 'declining':
            insights.append("Performance trend is declining - may need rest or strategy change")
        elif performance.get('trend') == 'improving':
            insights.append("Performance is improving - current strategies are effective")
        
        state_dist = performance.get('state_distribution', {})
        if state_dist.get('stuck', 0) > len(self.metrics_history) * 0.3:
            insights.append("Frequently getting stuck - need better problem decomposition")
        
        if not insights:
            insights.append("Performance is within normal parameters")
        
        return insights
    
    def reset(self):
        """Reset monitoring state."""
        self.current_state = CognitiveState.EXPLORING
        self.metrics_history.clear()
        self.task_history.clear()
