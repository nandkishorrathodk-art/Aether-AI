"""Self-reflection engine for error correction and improvement."""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
import json


@dataclass
class ReflectionResult:
    """Result of self-reflection process."""
    original_response: str
    issues_found: List[str]
    improved_response: str
    confidence_before: float
    confidence_after: float
    timestamp: str
    reasoning: str


class SelfReflectionEngine:
    """
    Implements self-reflection capabilities for error detection and correction.
    
    The engine analyzes its own outputs, identifies potential errors or
    improvements, and generates refined responses.
    """
    
    def __init__(self, llm_provider=None):
        """
        Initialize self-reflection engine.
        
        Args:
            llm_provider: Language model provider for reflection
        """
        self.llm_provider = llm_provider
        self.reflection_history: List[ReflectionResult] = []
        
        self.reflection_criteria = [
            "logical_consistency",
            "factual_accuracy",
            "completeness",
            "clarity",
            "relevance",
            "safety",
            "bias"
        ]
    
    def reflect(self, response: str, question: str, 
                context: Optional[Dict[str, Any]] = None) -> ReflectionResult:
        """
        Reflect on a response and improve it if needed.
        
        Args:
            response: The response to reflect on
            question: Original question/prompt
            context: Additional context
            
        Returns:
            ReflectionResult with analysis and improved response
        """
        context = context or {}
        
        issues = self._identify_issues(response, question, context)
        
        if issues:
            improved = self._improve_response(response, question, issues, context)
            confidence_after = self._assess_confidence(improved, question, context)
        else:
            improved = response
            confidence_after = self._assess_confidence(response, question, context)
        
        confidence_before = self._assess_confidence(response, question, context)
        
        reasoning = self._generate_reasoning(issues, response, improved)
        
        result = ReflectionResult(
            original_response=response,
            issues_found=issues,
            improved_response=improved,
            confidence_before=confidence_before,
            confidence_after=confidence_after,
            timestamp=datetime.now().isoformat(),
            reasoning=reasoning
        )
        
        self.reflection_history.append(result)
        
        return result
    
    def _identify_issues(self, response: str, question: str,
                        context: Dict[str, Any]) -> List[str]:
        """Identify issues in the response."""
        issues = []
        
        if self.llm_provider:
            issues = self._identify_issues_llm(response, question, context)
        else:
            issues = self._identify_issues_heuristic(response, question, context)
        
        return issues
    
    def _identify_issues_llm(self, response: str, question: str,
                            context: Dict[str, Any]) -> List[str]:
        """Use LLM to identify issues."""
        prompt = f"""Analyze this response for potential issues or improvements.

Question: {question}
Response: {response}

Check for:
1. Logical consistency - Does it contradict itself?
2. Factual accuracy - Are there obvious errors?
3. Completeness - Does it fully answer the question?
4. Clarity - Is it clear and well-organized?
5. Relevance - Does it stay on topic?
6. Safety - Are there any harmful elements?
7. Bias - Is it balanced and fair?

List any issues found (one per line). If no issues, respond with "No issues found".

Issues:"""
        
        try:
            result = self.llm_provider.generate(
                prompt,
                max_tokens=500,
                temperature=0.3,
                task_type='analysis'
            )
            
            content = result.get('content', '').strip()
            
            if "no issues" in content.lower():
                return []
            
            issues = [
                line.strip()
                for line in content.split('\n')
                if line.strip() and not line.strip().startswith('#')
            ]
            
            return issues
        except Exception as e:
            print(f"LLM issue identification error: {e}")
            return self._identify_issues_heuristic(response, question, context)
    
    def _identify_issues_heuristic(self, response: str, question: str,
                                   context: Dict[str, Any]) -> List[str]:
        """Heuristic issue identification."""
        issues = []
        
        if len(response) < 20:
            issues.append("Response is too short and may be incomplete")
        
        if len(response) > 2000:
            issues.append("Response is very long and could be more concise")
        
        question_words = set(question.lower().split())
        response_words = set(response.lower().split())
        overlap = len(question_words & response_words)
        
        if overlap < 2 and len(question_words) > 3:
            issues.append("Response may not address the question directly")
        
        uncertain_phrases = ["i think", "maybe", "not sure", "possibly", "might be"]
        if any(phrase in response.lower() for phrase in uncertain_phrases):
            issues.append("Response contains uncertain language")
        
        negative_phrases = ["cannot", "unable", "don't know", "not possible"]
        if any(phrase in response.lower() for phrase in negative_phrases):
            issues.append("Response may be overly negative or dismissive")
        
        return issues
    
    def _improve_response(self, response: str, question: str,
                         issues: List[str], context: Dict[str, Any]) -> str:
        """Generate improved response addressing identified issues."""
        if self.llm_provider:
            return self._improve_response_llm(response, question, issues, context)
        else:
            return self._improve_response_heuristic(response, question, issues)
    
    def _improve_response_llm(self, response: str, question: str,
                             issues: List[str], context: Dict[str, Any]) -> str:
        """Use LLM to improve response."""
        issues_text = '\n'.join(f"- {issue}" for issue in issues)
        
        prompt = f"""Improve this response by addressing the identified issues.

Question: {question}
Original Response: {response}

Issues to address:
{issues_text}

Provide an improved response that fixes these issues while maintaining accuracy.

Improved Response:"""
        
        try:
            result = self.llm_provider.generate(
                prompt,
                max_tokens=1000,
                temperature=0.7,
                task_type='conversation'
            )
            
            improved = result.get('content', '').strip()
            return improved if improved else response
        except Exception as e:
            print(f"LLM improvement error: {e}")
            return self._improve_response_heuristic(response, question, issues)
    
    def _improve_response_heuristic(self, response: str, question: str,
                                   issues: List[str]) -> str:
        """Heuristic response improvement."""
        improved = response
        
        if any("too short" in issue.lower() for issue in issues):
            improved = f"{improved}\n\nTo elaborate further: This response addresses the key aspects of your question regarding '{question[:50]}...'"
        
        if any("uncertain" in issue.lower() for issue in issues):
            improved = improved.replace("I think", "Based on analysis,")
            improved = improved.replace("maybe", "likely")
            improved = improved.replace("not sure", "it appears that")
        
        if any("negative" in issue.lower() for issue in issues):
            improved = f"{improved}\n\nAlternatively, here are some possible approaches to consider..."
        
        return improved
    
    def _assess_confidence(self, response: str, question: str,
                          context: Dict[str, Any]) -> float:
        """Assess confidence in response."""
        if self.llm_provider:
            return self._assess_confidence_llm(response, question, context)
        else:
            return self._assess_confidence_heuristic(response, question, context)
    
    def _assess_confidence_llm(self, response: str, question: str,
                              context: Dict[str, Any]) -> float:
        """Use LLM to assess confidence."""
        prompt = f"""Rate your confidence in this response.

Question: {question}
Response: {response}

How confident are you this is accurate and complete? (0.0 to 1.0)
Just provide the number.

Confidence:"""
        
        try:
            result = self.llm_provider.generate(
                prompt,
                max_tokens=10,
                temperature=0.3,
                task_type='analysis'
            )
            
            content = result.get('content', '0.5').strip()
            
            try:
                confidence = float(content.split()[0])
                return max(0.0, min(1.0, confidence))
            except ValueError:
                return 0.7
        except Exception:
            return 0.7
    
    def _assess_confidence_heuristic(self, response: str, question: str,
                                    context: Dict[str, Any]) -> float:
        """Heuristic confidence assessment."""
        confidence = 0.7
        
        uncertain_phrases = ["i think", "maybe", "not sure", "possibly"]
        for phrase in uncertain_phrases:
            if phrase in response.lower():
                confidence -= 0.05
        
        confident_phrases = ["definitely", "certainly", "clearly", "precisely"]
        for phrase in confident_phrases:
            if phrase in response.lower():
                confidence += 0.05
        
        if 50 <= len(response) <= 500:
            confidence += 0.1
        elif len(response) < 20 or len(response) > 1000:
            confidence -= 0.1
        
        return max(0.0, min(1.0, confidence))
    
    def _generate_reasoning(self, issues: List[str], original: str,
                           improved: str) -> str:
        """Generate reasoning for reflection."""
        if not issues:
            return "No issues found. Original response is satisfactory."
        
        reasoning = f"Found {len(issues)} issue(s):\n"
        for i, issue in enumerate(issues, 1):
            reasoning += f"{i}. {issue}\n"
        
        if original != improved:
            reasoning += f"\nResponse improved to address these concerns."
        else:
            reasoning += f"\nNo improvements could be made automatically."
        
        return reasoning
    
    def get_reflection_stats(self) -> Dict[str, Any]:
        """Get statistics on reflection history."""
        if not self.reflection_history:
            return {
                'total_reflections': 0,
                'avg_issues_found': 0,
                'avg_confidence_improvement': 0,
                'improvement_rate': 0
            }
        
        total = len(self.reflection_history)
        total_issues = sum(len(r.issues_found) for r in self.reflection_history)
        confidence_improvements = sum(
            r.confidence_after - r.confidence_before
            for r in self.reflection_history
        )
        improvements_made = sum(
            1 for r in self.reflection_history
            if r.improved_response != r.original_response
        )
        
        return {
            'total_reflections': total,
            'avg_issues_found': total_issues / total,
            'avg_confidence_improvement': confidence_improvements / total,
            'improvement_rate': improvements_made / total
        }
    
    def export_reflections(self, filepath: str):
        """Export reflection history to file."""
        data = [
            {
                'original_response': r.original_response,
                'issues_found': r.issues_found,
                'improved_response': r.improved_response,
                'confidence_before': r.confidence_before,
                'confidence_after': r.confidence_after,
                'timestamp': r.timestamp,
                'reasoning': r.reasoning
            }
            for r in self.reflection_history
        ]
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    
    def clear_history(self):
        """Clear reflection history."""
        self.reflection_history.clear()
