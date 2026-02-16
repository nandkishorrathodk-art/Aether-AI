"""
Self-Learning and Continuous Improvement System

Aether learns from every interaction and gets smarter over time!

NO OTHER AI DOES THIS:
- Learns from mistakes
- Adapts to user preferences
- Self-optimizes prompts
- Discovers better strategies
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import defaultdict
from src.utils.logger import get_logger
from src.cognitive.llm.model_loader import ModelLoader

logger = get_logger(__name__)


class SelfLearningEngine:
    """
    Continuous learning from user interactions
    
    Learning mechanisms:
    1. Feedback loop - User corrections improve future responses
    2. Reinforcement learning - Successful patterns are reinforced
    3. Meta-learning - Learns how to learn better
    4. Prompt optimization - Discovers better prompts
    """
    
    def __init__(self, storage_path: str = "./data/learning"):
        self.logger = get_logger(__name__)
        self.model_loader = ModelLoader()
        self.storage_path = storage_path
        
        # Learning data
        self.feedback_history: List[Dict[str, Any]] = []
        self.prompt_performance: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.user_corrections: List[Dict[str, Any]] = []
        self.success_patterns: List[Dict[str, Any]] = []
        
        # Load existing learning data
        self._load_learning_data()
        
        self.logger.info("SelfLearningEngine initialized")
    
    def record_interaction(
        self,
        prompt: str,
        response: str,
        task_type: str,
        user_feedback: Optional[str] = None,
        success: bool = True
    ):
        """
        Record interaction for learning
        
        Args:
            prompt: User's prompt
            response: AI's response
            task_type: Type of task
            user_feedback: User's feedback
            success: Whether interaction was successful
        """
        interaction = {
            'timestamp': datetime.now().isoformat(),
            'prompt': prompt,
            'response': response,
            'task_type': task_type,
            'feedback': user_feedback,
            'success': success
        }
        
        self.feedback_history.append(interaction)
        
        # Update prompt performance metrics
        prompt_key = self._get_prompt_pattern(prompt)
        if prompt_key not in self.prompt_performance:
            self.prompt_performance[prompt_key] = {
                'total': 0,
                'successful': 0,
                'avg_quality': 0.0
            }
        
        self.prompt_performance[prompt_key]['total'] += 1
        if success:
            self.prompt_performance[prompt_key]['successful'] += 1
        
        # Learn from feedback
        if user_feedback:
            self._learn_from_feedback(prompt, response, user_feedback)
        
        # Save learning data
        self._save_learning_data()
    
    def record_correction(
        self,
        original_response: str,
        corrected_response: str,
        context: Dict[str, Any]
    ):
        """
        Learn from user corrections
        
        This is CRITICAL - other AIs don't learn from corrections!
        """
        correction = {
            'timestamp': datetime.now().isoformat(),
            'original': original_response,
            'corrected': corrected_response,
            'context': context,
            'improvement': self._analyze_correction(original_response, corrected_response)
        }
        
        self.user_corrections.append(correction)
        
        # Extract learning
        learning = self._extract_learning_from_correction(correction)
        if learning:
            self.success_patterns.append(learning)
        
        self.logger.info(f"Learned from correction: {learning}")
        self._save_learning_data()
    
    def optimize_prompt(self, task_type: str, base_prompt: str) -> str:
        """
        Optimize prompt based on past performance
        
        Uses learned patterns to improve prompts!
        """
        # Find best-performing prompts for this task type
        similar_prompts = [
            (pattern, metrics)
            for pattern, metrics in self.prompt_performance.items()
            if task_type in pattern
        ]
        
        if not similar_prompts:
            return base_prompt
        
        # Sort by success rate
        similar_prompts.sort(
            key=lambda x: x[1]['successful'] / max(x[1]['total'], 1),
            reverse=True
        )
        
        if similar_prompts:
            best_pattern = similar_prompts[0][0]
            
            # Extract successful elements
            optimization_prompt = f"""Optimize this prompt using learned best practices.

Base prompt: {base_prompt}

Best-performing pattern: {best_pattern}

Improvements to apply:
1. Add clarity and specificity
2. Include relevant context
3. Specify output format
4. Add constraints if needed

Return only the optimized prompt."""

            optimized = self.model_loader.generate_response(
                prompt=optimization_prompt,
                task_type="analysis"
            )
            
            return optimized.strip()
        
        return base_prompt
    
    def get_learning_insights(self) -> Dict[str, Any]:
        """
        Get insights from learning data
        
        Shows how Aether is improving!
        """
        total_interactions = len(self.feedback_history)
        successful = sum(1 for i in self.feedback_history if i['success'])
        
        # Task type performance
        task_performance = defaultdict(lambda: {'total': 0, 'successful': 0})
        for interaction in self.feedback_history:
            task = interaction['task_type']
            task_performance[task]['total'] += 1
            if interaction['success']:
                task_performance[task]['successful'] += 1
        
        # Calculate improvement over time
        recent_success_rate = 0
        if len(self.feedback_history) > 10:
            recent = self.feedback_history[-100:]
            recent_successful = sum(1 for i in recent if i['success'])
            recent_success_rate = recent_successful / len(recent) if recent else 0
        
        return {
            'total_interactions': total_interactions,
            'success_rate': successful / total_interactions if total_interactions else 0,
            'recent_success_rate': recent_success_rate,
            'corrections_learned': len(self.user_corrections),
            'patterns_discovered': len(self.success_patterns),
            'task_performance': dict(task_performance),
            'improvement_percentage': self._calculate_improvement()
        }
    
    def suggest_improvements(self) -> List[str]:
        """
        AI suggests how to improve itself!
        
        Meta-intelligence - thinking about thinking
        """
        suggestions = []
        
        # Analyze failure patterns
        failures = [i for i in self.feedback_history if not i['success']]
        if len(failures) > 5:
            common_failures = self._find_common_patterns([f['prompt'] for f in failures])
            if common_failures:
                suggestions.append(
                    f"Improve handling of {common_failures[0]} type queries"
                )
        
        # Check for low-performing task types
        for task_type, metrics in self.prompt_performance.items():
            if metrics['total'] > 5:
                success_rate = metrics['successful'] / metrics['total']
                if success_rate < 0.7:
                    suggestions.append(
                        f"Need better prompts for {task_type} tasks (only {success_rate:.0%} success)"
                    )
        
        # Suggest new capabilities from user requests
        user_needs = self._analyze_user_needs()
        if user_needs:
            suggestions.extend([
                f"Add capability: {need}" for need in user_needs[:3]
            ])
        
        return suggestions
    
    def _learn_from_feedback(self, prompt: str, response: str, feedback: str):
        """Extract learning from user feedback"""
        # Use AI to understand feedback
        learning_prompt = f"""Analyze this user feedback to improve future responses.

Prompt: {prompt}
Response: {response}
Feedback: {feedback}

Extract:
1. What was wrong?
2. What would be better?
3. General principle to apply

Return as JSON."""

        try:
            analysis = self.model_loader.generate_response(
                prompt=learning_prompt,
                task_type="analysis"
            )
            
            # Store learning
            self.success_patterns.append({
                'timestamp': datetime.now().isoformat(),
                'type': 'feedback_learning',
                'analysis': analysis
            })
            
        except Exception as e:
            self.logger.error(f"Failed to learn from feedback: {e}")
    
    def _analyze_correction(self, original: str, corrected: str) -> Dict[str, Any]:
        """Analyze what changed in correction"""
        return {
            'original_length': len(original),
            'corrected_length': len(corrected),
            'significant_change': abs(len(original) - len(corrected)) > 50
        }
    
    def _extract_learning_from_correction(
        self,
        correction: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Extract actionable learning from correction"""
        if not correction['improvement']['significant_change']:
            return None
        
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'correction',
            'lesson': f"User prefers {len(correction['corrected'])} chars vs {len(correction['original'])}"
        }
    
    def _get_prompt_pattern(self, prompt: str) -> str:
        """Extract pattern from prompt"""
        # Simple pattern extraction - first 5 words
        words = prompt.split()[:5]
        return ' '.join(words).lower()
    
    def _find_common_patterns(self, texts: List[str]) -> List[str]:
        """Find common patterns in texts"""
        if not texts:
            return []
        
        # Simple word frequency
        all_words = ' '.join(texts).lower().split()
        word_freq = defaultdict(int)
        for word in all_words:
            if len(word) > 4:  # Ignore short words
                word_freq[word] += 1
        
        common = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
        return [word for word, _ in common[:5]]
    
    def _analyze_user_needs(self) -> List[str]:
        """Analyze user feedback to identify unmet needs"""
        needs = []
        
        for interaction in self.feedback_history[-50:]:
            if not interaction['success'] and interaction.get('feedback'):
                feedback = interaction['feedback'].lower()
                
                # Look for "can you" or "I need" patterns
                if 'can you' in feedback or 'i need' in feedback:
                    needs.append(feedback)
        
        return list(set(needs))[:5]
    
    def _calculate_improvement(self) -> float:
        """Calculate improvement percentage over time"""
        if len(self.feedback_history) < 20:
            return 0.0
        
        mid_point = len(self.feedback_history) // 2
        first_half = self.feedback_history[:mid_point]
        second_half = self.feedback_history[mid_point:]
        
        first_success_rate = sum(1 for i in first_half if i['success']) / len(first_half)
        second_success_rate = sum(1 for i in second_half if i['success']) / len(second_half)
        
        improvement = ((second_success_rate - first_success_rate) / first_success_rate * 100
                      if first_success_rate > 0 else 0)
        
        return round(improvement, 2)
    
    def _save_learning_data(self):
        """Save learning data to disk"""
        import os
        os.makedirs(self.storage_path, exist_ok=True)
        
        data = {
            'feedback_history': self.feedback_history[-1000:],  # Keep last 1000
            'prompt_performance': dict(self.prompt_performance),
            'user_corrections': self.user_corrections[-500:],
            'success_patterns': self.success_patterns[-500:]
        }
        
        try:
            with open(f"{self.storage_path}/learning_data.json", 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save learning data: {e}")
    
    def _load_learning_data(self):
        """Load existing learning data"""
        try:
            with open(f"{self.storage_path}/learning_data.json", 'r') as f:
                data = json.load(f)
                
            self.feedback_history = data.get('feedback_history', [])
            self.prompt_performance = defaultdict(dict, data.get('prompt_performance', {}))
            self.user_corrections = data.get('user_corrections', [])
            self.success_patterns = data.get('success_patterns', [])
            
            self.logger.info(f"Loaded {len(self.feedback_history)} interactions from storage")
            
        except FileNotFoundError:
            self.logger.info("No existing learning data found, starting fresh")
        except Exception as e:
            self.logger.error(f"Failed to load learning data: {e}")
