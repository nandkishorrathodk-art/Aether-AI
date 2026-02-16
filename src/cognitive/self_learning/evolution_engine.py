"""
Self-Learning & Auto-Evolution Engine
Learns from every interaction and improves automatically
"""
import json
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import pickle
from collections import defaultdict

class InteractionRecord:
    def __init__(self, input_data: str, output_data: str, success: bool, 
                 timestamp: datetime, metadata: Dict[str, Any] = None):
        self.input_data = input_data
        self.output_data = output_data
        self.success = success
        self.timestamp = timestamp
        self.metadata = metadata or {}
        self.score = 1.0 if success else 0.0

class PatternLearner:
    def __init__(self):
        self.patterns = defaultdict(list)
        self.success_patterns = []
        self.failure_patterns = []
    
    def add_pattern(self, input_pattern: str, output_pattern: str, success: bool):
        pattern_key = self._hash_pattern(input_pattern)
        self.patterns[pattern_key].append({
            'input': input_pattern,
            'output': output_pattern,
            'success': success,
            'count': 1
        })
        
        if success:
            self.success_patterns.append((input_pattern, output_pattern))
        else:
            self.failure_patterns.append((input_pattern, output_pattern))
    
    def _hash_pattern(self, pattern: str) -> str:
        return pattern[:50]
    
    def find_similar_patterns(self, input_data: str, top_k: int = 5) -> List[Dict]:
        pattern_key = self._hash_pattern(input_data)
        similar = self.patterns.get(pattern_key, [])
        return sorted(similar, key=lambda x: x.get('count', 0), reverse=True)[:top_k]
    
    def get_best_response(self, input_data: str) -> Optional[str]:
        similar = self.find_similar_patterns(input_data, top_k=1)
        if similar and similar[0]['success']:
            return similar[0]['output']
        return None

class GeneticOptimizer:
    def __init__(self, population_size: int = 10, mutation_rate: float = 0.1):
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.population = []
        self.generation = 0
    
    def initialize_population(self, base_patterns: List[Dict]):
        self.population = base_patterns[:self.population_size]
        for _ in range(self.population_size - len(self.population)):
            self.population.append(self._create_random_pattern())
    
    def _create_random_pattern(self) -> Dict:
        return {
            'weights': np.random.rand(10),
            'bias': np.random.rand(),
            'fitness': 0.0
        }
    
    def evolve(self, fitness_scores: List[float]):
        for i, score in enumerate(fitness_scores):
            if i < len(self.population):
                self.population[i]['fitness'] = score
        
        self.population.sort(key=lambda x: x['fitness'], reverse=True)
        
        survivors = self.population[:self.population_size // 2]
        
        new_population = survivors.copy()
        
        while len(new_population) < self.population_size:
            parent1 = np.random.choice(survivors)
            parent2 = np.random.choice(survivors)
            child = self._crossover(parent1, parent2)
            child = self._mutate(child)
            new_population.append(child)
        
        self.population = new_population
        self.generation += 1
    
    def _crossover(self, parent1: Dict, parent2: Dict) -> Dict:
        child = {
            'weights': (parent1['weights'] + parent2['weights']) / 2,
            'bias': (parent1['bias'] + parent2['bias']) / 2,
            'fitness': 0.0
        }
        return child
    
    def _mutate(self, individual: Dict) -> Dict:
        if np.random.rand() < self.mutation_rate:
            individual['weights'] += np.random.randn(10) * 0.1
            individual['bias'] += np.random.randn() * 0.1
        return individual
    
    def get_best_individual(self) -> Dict:
        return max(self.population, key=lambda x: x['fitness'])

class CapabilityExpander:
    def __init__(self):
        self.capabilities = set()
        self.learned_skills = {}
        self.skill_usage_count = defaultdict(int)
    
    def add_capability(self, capability_name: str, capability_func: callable):
        self.capabilities.add(capability_name)
        self.learned_skills[capability_name] = capability_func
    
    def use_capability(self, capability_name: str, *args, **kwargs):
        if capability_name in self.learned_skills:
            self.skill_usage_count[capability_name] += 1
            return self.learned_skills[capability_name](*args, **kwargs)
        return None
    
    def discover_new_capability(self, successful_interactions: List[InteractionRecord]):
        capability_candidates = []
        
        for interaction in successful_interactions:
            if "new_task" in interaction.metadata:
                task_type = interaction.metadata["new_task"]
                if task_type not in self.capabilities:
                    capability_candidates.append(task_type)
        
        for candidate in set(capability_candidates):
            if capability_candidates.count(candidate) >= 3:
                self.add_capability(candidate, lambda x: f"Auto-learned: {candidate}")
                print(f"[AUTO-LEARN] New capability discovered: {candidate}")
    
    def get_popular_capabilities(self, top_k: int = 10) -> List[tuple]:
        return sorted(self.skill_usage_count.items(), 
                     key=lambda x: x[1], reverse=True)[:top_k]

class EvolutionEngine:
    def __init__(self, data_dir: Path = None):
        self.data_dir = data_dir or Path(__file__).parent.parent.parent.parent / "data" / "learning"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.interaction_history: List[InteractionRecord] = []
        self.pattern_learner = PatternLearner()
        self.genetic_optimizer = GeneticOptimizer()
        self.capability_expander = CapabilityExpander()
        
        self.total_interactions = 0
        self.successful_interactions = 0
        self.success_rate = 0.0
        
        self.load_state()
    
    def learn_from_interaction(self, input_data: str, output_data: str, 
                               success: bool, metadata: Dict[str, Any] = None):
        record = InteractionRecord(
            input_data=input_data,
            output_data=output_data,
            success=success,
            timestamp=datetime.now(),
            metadata=metadata
        )
        
        self.interaction_history.append(record)
        self.total_interactions += 1
        if success:
            self.successful_interactions += 1
        
        self.success_rate = (self.successful_interactions / self.total_interactions 
                            if self.total_interactions > 0 else 0.0)
        
        self.pattern_learner.add_pattern(input_data, output_data, success)
        
        if len(self.interaction_history) % 100 == 0:
            self.auto_evolve()
        
        if len(self.interaction_history) % 50 == 0:
            self.save_state()
    
    def auto_evolve(self):
        print(f"[EVOLUTION] Starting auto-evolution (Generation {self.genetic_optimizer.generation})")
        
        recent_interactions = self.interaction_history[-100:]
        fitness_scores = [1.0 if i.success else 0.0 for i in recent_interactions]
        
        if len(fitness_scores) < len(self.genetic_optimizer.population):
            fitness_scores.extend([0.0] * (len(self.genetic_optimizer.population) - len(fitness_scores)))
        
        self.genetic_optimizer.evolve(fitness_scores[:self.genetic_optimizer.population_size])
        
        successful = [i for i in recent_interactions if i.success]
        self.capability_expander.discover_new_capability(successful)
        
        best = self.genetic_optimizer.get_best_individual()
        print(f"[EVOLUTION] Best fitness: {best['fitness']:.3f}, Success rate: {self.success_rate:.3f}")
    
    def predict_best_response(self, input_data: str) -> Optional[str]:
        cached_response = self.pattern_learner.get_best_response(input_data)
        if cached_response:
            return cached_response
        
        return None
    
    def get_learning_stats(self) -> Dict[str, Any]:
        return {
            'total_interactions': self.total_interactions,
            'successful_interactions': self.successful_interactions,
            'success_rate': self.success_rate,
            'generation': self.genetic_optimizer.generation,
            'learned_capabilities': len(self.capability_expander.capabilities),
            'unique_patterns': len(self.pattern_learner.patterns),
            'top_capabilities': self.capability_expander.get_popular_capabilities(5)
        }
    
    def save_state(self):
        state = {
            'interaction_count': len(self.interaction_history),
            'total_interactions': self.total_interactions,
            'successful_interactions': self.successful_interactions,
            'success_rate': self.success_rate,
            'generation': self.genetic_optimizer.generation,
            'capabilities': list(self.capability_expander.capabilities),
            'timestamp': datetime.now().isoformat()
        }
        
        state_path = self.data_dir / "evolution_state.json"
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)
        
        history_path = self.data_dir / "interaction_history.pkl"
        with open(history_path, 'wb') as f:
            pickle.dump(self.interaction_history[-1000:], f)
        
        patterns_path = self.data_dir / "patterns.pkl"
        with open(patterns_path, 'wb') as f:
            pickle.dump(self.pattern_learner, f)
    
    def load_state(self):
        try:
            state_path = self.data_dir / "evolution_state.json"
            if state_path.exists():
                with open(state_path, 'r') as f:
                    state = json.load(f)
                    self.total_interactions = state.get('total_interactions', 0)
                    self.successful_interactions = state.get('successful_interactions', 0)
                    self.success_rate = state.get('success_rate', 0.0)
                    self.genetic_optimizer.generation = state.get('generation', 0)
                    
                    for cap in state.get('capabilities', []):
                        self.capability_expander.add_capability(cap, lambda x: f"Loaded: {cap}")
            
            history_path = self.data_dir / "interaction_history.pkl"
            if history_path.exists():
                with open(history_path, 'rb') as f:
                    self.interaction_history = pickle.load(f)
            
            patterns_path = self.data_dir / "patterns.pkl"
            if patterns_path.exists():
                with open(patterns_path, 'rb') as f:
                    self.pattern_learner = pickle.load(f)
        
        except Exception as e:
            print(f"[EVOLUTION] Could not load state: {e}")

evolution_engine = EvolutionEngine()

def learn_from_interaction(input_data: str, output_data: str, success: bool, 
                          metadata: Dict[str, Any] = None):
    evolution_engine.learn_from_interaction(input_data, output_data, success, metadata)

def get_learning_stats() -> Dict[str, Any]:
    return evolution_engine.get_learning_stats()

def predict_best_response(input_data: str) -> Optional[str]:
    return evolution_engine.predict_best_response(input_data)
