"""
Multi-Agent Swarm Intelligence
5 specialist AI agents working together
"""
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import json
from datetime import datetime

class AgentRole(Enum):
    CODER = "coder"
    RESEARCHER = "researcher"
    ANALYST = "analyst"
    CREATIVE = "creative"
    CRITIC = "critic"

@dataclass
class AgentResponse:
    agent_role: AgentRole
    response: str
    confidence: float
    reasoning: str
    timestamp: datetime

class BaseAgent:
    def __init__(self, role: AgentRole, model_provider: str = "groq"):
        self.role = role
        self.model_provider = model_provider
        self.task_count = 0
        self.success_count = 0
    
    def get_system_prompt(self) -> str:
        prompts = {
            AgentRole.CODER: """You are a CODING SPECIALIST AI agent.
Your expertise:
- Writing clean, efficient code in any language
- Debugging and fixing errors
- Code architecture and design patterns
- Performance optimization
- Security best practices

Always provide: working code, explanations, and best practices.""",

            AgentRole.RESEARCHER: """You are a RESEARCH SPECIALIST AI agent.
Your expertise:
- Finding accurate information
- Verifying facts and sources
- Conducting thorough research
- Identifying reliable data
- Summarizing complex topics

Always provide: well-researched answers with sources.""",

            AgentRole.ANALYST: """You are an ANALYSIS SPECIALIST AI agent.
Your expertise:
- Data analysis and interpretation
- Statistical reasoning
- Pattern recognition
- Problem decomposition
- Root cause analysis

Always provide: insights, trends, and actionable recommendations.""",

            AgentRole.CREATIVE: """You are a CREATIVE SPECIALIST AI agent.
Your expertise:
- Generating creative ideas
- Content creation
- Brainstorming solutions
- Innovation and design thinking
- Out-of-the-box approaches

Always provide: novel ideas, creative solutions, and unique perspectives.""",

            AgentRole.CRITIC: """You are a CRITICAL EVALUATION SPECIALIST AI agent.
Your expertise:
- Identifying flaws and weaknesses
- Quality assurance
- Risk assessment
- Logical consistency checking
- Constructive criticism

Always provide: honest critique, potential issues, and improvement suggestions."""
        }
        return prompts.get(self.role, "You are a helpful AI assistant.")
    
    async def process(self, task: str, context: Dict[str, Any] = None) -> AgentResponse:
        from ..llm.model_loader import generate_response
        
        self.task_count += 1
        context = context or {}
        
        prompt = f"""TASK: {task}

CONTEXT: {json.dumps(context, indent=2) if context else 'No context'}

Provide your {self.role.value} perspective on this task.
"""
        
        try:
            response = await asyncio.to_thread(
                generate_response,
                prompt,
                system_prompt=self.get_system_prompt(),
                provider=self.model_provider
            )
            
            self.success_count += 1
            
            return AgentResponse(
                agent_role=self.role,
                response=response,
                confidence=0.8,
                reasoning=f"{self.role.value.title()} analysis complete",
                timestamp=datetime.now()
            )
        
        except Exception as e:
            return AgentResponse(
                agent_role=self.role,
                response=f"Error: {str(e)}",
                confidence=0.0,
                reasoning=f"Failed to process: {str(e)}",
                timestamp=datetime.now()
            )
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'role': self.role.value,
            'tasks_completed': self.task_count,
            'successful_tasks': self.success_count,
            'success_rate': self.success_count / self.task_count if self.task_count > 0 else 0.0
        }

class AgentSwarm:
    def __init__(self, model_provider: str = "groq"):
        self.agents = {
            AgentRole.CODER: BaseAgent(AgentRole.CODER, model_provider),
            AgentRole.RESEARCHER: BaseAgent(AgentRole.RESEARCHER, model_provider),
            AgentRole.ANALYST: BaseAgent(AgentRole.ANALYST, model_provider),
            AgentRole.CREATIVE: BaseAgent(AgentRole.CREATIVE, model_provider),
            AgentRole.CRITIC: BaseAgent(AgentRole.CRITIC, model_provider)
        }
        self.collaboration_history = []
    
    async def solve_with_all_agents(self, task: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        print(f"[SWARM] Deploying all 5 agents for task: {task[:50]}...")
        
        tasks = [agent.process(task, context) for agent in self.agents.values()]
        
        responses = await asyncio.gather(*tasks)
        
        result = {
            'task': task,
            'timestamp': datetime.now().isoformat(),
            'agent_responses': {}
        }
        
        for response in responses:
            result['agent_responses'][response.agent_role.value] = {
                'response': response.response,
                'confidence': response.confidence,
                'reasoning': response.reasoning
            }
        
        result['consensus'] = self._build_consensus(responses)
        result['best_response'] = self._select_best_response(responses)
        
        self.collaboration_history.append(result)
        
        return result
    
    async def solve_with_specific_agents(self, task: str, agent_roles: List[AgentRole], 
                                         context: Dict[str, Any] = None) -> Dict[str, Any]:
        print(f"[SWARM] Deploying {len(agent_roles)} agents: {[r.value for r in agent_roles]}")
        
        selected_agents = [self.agents[role] for role in agent_roles if role in self.agents]
        
        tasks = [agent.process(task, context) for agent in selected_agents]
        responses = await asyncio.gather(*tasks)
        
        result = {
            'task': task,
            'timestamp': datetime.now().isoformat(),
            'agent_responses': {}
        }
        
        for response in responses:
            result['agent_responses'][response.agent_role.value] = {
                'response': response.response,
                'confidence': response.confidence
            }
        
        result['consensus'] = self._build_consensus(responses)
        result['best_response'] = self._select_best_response(responses)
        
        return result
    
    def _build_consensus(self, responses: List[AgentResponse]) -> str:
        successful_responses = [r for r in responses if r.confidence > 0.5]
        
        if not successful_responses:
            return "No consensus reached - all agents had low confidence"
        
        consensus = "CONSENSUS:\n\n"
        
        for response in successful_responses:
            consensus += f"**{response.agent_role.value.title()}**: {response.response[:200]}...\n\n"
        
        consensus += f"\n{len(successful_responses)}/{len(responses)} agents reached consensus."
        
        return consensus
    
    def _select_best_response(self, responses: List[AgentResponse]) -> Dict[str, Any]:
        best = max(responses, key=lambda r: r.confidence)
        
        return {
            'agent': best.agent_role.value,
            'response': best.response,
            'confidence': best.confidence,
            'reasoning': best.reasoning
        }
    
    async def democratic_vote(self, task: str, options: List[str], 
                             context: Dict[str, Any] = None) -> Dict[str, Any]:
        print(f"[SWARM] Democratic voting on {len(options)} options")
        
        voting_task = f"""Vote on the best option for this task:

TASK: {task}

OPTIONS:
{chr(10).join([f"{i+1}. {opt}" for i, opt in enumerate(options)])}

Choose the best option and explain why. Respond with: "VOTE: [number]" followed by your reasoning.
"""
        
        result = await self.solve_with_all_agents(voting_task, context)
        
        votes = {}
        for agent_name, agent_data in result['agent_responses'].items():
            response = agent_data['response']
            
            try:
                if "VOTE:" in response:
                    vote_num = int(response.split("VOTE:")[1].strip().split()[0])
                    if 1 <= vote_num <= len(options):
                        votes[agent_name] = vote_num - 1
            except:
                pass
        
        if votes:
            from collections import Counter
            vote_counts = Counter(votes.values())
            winner_idx = vote_counts.most_common(1)[0][0]
            
            return {
                'winning_option': options[winner_idx],
                'votes': votes,
                'vote_distribution': dict(vote_counts),
                'consensus_strength': vote_counts[winner_idx] / len(votes)
            }
        
        return {
            'winning_option': None,
            'votes': {},
            'error': 'No valid votes received'
        }
    
    async def collaborative_creation(self, task: str) -> Dict[str, Any]:
        print(f"[SWARM] Collaborative creation mode")
        
        creative_response = await self.agents[AgentRole.CREATIVE].process(
            f"Generate 3 creative ideas for: {task}"
        )
        
        ideas = creative_response.response.split('\n')[:3]
        
        vote_result = await self.democratic_vote(task, ideas)
        
        if vote_result.get('winning_option'):
            best_idea = vote_result['winning_option']
            
            coder_task = f"Implement this idea: {best_idea}"
            analyst_task = f"Analyze feasibility of: {best_idea}"
            critic_task = f"Critique this idea: {best_idea}"
            
            final_responses = await asyncio.gather(
                self.agents[AgentRole.CODER].process(coder_task),
                self.agents[AgentRole.ANALYST].process(analyst_task),
                self.agents[AgentRole.CRITIC].process(critic_task)
            )
            
            return {
                'original_task': task,
                'creative_ideas': ideas,
                'chosen_idea': best_idea,
                'vote_result': vote_result,
                'implementation': final_responses[0].response,
                'feasibility_analysis': final_responses[1].response,
                'critique': final_responses[2].response
            }
        
        return {
            'error': 'Could not reach consensus on ideas'
        }
    
    def get_swarm_stats(self) -> Dict[str, Any]:
        stats = {
            'total_collaborations': len(self.collaboration_history),
            'agent_stats': {}
        }
        
        for role, agent in self.agents.items():
            stats['agent_stats'][role.value] = agent.get_stats()
        
        return stats

swarm = AgentSwarm()

async def solve_with_swarm(task: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    return await swarm.solve_with_all_agents(task, context)

async def solve_with_agents(task: str, agent_roles: List[str], 
                            context: Dict[str, Any] = None) -> Dict[str, Any]:
    roles = [AgentRole(role) for role in agent_roles]
    return await swarm.solve_with_specific_agents(task, roles, context)

async def collaborative_creation(task: str) -> Dict[str, Any]:
    return await swarm.collaborative_creation(task)

def get_swarm_stats() -> Dict[str, Any]:
    return swarm.get_swarm_stats()
