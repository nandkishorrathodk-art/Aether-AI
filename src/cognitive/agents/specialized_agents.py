"""
Specialized AI Agents for different task domains
Each agent is optimized for specific types of work
"""
import time
from typing import Dict, Any, List
from .multi_agent_system import BaseAgent, AgentType, AgentTask, AgentResponse
from src.cognitive.llm.model_router import router
from src.cognitive.llm.providers.base import TaskType
from src.utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisAgent(BaseAgent):
    """
    Specialized in SWOT, business analysis, data interpretation
    Replaces: Strategic analysts, business consultants, data analysts
    """
    
    def __init__(self, llm_provider=None):
        super().__init__(AgentType.ANALYSIS, llm_provider)
        self.expertise_level = 0.9
        
    async def process(self, task: AgentTask) -> AgentResponse:
        start_time = time.time()
        
        system_prompt = """You are an expert business analyst with 15+ years experience in strategic analysis, 
        SWOT analysis, market research, and competitive intelligence. Provide detailed, actionable insights."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task.prompt}
        ]
        
        try:
            response = await router.route_request(
                messages=messages,
                task_type=TaskType.ANALYSIS,
                temperature=0.3,
                max_tokens=4096
            )
            
            execution_time = time.time() - start_time
            
            return AgentResponse(
                agent_type=self.agent_type,
                result=response.content,
                confidence=0.85,
                execution_time=execution_time,
                metadata={
                    "provider": response.provider,
                    "model": response.model,
                    "tokens": response.usage.get("total_tokens", 0) if response.usage else 0
                }
            )
        except Exception as e:
            logger.error(f"Analysis agent failed: {e}")
            raise
            
    def get_capabilities(self) -> List[str]:
        return [
            "SWOT Analysis",
            "Market Research",
            "Competitive Analysis",
            "Business Intelligence",
            "Data Interpretation",
            "Trend Forecasting",
            "Financial Analysis"
        ]


class CodingAgent(BaseAgent):
    """
    Specialized in code generation, debugging, optimization
    Replaces: Junior/Mid-level developers, code reviewers
    """
    
    def __init__(self, llm_provider=None):
        super().__init__(AgentType.CODING, llm_provider)
        self.expertise_level = 0.95
        
    async def process(self, task: AgentTask) -> AgentResponse:
        start_time = time.time()
        
        system_prompt = """You are a senior software engineer with expertise in Python, JavaScript, 
        system design, algorithms, and best practices. Write production-ready, well-documented code."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task.prompt}
        ]
        
        try:
            response = await router.route_request(
                messages=messages,
                task_type=TaskType.CODE,
                temperature=0.2,
                max_tokens=8192
            )
            
            execution_time = time.time() - start_time
            
            return AgentResponse(
                agent_type=self.agent_type,
                result=response.content,
                confidence=0.92,
                execution_time=execution_time,
                metadata={
                    "provider": response.provider,
                    "model": response.model,
                    "language": task.context.get("language", "python")
                }
            )
        except Exception as e:
            logger.error(f"Coding agent failed: {e}")
            raise
            
    def get_capabilities(self) -> List[str]:
        return [
            "Code Generation (Python, JS, Go, Rust)",
            "Bug Fixing & Debugging",
            "Code Optimization",
            "Code Review",
            "API Design",
            "Algorithm Implementation",
            "Test Writing",
            "Documentation"
        ]


class CreativeAgent(BaseAgent):
    """
    Specialized in content creation, brainstorming, design
    Replaces: Content writers, copywriters, creative assistants
    """
    
    def __init__(self, llm_provider=None):
        super().__init__(AgentType.CREATIVE, llm_provider)
        self.expertise_level = 0.88
        
    async def process(self, task: AgentTask) -> AgentResponse:
        start_time = time.time()
        
        system_prompt = """You are a creative professional with expertise in copywriting, 
        content strategy, storytelling, and innovative thinking. Generate engaging, original content."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task.prompt}
        ]
        
        try:
            response = await router.route_request(
                messages=messages,
                task_type=TaskType.CREATIVE,
                temperature=0.8,
                max_tokens=4096
            )
            
            execution_time = time.time() - start_time
            
            return AgentResponse(
                agent_type=self.agent_type,
                result=response.content,
                confidence=0.82,
                execution_time=execution_time,
                metadata={
                    "provider": response.provider,
                    "model": response.model,
                    "creativity_level": "high"
                }
            )
        except Exception as e:
            logger.error(f"Creative agent failed: {e}")
            raise
            
    def get_capabilities(self) -> List[str]:
        return [
            "Blog Writing",
            "Marketing Copy",
            "Social Media Content",
            "Brainstorming",
            "Storytelling",
            "Product Descriptions",
            "Email Campaigns",
            "Creative Ideation"
        ]


class StrategyAgent(BaseAgent):
    """
    Specialized in high-level strategic planning and decision-making
    Replaces: Management consultants, strategy directors, C-level advisors
    """
    
    def __init__(self, llm_provider=None):
        super().__init__(AgentType.STRATEGY, llm_provider)
        self.expertise_level = 0.92
        
    async def process(self, task: AgentTask) -> AgentResponse:
        start_time = time.time()
        
        system_prompt = """You are a senior management consultant with MBA and 20+ years experience 
        in corporate strategy, business transformation, and organizational leadership. Think like a CEO."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task.prompt}
        ]
        
        try:
            response = await router.route_request(
                messages=messages,
                task_type=TaskType.ANALYSIS,
                temperature=0.4,
                max_tokens=6144
            )
            
            execution_time = time.time() - start_time
            
            return AgentResponse(
                agent_type=self.agent_type,
                result=response.content,
                confidence=0.87,
                execution_time=execution_time,
                metadata={
                    "provider": response.provider,
                    "model": response.model,
                    "strategic_level": "executive"
                }
            )
        except Exception as e:
            logger.error(f"Strategy agent failed: {e}")
            raise
            
    def get_capabilities(self) -> List[str]:
        return [
            "Business Strategy",
            "Growth Planning",
            "M&A Analysis",
            "Organizational Design",
            "Change Management",
            "Risk Assessment",
            "Market Entry Strategy",
            "Competitive Positioning"
        ]


class SecurityAgent(BaseAgent):
    """
    Specialized in cybersecurity, threat analysis, compliance
    Replaces: Security analysts, compliance officers, ethical hackers
    """
    
    def __init__(self, llm_provider=None):
        super().__init__(AgentType.SECURITY, llm_provider)
        self.expertise_level = 0.91
        
    async def process(self, task: AgentTask) -> AgentResponse:
        start_time = time.time()
        
        system_prompt = """You are a cybersecurity expert with certifications (CISSP, CEH, OSCP) 
        and experience in threat detection, penetration testing, and security architecture. 
        Provide security-focused analysis and recommendations."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task.prompt}
        ]
        
        try:
            response = await router.route_request(
                messages=messages,
                task_type=TaskType.ANALYSIS,
                temperature=0.2,
                max_tokens=4096
            )
            
            execution_time = time.time() - start_time
            
            return AgentResponse(
                agent_type=self.agent_type,
                result=response.content,
                confidence=0.89,
                execution_time=execution_time,
                metadata={
                    "provider": response.provider,
                    "model": response.model,
                    "security_focus": True
                }
            )
        except Exception as e:
            logger.error(f"Security agent failed: {e}")
            raise
            
    def get_capabilities(self) -> List[str]:
        return [
            "Threat Detection",
            "Vulnerability Assessment",
            "Security Audits",
            "Compliance Analysis (GDPR, ISO 27001, SOC 2)",
            "Incident Response",
            "Penetration Testing Guidance",
            "Security Architecture Review",
            "Risk Management"
        ]
