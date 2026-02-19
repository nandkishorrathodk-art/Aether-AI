import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class AgentCapability(Enum):
    """Agent capability types"""
    WEB_SCRAPING = "web_scraping"
    CODE_ANALYSIS = "code_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOIT_DEVELOPMENT = "exploit_development"
    REPORT_GENERATION = "report_generation"
    DATA_EXTRACTION = "data_extraction"
    API_TESTING = "api_testing"
    AUTH_BYPASS = "auth_bypass"
    XSS_DETECTION = "xss_detection"
    SQL_INJECTION = "sql_injection"
    INTELLIGENCE = "intelligence"
    COORDINATION = "coordination"


class Agent:
    """Individual specialized agent"""
    
    def __init__(
        self,
        name: str,
        capabilities: List[AgentCapability],
        execute_func: Callable
    ):
        self.name = name
        self.capabilities = capabilities
        self.execute = execute_func
        self.status = "idle"
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.created_at = datetime.now()
    
    async def run_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute assigned task"""
        self.status = "running"
        logger.info(f"Agent {self.name} starting task: {task.get('type')}")
        
        try:
            result = await self.execute(task)
            self.tasks_completed += 1
            self.status = "idle"
            return {
                "success": True,
                "agent": self.name,
                "result": result
            }
        except Exception as e:
            self.tasks_failed += 1
            self.status = "idle"
            logger.error(f"Agent {self.name} failed: {e}")
            return {
                "success": False,
                "agent": self.name,
                "error": str(e)
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return {
            "name": self.name,
            "status": self.status,
            "capabilities": [c.value for c in self.capabilities],
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "success_rate": round(
                self.tasks_completed / max(self.tasks_completed + self.tasks_failed, 1) * 100,
                2
            ),
            "uptime_seconds": (datetime.now() - self.created_at).total_seconds()
        }


class AgentMesh:
    """
    Neural mesh framework for agent orchestration
    Manages 60+ specialized AI agents with event streaming
    """
    
    def __init__(self):
        self.agents: Dict[str, Agent] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.result_queue: asyncio.Queue = asyncio.Queue()
        self.running = False
        logger.info("Agent Mesh initialized")
    
    def register_agent(self, agent: Agent):
        """Register new agent in mesh"""
        self.agents[agent.name] = agent
        logger.info(f"Agent registered: {agent.name} with capabilities {agent.capabilities}")
    
    def create_standard_agents(self):
        """Create standard agent fleet"""
        
        # Web scraping agent
        async def scrape_task(task):
            from src.openclaw.openclaw import OpenClaw
            claw = OpenClaw()
            return await claw.scrape(task["url"])
        
        self.register_agent(Agent(
            "web_scraper_01",
            [AgentCapability.WEB_SCRAPING, AgentCapability.DATA_EXTRACTION],
            scrape_task
        ))
        
        # Vulnerability scanner agent
        async def scan_task(task):
            from src.security.vulnerability_scanner import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            return await scanner.quick_scan(task["target"])
        
        self.register_agent(Agent(
            "vuln_scanner_01",
            [AgentCapability.VULNERABILITY_SCAN, AgentCapability.XSS_DETECTION],
            scan_task
        ))
        
        # Code analysis agent
        async def code_task(task):
            from src.execution.code_executor import get_executor
            executor = get_executor()
            return await executor.execute(
                task["code"],
                task.get("language", "python")
            )
        
        self.register_agent(Agent(
            "code_analyzer_01",
            [AgentCapability.CODE_ANALYSIS],
            code_task
        ))
        
        # Intelligence agent (LLM-powered)
        async def intel_task(task):
            from src.cognitive.llm.model_router import ModelRouter
            router = ModelRouter()
            return await router.generate(task["prompt"])
        
        for i in range(5):
            self.register_agent(Agent(
                f"intelligence_{i:02d}",
                [AgentCapability.INTELLIGENCE, AgentCapability.REPORT_GENERATION],
                intel_task
            ))
        
        logger.info(f"Created {len(self.agents)} standard agents")
    
    async def route_task(self, task: Dict[str, Any]) -> Optional[Agent]:
        """Route task to best available agent"""
        required_capability = AgentCapability(task.get("capability", "intelligence"))
        
        # Find available agents with capability
        available = [
            agent for agent in self.agents.values()
            if required_capability in agent.capabilities and agent.status == "idle"
        ]
        
        if not available:
            logger.warning(f"No available agents for {required_capability}")
            return None
        
        # Select agent with lowest task count (load balancing)
        return min(available, key=lambda a: a.tasks_completed)
    
    async def submit_task(self, task: Dict[str, Any]) -> str:
        """Submit task to mesh"""
        task_id = f"task_{datetime.now().timestamp()}"
        task["id"] = task_id
        await self.task_queue.put(task)
        logger.info(f"Task {task_id} submitted to mesh")
        return task_id
    
    async def process_tasks(self):
        """Main task processing loop"""
        logger.info("Agent mesh task processor started")
        
        while self.running:
            try:
                # Get next task (wait up to 1 second)
                task = await asyncio.wait_for(
                    self.task_queue.get(),
                    timeout=1.0
                )
                
                # Route to agent
                agent = await self.route_task(task)
                
                if agent:
                    # Execute asynchronously
                    result = await agent.run_task(task)
                    await self.result_queue.put(result)
                else:
                    # Re-queue if no agent available
                    await asyncio.sleep(0.5)
                    await self.task_queue.put(task)
            
            except asyncio.TimeoutError:
                # No tasks, continue loop
                continue
            except Exception as e:
                logger.error(f"Task processing error: {e}")
    
    async def start(self):
        """Start agent mesh"""
        if not self.agents:
            self.create_standard_agents()
        
        self.running = True
        
        # Start task processors (3 concurrent workers)
        workers = [
            asyncio.create_task(self.process_tasks())
            for _ in range(3)
        ]
        
        logger.info("Agent mesh started with 3 workers")
        
        return workers
    
    async def stop(self):
        """Stop agent mesh"""
        self.running = False
        logger.info("Agent mesh stopped")
    
    async def execute_swarm(
        self,
        tasks: List[Dict[str, Any]],
        max_concurrent: int = 10
    ) -> List[Dict[str, Any]]:
        """Execute multiple tasks in parallel (swarm mode)"""
        logger.info(f"Executing swarm of {len(tasks)} tasks")
        
        # Submit all tasks
        task_ids = []
        for task in tasks:
            task_id = await self.submit_task(task)
            task_ids.append(task_id)
        
        # Collect results
        results = []
        for _ in range(len(tasks)):
            result = await self.result_queue.get()
            results.append(result)
        
        logger.info(f"Swarm complete: {len(results)} results")
        return results
    
    def get_mesh_stats(self) -> Dict[str, Any]:
        """Get mesh statistics"""
        total_completed = sum(a.tasks_completed for a in self.agents.values())
        total_failed = sum(a.tasks_failed for a in self.agents.values())
        
        return {
            "total_agents": len(self.agents),
            "active_agents": sum(1 for a in self.agents.values() if a.status != "idle"),
            "tasks_completed": total_completed,
            "tasks_failed": total_failed,
            "success_rate": round(
                total_completed / max(total_completed + total_failed, 1) * 100,
                2
            ),
            "queue_size": self.task_queue.qsize(),
            "agents": [agent.get_stats() for agent in self.agents.values()]
        }
    
    async def coordinate_attack(
        self,
        target: str,
        attack_type: str = "full"
    ) -> Dict[str, Any]:
        """Coordinate multi-agent attack on target"""
        logger.info(f"Coordinating {attack_type} attack on {target}")
        
        # Build attack plan
        tasks = []
        
        if attack_type in ["full", "recon"]:
            tasks.append({
                "capability": "web_scraping",
                "url": target,
                "type": "reconnaissance"
            })
        
        if attack_type in ["full", "scan"]:
            tasks.append({
                "capability": "vulnerability_scan",
                "target": target,
                "type": "vulnerability_scan"
            })
        
        if attack_type in ["full", "intelligence"]:
            tasks.append({
                "capability": "intelligence",
                "prompt": f"Analyze {target} for security weaknesses",
                "type": "analysis"
            })
        
        # Execute swarm
        results = await self.execute_swarm(tasks)
        
        return {
            "target": target,
            "attack_type": attack_type,
            "tasks_executed": len(tasks),
            "results": results,
            "timestamp": datetime.now().isoformat()
        }


# Singleton
_mesh = None

def get_agent_mesh() -> AgentMesh:
    global _mesh
    if _mesh is None:
        _mesh = AgentMesh()
    return _mesh
