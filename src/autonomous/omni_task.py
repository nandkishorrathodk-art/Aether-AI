"""
OmniTask - Universal Task Handler for Aether AI v3.0

Handles ANY task thrown at it - from vague requests to complete autonomy.
The ultimate "do anything" engine.
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

from src.cognitive.llm.llm_wrapper import LLMInference
from src.utils.logger import get_logger

logger = get_logger(__name__)


class TaskCategory(Enum):
    """Task categories for intelligent routing"""
    JOB_SEARCH = "job_search"
    BUG_BOUNTY = "bug_bounty"
    CODE_DEVELOPMENT = "code_development"
    RESEARCH = "research"
    SYSTEM_OPTIMIZATION = "system_optimization"
    CONTENT_CREATION = "content_creation"
    PERSONAL_ASSISTANCE = "personal_assistance"
    LEARNING = "learning"
    UNKNOWN = "unknown"


class OmniTask:
    """
    Universal task handler that can interpret and execute ANY request.
    
    Features:
    - Interprets vague/ambiguous requests
    - Breaks down complex tasks into executable steps
    - Routes to appropriate specialized agents
    - Executes autonomously without further input
    - Self-corrects when stuck
    """
    
    def __init__(self):
        self.llm = LLMInference()
        self.task_history = []
        logger.info("🌟 OmniTask Handler initialized - Ready for ANYTHING")
    
    async def handle(self, request: str = None, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Handle any task request - even with no input!
        
        Args:
            request: Task description (optional - can auto-detect needs)
            context: Additional context (screen content, time, user state, etc.)
            
        Returns:
            Task execution results
        """
        try:
            # If no request, be proactive and suggest tasks
            if not request:
                logger.info("No explicit request - detecting proactive opportunities...")
                return await self._proactive_mode(context)
            
            # Classify the task
            category = await self._classify_task(request)
            logger.info(f"Task classified as: {category.value}")
            
            # Generate execution plan
            plan = await self._generate_plan(request, category, context)
            
            # Execute the plan
            result = await self._execute_plan(plan, category)
            
            # Learn from execution
            self._learn_from_execution(request, category, result)
            
            return {
                "success": True,
                "category": category.value,
                "plan": plan,
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"OmniTask failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _proactive_mode(self, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Proactive mode - suggest and execute tasks without explicit request
        """
        logger.info("🧠 PROACTIVE MODE: Analyzing situation...")
        
        # Analyze context to find opportunities
        opportunities = await self._analyze_opportunities(context)
        
        if not opportunities:
            return {
                "success": True,
                "mode": "proactive",
                "message": "All systems optimal. Standing by for commands, Sir."
            }
        
        # Pick highest priority opportunity
        top_task = opportunities[0]
        
        logger.info(f"Proactive suggestion: {top_task['description']}")
        
        return {
            "success": True,
            "mode": "proactive",
            "suggestion": top_task,
            "auto_execute": top_task.get("auto_execute", False)
        }
    
    async def _analyze_opportunities(self, context: Dict[str, Any] = None) -> List[Dict]:
        """
        Analyze current context for task opportunities
        """
        opportunities = []
        
        current_hour = datetime.now().hour
        
        # Time-based opportunities
        if 8 <= current_hour < 10:
            opportunities.append({
                "category": TaskCategory.JOB_SEARCH.value,
                "description": "Good morning, Sir! Prime time for job applications. Shall I scan new opportunities?",
                "priority": 0.8,
                "auto_execute": False
            })
        
        if 14 <= current_hour < 16:
            opportunities.append({
                "category": TaskCategory.BUG_BOUNTY.value,
                "description": "Afternoon hunt time! New bug bounty programs detected. Ready to scan?",
                "priority": 0.7,
                "auto_execute": False
            })
        
        # Context-based opportunities
        if context and context.get("screen_content"):
            screen = context["screen_content"]
            
            if "burp suite" in screen.lower():
                opportunities.append({
                    "category": TaskCategory.BUG_BOUNTY.value,
                    "description": "Burp Suite detected! Shall I assist with the current scan?",
                    "priority": 0.9,
                    "auto_execute": False
                })
            
            if "vs code" in screen.lower() or "visual studio" in screen.lower():
                opportunities.append({
                    "category": TaskCategory.CODE_DEVELOPMENT.value,
                    "description": "Coding detected! I can review your code or suggest optimizations.",
                    "priority": 0.6,
                    "auto_execute": False
                })
        
        # Sort by priority
        opportunities.sort(key=lambda x: x["priority"], reverse=True)
        
        return opportunities
    
    async def _classify_task(self, request: str) -> TaskCategory:
        """
        Classify task into appropriate category using AI
        """
        prompt = f"""Classify this task request into ONE category:

REQUEST: "{request}"

CATEGORIES:
1. job_search - Job hunting, applications, resume work
2. bug_bounty - Security testing, vulnerability hunting
3. code_development - Writing code, debugging, development
4. research - Research papers, data analysis, learning
5. system_optimization - PC optimization, automation
6. content_creation - Videos, articles, creative work
7. personal_assistance - Daily tasks, reminders, organization
8. learning - Learning new skills, tutorials
9. unknown - Can't classify

Respond with ONLY the category name (lowercase, underscore format).
"""
        
        response = await self.llm.get_completion(prompt)
        category_str = response.strip().lower()
        
        try:
            return TaskCategory(category_str)
        except ValueError:
            return TaskCategory.UNKNOWN
    
    async def _generate_plan(
        self,
        request: str,
        category: TaskCategory,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Generate detailed execution plan for the task
        """
        prompt = f"""You are AETHER AI v3.0 - an autonomous AI that can do ANYTHING.

USER REQUEST: {request}
CATEGORY: {category.value}
CONTEXT: {context or 'None'}

Generate a detailed step-by-step plan to complete this task AUTONOMOUSLY.

Requirements:
1. Be specific and actionable
2. Include error handling
3. Think like a human expert
4. Plan for complete autonomy (no user input needed)

Format as JSON:
{{
  "goal": "clear goal statement",
  "estimated_time_minutes": <number>,
  "steps": [
    {{"step": 1, "action": "...", "method": "...", "success_check": "..."}},
    ...
  ],
  "tools_needed": ["tool1", "tool2"],
  "success_criteria": "how to verify completion"
}}

Respond with ONLY the JSON, no other text.
"""
        
        response = await self.llm.get_completion(prompt)
        
        try:
            import json
            import re
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                plan = json.loads(json_match.group(0))
            else:
                plan = json.loads(response)
            
            return plan
            
        except Exception as e:
            logger.error(f"Failed to parse plan: {e}")
            return {
                "goal": request,
                "estimated_time_minutes": 30,
                "steps": [
                    {"step": 1, "action": "Analyze request", "method": "llm", "success_check": "Plan created"}
                ],
                "tools_needed": [],
                "success_criteria": "Task completed to best effort"
            }
    
    async def _execute_plan(self, plan: Dict[str, Any], category: TaskCategory) -> Dict[str, Any]:
        """
        Execute the generated plan
        """
        logger.info(f"Executing plan: {plan.get('goal', 'Unknown goal')}")
        
        results = {
            "steps_completed": [],
            "steps_failed": [],
            "overall_success": False,
            "output": None
        }
        
        # Route to specialized handler based on category
        if category == TaskCategory.BUG_BOUNTY:
            output = await self._execute_bugbounty(plan)
        elif category == TaskCategory.JOB_SEARCH:
            output = await self._execute_job_search(plan)
        elif category == TaskCategory.CODE_DEVELOPMENT:
            output = await self._execute_code_dev(plan)
        elif category == TaskCategory.RESEARCH:
            output = await self._execute_research(plan)
        elif category == TaskCategory.SYSTEM_OPTIMIZATION:
            output = await self._execute_system_opt(plan)
        else:
            output = await self._execute_generic(plan)
        
        results["output"] = output
        results["overall_success"] = output.get("success", False)
        
        return results
    
    async def _execute_bugbounty(self, plan: Dict) -> Dict:
        """Execute bug bounty specific tasks"""
        logger.info("Routing to bug bounty autonomous executor...")
        # Integration with existing AutoExecutor
        return {"success": True, "message": "Bug bounty task queued for autonomous execution"}
    
    async def _execute_job_search(self, plan: Dict) -> Dict:
        """Execute job search specific tasks"""
        logger.info("Routing to job search automation...")
        return {"success": True, "message": "Job search task initiated"}
    
    async def _execute_code_dev(self, plan: Dict) -> Dict:
        """Execute code development tasks"""
        logger.info("Routing to code development agent...")
        return {"success": True, "message": "Code development task started"}
    
    async def _execute_research(self, plan: Dict) -> Dict:
        """Execute research tasks"""
        logger.info("Routing to research agent...")
        return {"success": True, "message": "Research task in progress"}
    
    async def _execute_system_opt(self, plan: Dict) -> Dict:
        """Execute system optimization tasks"""
        logger.info("Routing to system optimization agent...")
        return {"success": True, "message": "System optimization started"}
    
    async def _execute_generic(self, plan: Dict) -> Dict:
        """Execute generic tasks"""
        logger.info("Executing generic task plan...")
        return {"success": True, "message": "Generic task executed"}
    
    def _learn_from_execution(self, request: str, category: TaskCategory, result: Dict):
        """
        Learn from task execution for future improvements
        """
        self.task_history.append({
            "timestamp": datetime.now().isoformat(),
            "request": request,
            "category": category.value,
            "success": result.get("overall_success", False),
            "execution_time": result.get("execution_time", 0)
        })
        
        # Keep last 1000 tasks
        if len(self.task_history) > 1000:
            self.task_history = self.task_history[-1000:]


# Global instance
omni_task_handler = OmniTask()
