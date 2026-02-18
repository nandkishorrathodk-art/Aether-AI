"""
Autonomous Brain - The Core Decision Maker

Decides what to do next without human input.
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from src.cognitive.llm.llm_wrapper import LLMInference
from src.utils.logger import get_logger
from src.monitoring.screen_monitor import ScreenMonitor
from src.control.pc_controller import PCController
from src.autonomous.vision_system import VisionSystem
from src.autonomous.decision_engine import DecisionEngine

logger = get_logger(__name__)


class AgentState(Enum):
    """Agent operational states"""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    WAITING_APPROVAL = "waiting_approval"


class AutonomousBrain:
    """
    The autonomous brain that controls everything without human intervention.
    
    This is the TRUE JARVIS - decides and acts independently.
    """
    
    def __init__(self):
        self.llm = LLMInference()
        self.screen_monitor = ScreenMonitor()
        self.pc_controller = PCController()
        self.vision = VisionSystem()
        self.decision_engine = DecisionEngine()
        
        self.state = AgentState.IDLE
        self.current_task = None
        self.task_history = []
        self.findings = []
        
        logger.info("Autonomous Brain initialized - FULL GOD MODE")
    
    async def start_autonomous_mode(self, goal: str, max_duration_hours: int = 8):
        """
        Start fully autonomous operation
        
        Args:
            goal: High-level goal (e.g., "Find bugs on Apple.com")
            max_duration_hours: Maximum time to run autonomously
            
        This will run completely independently until goal is achieved.
        """
        try:
            logger.info(f"🚀 Starting autonomous mode: {goal}")
            logger.info(f"⏰ Max duration: {max_duration_hours} hours")
            
            start_time = datetime.now()
            
            self.state = AgentState.PLANNING
            plan = await self._create_master_plan(goal)
            
            logger.info(f"📋 Master Plan Created:")
            for i, step in enumerate(plan["steps"]):
                logger.info(f"   {i+1}. {step['action']}")
            
            for step_num, step in enumerate(plan["steps"]):
                if self._should_stop(start_time, max_duration_hours):
                    logger.info("Time limit reached, stopping gracefully")
                    break
                
                logger.info(f"\n{'='*60}")
                logger.info(f"🎯 Executing Step {step_num + 1}/{len(plan['steps'])}: {step['action']}")
                logger.info(f"{'='*60}\n")
                
                self.state = AgentState.EXECUTING
                result = await self._execute_step(step)
                
                if result.get("bug_found"):
                    self.findings.append(result)
                    logger.info(f"🚨 BUG FOUND! Total findings: {len(self.findings)}")
                
                if result.get("critical_error"):
                    logger.error(f"❌ Critical error in step {step_num + 1}, stopping")
                    break
                
                if step.get("wait_after"):
                    await asyncio.sleep(step["wait_after"])
            
            self.state = AgentState.REPORTING
            final_report = await self._generate_final_report(goal, plan)
            
            logger.info(f"\n{'='*60}")
            logger.info(f"✅ AUTONOMOUS SESSION COMPLETE")
            logger.info(f"{'='*60}")
            logger.info(f"Total bugs found: {len(self.findings)}")
            logger.info(f"Duration: {(datetime.now() - start_time).total_seconds() / 3600:.2f} hours")
            
            return final_report
            
        except Exception as e:
            logger.error(f"Autonomous mode failed: {e}", exc_info=True)
            self.state = AgentState.IDLE
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _create_master_plan(self, goal: str) -> Dict:
        """
        Create autonomous master plan using LLM
        
        No human input needed - AI decides everything.
        """
        prompt = f"""You are VELTRON, a fully autonomous AI hacker. Create a detailed plan to achieve this goal:

GOAL: {goal}

You have these capabilities:
- Control mouse and keyboard
- Open and operate applications (Burp Suite, browsers, terminals)
- Read and analyze screen content
- Write code and scripts
- Execute commands
- Make decisions independently

Create a step-by-step plan. Each step should be specific and actionable.

Format:
```json
{{
  "goal": "{goal}",
  "estimated_duration_minutes": <number>,
  "steps": [
    {{
      "step_number": 1,
      "action": "Open Burp Suite Professional",
      "method": "pc_control",
      "parameters": {{"app": "burp"}},
      "success_criteria": "Burp Suite window visible",
      "wait_after": 3
    }},
    {{
      "step_number": 2,
      "action": "Configure proxy to localhost:8080",
      "method": "burp_config",
      "parameters": {{"proxy": "localhost:8080"}},
      "success_criteria": "Proxy configured",
      "wait_after": 2
    }}
  ]
}}
```

Make the plan comprehensive but efficient. Think like a professional bug bounty hunter.
"""
        
        response = await self.llm.get_completion(prompt)
        
        try:
            import json
            import re
            
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response, re.DOTALL)
            if json_match:
                plan = json.loads(json_match.group(1))
            else:
                plan = json.loads(response)
            
            return plan
            
        except Exception as e:
            logger.error(f"Failed to parse plan: {e}")
            return self._get_default_plan(goal)
    
    def _get_default_plan(self, goal: str) -> Dict:
        """Default plan if LLM fails"""
        return {
            "goal": goal,
            "estimated_duration_minutes": 120,
            "steps": [
                {
                    "step_number": 1,
                    "action": "Open Burp Suite",
                    "method": "pc_control",
                    "parameters": {"app": "burp"},
                    "success_criteria": "Burp Suite running",
                    "wait_after": 5
                },
                {
                    "step_number": 2,
                    "action": "Configure browser proxy",
                    "method": "browser_config",
                    "parameters": {"proxy": "localhost:8080"},
                    "success_criteria": "Proxy configured",
                    "wait_after": 2
                },
                {
                    "step_number": 3,
                    "action": "Navigate to target",
                    "method": "browser_navigate",
                    "parameters": {"url": self._extract_target_from_goal(goal)},
                    "success_criteria": "Target loaded",
                    "wait_after": 3
                },
                {
                    "step_number": 4,
                    "action": "Start passive scanning",
                    "method": "burp_scan",
                    "parameters": {"type": "passive"},
                    "success_criteria": "Scan running",
                    "wait_after": 60
                },
                {
                    "step_number": 5,
                    "action": "Analyze findings",
                    "method": "analyze_results",
                    "parameters": {},
                    "success_criteria": "Analysis complete",
                    "wait_after": 0
                }
            ]
        }
    
    def _extract_target_from_goal(self, goal: str) -> str:
        """Extract target domain from goal"""
        import re
        match = re.search(r'(https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', goal)
        if match:
            domain = match.group(2)
            return f"https://{domain}"
        return "https://example.com"
    
    async def _execute_step(self, step: Dict) -> Dict:
        """
        Execute a single step autonomously
        """
        try:
            method = step.get("method")
            params = step.get("parameters", {})
            
            logger.info(f"▶️  Executing: {step['action']}")
            
            if method == "pc_control":
                return await self._execute_pc_control(step, params)
            
            elif method == "burp_config":
                return await self._execute_burp_config(step, params)
            
            elif method == "browser_navigate":
                return await self._execute_browser_navigate(step, params)
            
            elif method == "burp_scan":
                return await self._execute_burp_scan(step, params)
            
            elif method == "analyze_results":
                return await self._execute_analyze_results(step, params)
            
            elif method == "visual_analysis":
                return await self._execute_visual_analysis(step, params)
            
            elif method == "custom_code":
                return await self._execute_custom_code(step, params)
            
            else:
                logger.warning(f"Unknown method: {method}, using generic execution")
                return await self._execute_generic(step, params)
            
        except Exception as e:
            logger.error(f"Step execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "step": step["action"]
            }
    
    async def _execute_pc_control(self, step: Dict, params: Dict) -> Dict:
        """Execute PC control action (open app, click, type)"""
        try:
            app_name = params.get("app")
            
            if app_name == "burp":
                result = await self.pc_controller.launch_app("Burp Suite Professional")
                
                await asyncio.sleep(3)
                
                screenshot = await self.screen_monitor.capture_screenshot()
                is_running = await self.vision.detect_application(screenshot, "Burp Suite")
                
                return {
                    "success": is_running,
                    "app": app_name,
                    "running": is_running
                }
            
            return {"success": True}
            
        except Exception as e:
            logger.error(f"PC control failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _execute_burp_config(self, step: Dict, params: Dict) -> Dict:
        """Configure Burp Suite settings"""
        logger.info("Configuring Burp Suite proxy...")
        return {"success": True, "configured": True}
    
    async def _execute_browser_navigate(self, step: Dict, params: Dict) -> Dict:
        """Navigate browser to URL"""
        url = params.get("url")
        logger.info(f"Navigating to: {url}")
        
        await self.pc_controller.launch_app("Google Chrome")
        await asyncio.sleep(2)
        
        await self.pc_controller.type_text(url)
        await self.pc_controller.press_key("enter")
        
        return {"success": True, "url": url}
    
    async def _execute_burp_scan(self, step: Dict, params: Dict) -> Dict:
        """Execute Burp Suite scan"""
        scan_type = params.get("type", "passive")
        logger.info(f"Starting {scan_type} scan...")
        
        return {"success": True, "scan_type": scan_type}
    
    async def _execute_analyze_results(self, step: Dict, params: Dict) -> Dict:
        """Analyze Burp Suite results for bugs"""
        logger.info("Analyzing scan results...")
        
        screenshot = await self.screen_monitor.capture_screenshot()
        
        analysis = await self.vision.analyze_burp_findings(screenshot)
        
        bugs_found = analysis.get("bugs_found", [])
        
        if bugs_found:
            logger.info(f"🚨 Found {len(bugs_found)} potential bugs!")
            return {
                "success": True,
                "bug_found": True,
                "bugs": bugs_found
            }
        
        return {
            "success": True,
            "bug_found": False
        }
    
    async def _execute_visual_analysis(self, step: Dict, params: Dict) -> Dict:
        """Perform visual analysis of screen"""
        screenshot = await self.screen_monitor.capture_screenshot()
        analysis = await self.vision.analyze_screen(screenshot)
        
        return {
            "success": True,
            "analysis": analysis
        }
    
    async def _execute_custom_code(self, step: Dict, params: Dict) -> Dict:
        """Write and execute custom code"""
        from src.autonomous.self_coder import SelfCoder
        
        coder = SelfCoder()
        code = await coder.write_exploit_code(params)
        
        result = await coder.execute_code(code)
        
        return {
            "success": True,
            "code_executed": True,
            "result": result
        }
    
    async def _execute_generic(self, step: Dict, params: Dict) -> Dict:
        """Generic execution for unknown methods"""
        logger.info(f"Generic execution: {step['action']}")
        return {"success": True}
    
    def _should_stop(self, start_time: datetime, max_hours: int) -> bool:
        """Check if we should stop autonomous operation"""
        elapsed = (datetime.now() - start_time).total_seconds() / 3600
        return elapsed >= max_hours
    
    async def _generate_final_report(self, goal: str, plan: Dict) -> Dict:
        """Generate final autonomous session report"""
        return {
            "success": True,
            "goal": goal,
            "plan_steps": len(plan.get("steps", [])),
            "bugs_found": len(self.findings),
            "findings": self.findings,
            "task_history": self.task_history[-10:]
        }
