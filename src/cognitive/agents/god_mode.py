"""
God Mode Autonomous Agent

This is the BRAIN that turns Aether from reactive to PROACTIVE.
One command → Aether plans, executes, narrates, and asks next step.

Features:
- Autonomous multi-step task planning
- Real-time narration via pipeline.narrate()
- Self-decision loop: decides next action after each step
- Bug bounty integration: HUNT command
- Broadcast live status to HUD
"""

import asyncio
import logging
import re
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class GodModeStatus(Enum):
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING = "waiting"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class GodModeTask:
    """A planned autonomous task"""
    task_id: str
    name: str
    command: str                       # Raw user command
    steps: List[Dict[str, Any]] = field(default_factory=list)
    current_step: int = 0
    status: GodModeStatus = GodModeStatus.IDLE
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    result: Optional[str] = None
    narrations: List[str] = field(default_factory=list)


class GodModeAgent:
    """
    The Autonomous Agent that powers Aether in God Mode.
    
    Usage:
        agent = GodModeAgent()
        await agent.execute("BurpSuite setup karo aur HackerOne scan shuru karo")
    """

    def __init__(self):
        self.active_tasks: Dict[str, GodModeTask] = {}
        self.status = GodModeStatus.IDLE
        self._pipeline = None
        logger.info("🔥 God Mode Agent initialized - FULL POWER READY")

    def _get_pipeline(self):
        """Lazy-load pipeline to avoid circular imports"""
        if self._pipeline is None:
            try:
                from src.pipeline.voice_pipeline import get_pipeline
                self._pipeline = get_pipeline()
            except Exception as e:
                logger.warning(f"Pipeline not available: {e}")
        return self._pipeline

    def narrate(self, text: str):
        """Speak narration via voice pipeline"""
        logger.info(f"📣 GOD MODE NARRATION: {text}")
        try:
            pipeline = self._get_pipeline()
            if pipeline and hasattr(pipeline, 'narrate'):
                pipeline.narrate(text)
            # Also broadcast to HUD
            self._broadcast_hud({"narration": text})
        except Exception as e:
            logger.error(f"Narration failed: {e}")

    def _broadcast_hud(self, data: Dict[str, Any]):
        """Broadcast status to HUD broadcaster"""
        try:
            from src.monitoring.hud_broadcaster import get_hud_broadcaster
            broadcaster = get_hud_broadcaster()
            broadcaster.update(data)
        except Exception:
            pass  # HUD is optional

    async def execute(
        self,
        command: str,
        on_narration: Optional[Callable] = None
    ) -> str:
        """
        Execute a command autonomously.
        
        Aether:
        1. Announces what it will do
        2. Executes each sub-step
        3. Narrates after each step
        4. Asks next follow-up question at the end
        
        Args:
            command: Natural language command from user
            on_narration: Optional callback for each narration
            
        Returns:
            Final summary of what was done
        """
        task_id = f"god_{int(datetime.now().timestamp())}"
        task = GodModeTask(
            task_id=task_id,
            name=command[:50],
            command=command
        )
        self.active_tasks[task_id] = task
        self.status = GodModeStatus.THINKING

        self._broadcast_hud({
            "task_id": task_id,
            "status": "thinking",
            "command": command
        })

        try:
            # Detect what kind of autonomous task this is
            plan = self._plan_task(command)
            task.steps = plan

            self._broadcast_hud({"status": "executing", "total_steps": len(plan)})

            results = []
            for i, step in enumerate(plan):
                task.current_step = i + 1
                task.status = GodModeStatus.EXECUTING

                # Narrate before executing
                narration = step.get("narration_before", "")
                if narration:
                    self.narrate(narration)
                    if on_narration:
                        on_narration(narration)
                    task.narrations.append(narration)

                self._broadcast_hud({
                    "step": i + 1,
                    "total": len(plan),
                    "action": step.get("action"),
                    "narration": narration
                })

                # Execute the step
                try:
                    result = await self._execute_step(step)
                    results.append(result)

                    # Narrate after
                    narration_after = step.get("narration_after", "")
                    if narration_after:
                        self.narrate(narration_after)
                        task.narrations.append(narration_after)

                except Exception as e:
                    error_msg = f"Step mein problem aai, sir: {e}"
                    self.narrate(error_msg)
                    logger.error(f"Step {i+1} failed: {e}")
                    results.append({"error": str(e)})

            # Task complete - final narration
            task.status = GodModeStatus.COMPLETE
            summary = self._build_summary(command, results)
            task.result = summary

            self.narrate(summary)
            self._broadcast_hud({"status": "complete", "summary": summary})

            return summary

        except Exception as e:
            task.status = GodModeStatus.ERROR
            error_narration = f"God Mode mein error aaya, sir. {str(e)}"
            self.narrate(error_narration)
            logger.error(f"God Mode execution failed: {e}")
            return error_narration

        finally:
            self.status = GodModeStatus.IDLE

    def _plan_task(self, command: str) -> List[Dict[str, Any]]:
        """
        Plan a sequence of steps for the given command.
        Pattern matches to known workflows.
        """
        cmd_lower = command.lower()
        steps = []

        # === BurpSuite + Bug Bounty Hunt ===
        if any(k in cmd_lower for k in ["burpsuite", "burp suite", "bug hunt", "hackerone", "bug bounty"]):
            steps.extend(self._plan_bug_bounty(command))

        # === Web Search ===
        elif any(k in cmd_lower for k in ["search", "find", "dhundo", "dekho"]):
            query = re.sub(r"(search|find|dhundo|dekho)\s*(for\s*)?", "", cmd_lower).strip()
            steps.append({
                "action": "SEARCH",
                "args": query or command,
                "narration_before": f"Zaroor sir, '{query}' search kar raha hoon...",
                "narration_after": "Search complete. Results mil gaye. Kuch specific dhundhna hai?"
            })

        # === Open App ===
        elif any(k in cmd_lower for k in ["open", "launch", "start", "kholo"]):
            # Extract app name
            app_match = re.search(r"(?:open|launch|start|kholo)\s+(\w[\w\s]*)", cmd_lower)
            app = app_match.group(1).strip() if app_match else command
            steps.append({
                "action": "OPEN",
                "args": app,
                "narration_before": f"{app} open kar raha hoon, sir...",
                "narration_after": f"{app} launch ho gaya! Kya karna hai ab?"
            })

        # === Screen Analysis ===
        elif any(k in cmd_lower for k in ["dekho screen", "screen dekho", "look", "analyze screen"]):
            steps.append({
                "action": "LOOK",
                "args": command,
                "narration_before": "Screen analyze kar raha hoon, sir...",
                "narration_after": "Analysis ho gaya. Screen mein kya hai woh bata sakta hoon."
            })

        # === Default: Smart fallback ===
        else:
            steps.append({
                "action": "THINK",
                "args": command,
                "narration_before": f"Samajh raha hoon aapka command...",
                "narration_after": "Done."
            })

        return steps

    def _plan_bug_bounty(self, command: str) -> List[Dict[str, Any]]:
        """Plan full bug bounty hunting workflow"""
        cmd_lower = command.lower()

        steps = []

        # Step 1: Find target/program
        if "hackerone" in cmd_lower or "program" in cmd_lower:
            steps.append({
                "action": "HUNT_FIND_PROGRAM",
                "args": command,
                "narration_before": "HackerOne par best paying programs dhundh raha hoon, sir...",
                "narration_after": "Programs mil gaye! Ab best target select karta hoon..."
            })

        # Step 2: Setup BurpSuite
        if "burp" in cmd_lower or "setup" in cmd_lower or "scan" in cmd_lower:
            steps.append({
                "action": "SETUP_BURPSUITE",
                "args": "",
                "narration_before": "BurpSuite launch kar raha hoon, sir. Proxy aur intercept configure hoga...",
                "narration_after": "BurpSuite ready hai! Intercept ON hai. Requests capture ho rahi hain."
            })

        # Step 3: Start hunt
        steps.append({
            "action": "START_HUNT",
            "args": command,
            "narration_before": "Auto-hunt shuru kar raha hoon... vulnerabilities dhundhunga, sir.",
            "narration_after": "Hunt chal rahi hai. Koi bug mila toh seedha bolunga - BOSS BUG MILA!"
        })

        return steps

    async def _execute_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single planned step"""
        action = step.get("action", "").upper()
        args = step.get("args", "")

        if action == "OPEN":
            from src.features.automation import DesktopAutomation
            DesktopAutomation.open_app(args)
            return {"status": "success", "action": "OPEN", "app": args}

        elif action == "SEARCH":
            from src.features.browser import BrowserAutomation
            BrowserAutomation.search(args)
            return {"status": "success", "action": "SEARCH", "query": args}

        elif action == "LOOK":
            from src.features.vision import VisionSystem
            result = VisionSystem.analyze_screen(args)
            self.narrate(f"Screen mein dekha: {result[:150]}")
            return {"status": "success", "action": "LOOK", "result": result}

        elif action == "SETUP_BURPSUITE":
            from src.action.tasks.burpsuite_tasks import setup_burpsuite_and_scan
            url_match = re.search(r'https?://[^\s]+', args)
            target = url_match.group(0) if url_match else None

            async def _narrate_callback(progress):
                desc = progress.get("current_step_description", "")
                if desc and progress.get("status") == "step_start":
                    self.narrate(desc)

            success = await setup_burpsuite_and_scan(target, _narrate_callback)
            return {"status": "success" if success else "error", "action": "SETUP_BURPSUITE"}

        elif action == "HUNT_FIND_PROGRAM":
            # Use existing auto_hunter to find programs
            try:
                from src.bugbounty.pipeline import BugBountyPipeline
                pipeline = BugBountyPipeline()
                program = await pipeline.find_best_program()
                if program:
                    self.narrate(f"Achha program mila, sir: {program}. Is par hunt karun?")
                return {"status": "success", "program": program}
            except Exception as e:
                logger.error(f"Program search failed: {e}")
                return {"status": "error", "error": str(e)}

        elif action == "START_HUNT":
            try:
                from src.bugbounty.pipeline import BugBountyPipeline
                pipeline = BugBountyPipeline(narrate_callback=self.narrate)
                asyncio.create_task(pipeline.run_full_hunt(args))
                return {"status": "started", "action": "HUNT"}
            except Exception as e:
                logger.error(f"Hunt start failed: {e}")
                return {"status": "error", "error": str(e)}

        elif action == "THINK":
            # Just log + narrate - no actual action
            await asyncio.sleep(0.5)
            return {"status": "thought", "input": args}

        return {"status": "unknown", "action": action}

    def _build_summary(self, command: str, results: List[Dict]) -> str:
        """Build a Jarvis-style completion summary"""
        success_count = sum(1 for r in results if r.get("status") in ("success", "started"))
        total = len(results)

        if success_count == total:
            return f"Sab complete ho gaya, sir! Sare {total} steps successfully execute hue. Ab batao kya karna hai?"
        elif success_count > 0:
            return f"Kuch kaam ho gaya sir, {success_count}/{total} steps complete. Baaki steps mein thodi problem aai. Manual check kar sakte hain?"
        else:
            return "Sir, task mein problem aai. Logs check karein ya dobara try karein?"

    def get_active_tasks(self) -> List[Dict]:
        return [
            {
                "task_id": t.task_id,
                "name": t.name,
                "status": t.status.value,
                "step": t.current_step,
                "total": len(t.steps)
            }
            for t in self.active_tasks.values()
            if t.status not in (GodModeStatus.COMPLETE, GodModeStatus.ERROR)
        ]

    def stop_all(self):
        """Emergency stop all tasks"""
        for task in self.active_tasks.values():
            task.status = GodModeStatus.ERROR
        self.narrate("Sab tasks stop kar diye, sir.")
        logger.warning("God Mode: All tasks stopped")


# Global instance
_god_mode_agent: Optional[GodModeAgent] = None


def get_god_mode_agent() -> GodModeAgent:
    """Get or create the global God Mode agent"""
    global _god_mode_agent
    if _god_mode_agent is None:
        _god_mode_agent = GodModeAgent()
    return _god_mode_agent


logger.info("🔥 God Mode Agent module loaded - MAXIMUM POWER READY")
