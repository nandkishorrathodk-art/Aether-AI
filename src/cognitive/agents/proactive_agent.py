"""
Proactive Agent (The BIG Upgrade)

Aether ko har bar user se poochna nahi padega.
Yeh background loop:
1. Every 30 seconds — system context check karta hai
2. Kya chal raha hai dekh ke — KHUD decide karta hai kya karna hai
3. Task identify karta hai aur BINA POOCHE execute karta hai
4. Important events par narrate karta hai

Scenarios handled:
- BurpSuite khula hai + intercept ON → auto-find HackerOne program
- Koi scan chal raha hai → progress narrate karo
- User ne kuch bol diya pehle → memory se context lo, next step do
- Agar user ne 5 min se kuch nahi kaha → suggest karo silently
"""

import asyncio
import logging
import threading
import time
from typing import Optional, List, Dict, Callable
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class SituationContext(Enum):
    """What situation is Aether currently in?"""
    IDLE              = "idle"             # Nothing happening
    BURPSUITE_OPEN    = "burpsuite_open"   # BurpSuite running
    SCAN_RUNNING      = "scan_running"     # Active scan in progress
    BUG_FOUND         = "bug_found"        # Vulnerability detected
    USER_ACTIVE       = "user_active"      # User recently interacted
    HUNT_MODE         = "hunt_mode"        # Full autonomous hunt running


class ProactiveAgent:
    """
    The brain that makes Aether truly autonomous.
    
    Runs a background loop every N seconds.
    Detects what's happening, decides next action, executes it.
    User does NOT need to say anything.
    
    Example flow:
    1. BurpSuite detected running
    2. → ProactiveAgent notices, loads last conversation context
    3. → "BurpSuite open ho gaya. HackerOne program select kar leta hoon..."
    4. → Auto-starts program analysis + target selection
    5. → If target found: "Sir, testphp.vulnweb.com achha target lag raha hai. Scan shuru karta hoon"
    6. → Starts scan WITHOUT asking user
    """

    def __init__(self, check_interval_seconds: int = 30):
        self.interval = check_interval_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pipeline = None
        self._last_action_time: Optional[datetime] = None
        self._situation: SituationContext = SituationContext.IDLE
        self._active_hunt_target: Optional[str] = None
        self._auto_next_enabled: bool = True   # Master switch
        self._last_conversation: List[Dict] = []
        self._completed_auto_steps: List[str] = []
        self._last_situation_report = ""

        logger.info("🤖 Proactive Agent initialized - DYNAMIC REASONING READY")

    # ── Lifecycle ──────────────────────────────────────────────────────────────
    def start(self):
        """Start background autonomy loop"""
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ProactiveAgent")
        self._thread.start()
        logger.info("🤖 Proactive Agent started - running autonomously")
        self._narrate("Autonomous mode active, sir. Main khud context samajhunga aur actions lunga.")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("🤖 Proactive Agent stopped")

    def disable_auto_next(self):
        """User can say 'stop automatic' to pause autonomy"""
        self._auto_next_enabled = False
        self._narrate("Samajh gaya sir, manual mode mein aa gaya hoon. Aap bolenge tab karunga.")

    def enable_auto_next(self):
        """Resume full autonomy"""
        self._auto_next_enabled = True
        self._narrate("Autonomous mode back ON, sir!")

    # ── Main loop ──────────────────────────────────────────────────────────────
    def _loop(self):
        """Background check every N seconds"""
        while not self._stop.is_set():
            try:
                asyncio.run(self._tick())
            except Exception as e:
                logger.error(f"ProactiveAgent tick error: {e}")
            time.sleep(self.interval)

    async def _tick(self):
        """Single autonomy cycle"""
        if not self._auto_next_enabled:
            return

        # 1. Read current system situation
        situation = await self._detect_situation()
        # The _situation attribute is now less relevant as decision is LLM-driven
        # self._situation = situation 

        # 2. Decide and execute next intelligent action
        await self._decide_and_act(situation)

    # ── Context Detection ──────────────────────────────────────────────────────
    async def _detect_situation(self) -> Dict[str, Any]:
        """
        Detects granular context: Active window, Vision OCR, Scans, etc.
        Returns a dictionary for the LLM to reason over.
        """
        context = {
            "timestamp": datetime.now().isoformat(),
            "active_window": "Unknown",
            "vision_text": "",
            "recent_topic": await self._get_last_conversation_topic(),
            "active_hunt": self._active_hunt_target
        }

        # 1. Get Active Window Title
        try:
            from src.perception.vision.realtime_vision import get_realtime_vision
            vision = get_realtime_vision()
            context["active_window"] = vision.get_active_window_context()
        except: pass

        # 2. Check for BurpSuite/Tools running
        context["burpsuite_running"] = await self._is_burpsuite_running()

        return context

    async def _is_burpsuite_running(self) -> bool:
        """Check if BurpSuite process is running"""
        try:
            import psutil
            for proc in psutil.process_iter(['name', 'cmdline']):
                name = (proc.info.get('name') or '').lower()
                if 'burp' in name or 'burpsuite' in name:
                    return True
        except Exception:
            pass
        return False

    async def _get_last_conversation_topic(self) -> Optional[str]:
        """Retrieve last conversation topic from memory"""
        try:
            from src.cognitive.memory.persistent_memory import get_memory_manager
            memories = get_memory_manager().recall("recent conversation task", limit=1)
            if memories:
                return memories[0].get("content", "")
        except Exception:
            pass
        return None

    # ── Decision Engine ────────────────────────────────────────────────────────
    async def _decide_and_act(self, context: Dict[str, Any]):
        """
        DYNAMIC REASONING: Feed context to LLM and let it decide next step.
        """
        # Detect if something critical is happening
        aw = context["active_window"].lower()
        
        # Fallback to smart heuristics if LLM check is too expensive for 30s loop
        # But for 'Tier 6', we want LLM reasoning.
        
        # For now, let's implement a 'Smart Evaluator' that uses inference.py
        current_report = f"User is on: {aw}. "
        if context["burpsuite_running"]: current_report += "BurpSuite is open. "
        
        if current_report == self._last_situation_report:
            return # No change in context
        
        self._last_situation_report = current_report
        
        # PROACTIVE LLM CALL
        try:
            from src.cognitive.llm.inference import conversation_engine, ConversationRequest
            
            prompt = (
                f"SYSTEM: You are Aether's Proactive Brain. "
                f"Current Context: {current_report}. "
                f"Recent Topic: {context['recent_topic']}. "
                f"Based on this, should Aether say or do something autonomously? "
                f"If YES, respond with the action/speech. If NO, respond exactly with 'IGNORE'."
            )
            
            req = ConversationRequest(user_input=prompt, session_id="proactive_loop")
            response = await conversation_engine.process_conversation(req)
            
            if response and "IGNORE" not in response.upper():
                self._narrate(response)
                # If the response contains a tool call, the conversation_engine handles execution
        except Exception as e:
            logger.debug(f"Proactive LLM reasoning failed: {e}")

    # ── Autonomous Actions ─────────────────────────────────────────────────────
    async def _auto_start_hunt_for_burpsuite(self):
        """
        BurpSuite is open → automatically find a good bug bounty target
        and start the scan without user asking.
        """
        self._narrate(
            "BurpSuite detect kiya, sir. "
            "HackerOne se ek achha program dhundh ke scan shuru karta hoon..."
        )

        try:
            from src.bugbounty.pipeline import BugBountyPipeline
            bb_pipeline = BugBountyPipeline(narrate_callback=self._narrate)

            program = await bb_pipeline.find_best_program()
            if program:
                # Auto-start scan without asking
                self._active_hunt_target = program
                self._narrate(
                    f"Milgaya sir — {program}! "
                    f"Scan shuru kar raha hoon. Aap kuch aur karo, main kar lunga ye."
                )
                asyncio.create_task(bb_pipeline.run_full_hunt(program))
            else:
                self._narrate(
                    "Sir, koi perfect HackerOne program nahi mila. "
                    "Aap ek target URL bolo, main seedha scan shuru kar deta hoon."
                )

        except Exception as e:
            logger.error(f"Auto hunt start failed: {e}")

    async def _auto_monitor_scan(self):
        """Monitor ongoing scan and narrate any findings without user asking"""
        try:
            from src.bugbounty.burp_controller import BurpController
            burp = BurpController()
            if not burp.is_burp_running():
                self._active_hunt_target = None
                return

            # Encourage during long scans every few minutes
            self._narrate(
                "Scan chal raha hai, sir. Koi bug mila toh seedha bolunga. "
                "Aap kuch aur karo meanwhile."
            )

        except Exception as e:
            logger.error(f"Scan monitoring failed: {e}")

    async def _auto_continue_hunt(self):
        """Continue hunt autonomously — pick next target if current done"""
        try:
            from src.bugbounty.pipeline import BugBountyPipeline
            bb = BugBountyPipeline(narrate_callback=self._narrate)

            self._narrate(
                "Hunt chal rahi hai, sir. Next target check kar raha hoon automatically..."
            )
            program = await bb.find_best_program()
            if program and program != self._active_hunt_target:
                self._active_hunt_target = program
                self._narrate(f"Naya target: {program}! Scan shuru...")
                asyncio.create_task(bb.run_full_hunt(program))
        except Exception as e:
            logger.error(f"Auto continue hunt failed: {e}")

    async def _proactive_suggestion(self):
        """Proactively suggest something useful after user has been quiet"""
        try:
            topic = await self._get_last_conversation_topic()
            if topic and "burp" in topic.lower():
                self._narrate(
                    "Sir, aap kuch der se quiet hain. "
                    "Pehle BurpSuite ki baat kar rahe the — "
                    "chahte hain main ek HackerOne program scan start kar dun?"
                )
            elif topic and "bug" in topic.lower():
                self._narrate(
                    "Sir, ek nayi vulnerability report generate kar dun "
                    "jo pehle mili thi? Ya naya program select karein?"
                )
            else:
                # Generic proactive check
                self._narrate(
                    "Sir, koi kaam chahiye? "
                    "Bug bounty hunt shuru karun, ya kuch aur help karun?"
                )
        except Exception as e:
            logger.debug(f"Proactive suggestion failed: {e}")

    # ── Called by inference.py to track last user action ──────────────────────
    def on_user_message(self, message: str):
        """Call this whenever user sends a message"""
        self._last_action_time = datetime.now()
        self._last_conversation.append({
            "role": "user",
            "content": message,
            "time": datetime.now().isoformat()
        })
        # Keep last 10 messages
        self._last_conversation = self._last_conversation[-10:]

    def on_task_complete(self, task_name: str, result: str):
        """Call this when any task finishes — Aether decides next step auto"""
        logger.info(f"Task complete: {task_name}")
        if self._auto_next_enabled:
            asyncio.create_task(self._decide_next_after_complete(task_name, result))

    async def _decide_next_after_complete(self, task_name: str, result: str):
        """After a task finishes, automatically decide the NEXT logical step"""
        task_lower = task_name.lower()

        if "burpsuite" in task_lower or "setup" in task_lower:
            self._narrate(
                "BurpSuite ready hai, sir! "
                "Ab HackerOne pe ek program dhundh ke target select karta hoon automatically..."
            )
            await asyncio.sleep(2)
            await self._auto_start_hunt_for_burpsuite()

        elif "program" in task_lower or "find" in task_lower:
            if self._active_hunt_target:
                self._narrate(
                    f"Program mil gaya — ab seedha {self._active_hunt_target} "
                    "par scan shuru karta hoon, sir..."
                )

        elif "scan" in task_lower:
            self._narrate(
                "Scan khatam hua. Results analyze kar raha hoon, sir. "
                "Koi bug mila toh report automatically generate karunga."
            )

        elif "bug" in task_lower or "vulnerability" in task_lower:
            self._narrate(
                "Bug confirm hua! PoC aur HackerOne report generate kar raha hoon — "
                "aapko kuch karna nahi, sir."
            )

    # ── Helpers ────────────────────────────────────────────────────────────────
    def _narrate(self, text: str):
        try:
            if self._pipeline is None:
                from src.pipeline.voice_pipeline import get_pipeline
                self._pipeline = get_pipeline()
            if self._pipeline and hasattr(self._pipeline, 'narrate'):
                self._pipeline.narrate(text)
            else:
                logger.info(f"[PROACTIVE NARRATION] {text}")
        except Exception:
            logger.info(f"[PROACTIVE NARRATION] {text}")


# ── Global singleton ──────────────────────────────────────────────────────────
_proactive_agent: Optional[ProactiveAgent] = None


def get_proactive_agent() -> ProactiveAgent:
    global _proactive_agent
    if _proactive_agent is None:
        _proactive_agent = ProactiveAgent(check_interval_seconds=30)
    return _proactive_agent


def start_autonomous_mode():
    """Call this at app startup to enable full autonomy"""
    agent = get_proactive_agent()
    agent.start()
    return agent


logger.info("🤖 Proactive Agent module loaded - TRUE AUTONOMY READY")
