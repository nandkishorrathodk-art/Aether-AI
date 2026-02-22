"""
Live Voice-First Assistant - True Human-like Multitasking

Works like a real human assistant:
- Talks while working (not just results)
- Opens browser, plays YouTube, teaches code
- Conversational task control ("pause that scan")
- No typing needed - 100% voice driven

Example:
    You: "Hey Aether, teach me Python functions"
    AI: "Sure boss! Let me open VS Code... [opens] Now dekho, functions..."
    [While teaching, you interrupt]
    You: "Play some music first"
    AI: "Of course! Playing your favorite playlist... [opens YouTube, plays]
         Now, where were we? Ah yes, Python functions..."
"""

import asyncio
import threading
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime
from queue import Queue
import webbrowser
import subprocess
import os

from src.pipeline.voice_pipeline import VoicePipelineOrchestrator, PipelineConfig
from src.automation.browser_controller import BrowserController
from src.control.pc_controller import PCController
from src.bugbounty.voice_notifier import BugBountyVoiceNotifier
from src.autonomous.autonomous_brain import AutonomousBrain
from src.cognitive.llm.llm_wrapper import LLMInference
from src.utils.logger import get_logger
from src.security.nuclei_scanner import get_nuclei_scanner
from src.security.cve_database import get_cve_database

logger = get_logger(__name__)


@dataclass
class Task:
    """Represents a background task"""
    id: str
    name: str
    description: str
    status: str  # "running", "paused", "completed", "failed"
    progress: float  # 0.0 to 1.0
    started_at: datetime
    last_update: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "status": self.status,
            "progress": self.progress * 100,
            "started_at": self.started_at.isoformat(),
            "last_update": self.last_update
        }


class LiveVoiceAssistant:
    """
    Live Voice-First Assistant - The ULTIMATE Jarvis/Friday
    
    Capabilities:
    1. Voice-first multitasking (talks while working)
    2. Desktop automation (browser, apps, YouTube)
    3. Teaching mode (interactive code lessons)
    4. Conversational task control
    5. Bug bounty hunting (security scans)
    6. Real-time progress updates
    """
    
    def __init__(self):
        """Initialize live assistant"""
        self.voice_pipeline = VoicePipelineOrchestrator(PipelineConfig(
            wake_word="hey aether",
            tts_provider="edge",  # Natural voice
            enable_continuous_mode=True
        ))
        
        self.voice_notifier = BugBountyVoiceNotifier(
            enable_voice=True,
            personality="friendly"  # Hinglish personality
        )
        
        self.browser = BrowserController(headless=False)
        self.pc_controller = PCController()
        self.autonomous_brain = AutonomousBrain()
        self.llm = LLMInference()
        
        # Task management
        self.active_tasks: Dict[str, Task] = {}
        self.task_queue = Queue()
        self.task_executor_running = False
        
        # Voice callbacks
        self.voice_updates_enabled = True
        
        logger.info("🎙️ Live Voice Assistant initialized - 100% voice-first!")
    
    async def start(self):
        """Start the live assistant"""
        logger.info("🚀 Starting Live Voice Assistant...")
        
        # Start voice pipeline
        await self.voice_pipeline.start()
        
        # Start task executor in background
        self.task_executor_running = True
        threading.Thread(target=self._task_executor_loop, daemon=True).start()
        
        # Start browser
        await self.browser.start()
        
        await self.speak("Ji boss! Aether ready hai. Koi bhi kaam batao!")
        
        logger.info("✅ Live Assistant started - Ready for voice commands!")
    
    async def speak(self, text: str, interrupt: bool = False):
        """
        Speak text with natural voice
        
        Args:
            text: Text to speak
            interrupt: Interrupt current speech
        """
        if not self.voice_updates_enabled:
            return
        
        try:
            await self.voice_notifier._speak_async(text)
        except Exception as e:
            logger.error(f"Speech error: {e}")
    
    async def process_voice_command(self, command: str) -> Dict[str, Any]:
        """
        Process voice command with live execution
        
        Handles:
        - Desktop actions (open browser, play YouTube)
        - Teaching requests (explain Python, debug code)
        - Bug bounty tasks (scan target, find CVEs)
        - Task control (pause, resume, status)
        """
        command_lower = command.lower()
        
        # === Desktop Actions ===
        if "open" in command_lower and ("browser" in command_lower or "chrome" in command_lower):
            return await self._handle_open_browser(command)
        
        if "play" in command_lower and ("youtube" in command_lower or "music" in command_lower or "song" in command_lower):
            return await self._handle_play_youtube(command)
        
        if "search" in command_lower:
            return await self._handle_search(command)
        
        # === Teaching Mode ===
        if "teach" in command_lower or "explain" in command_lower or "show me" in command_lower:
            return await self._handle_teaching(command)
        
        if "debug" in command_lower or "fix" in command_lower:
            return await self._handle_debug_code(command)
        
        # === Bug Bounty ===
        if "scan" in command_lower or "find vulnerabilities" in command_lower:
            return await self._handle_security_scan(command)
        
        if "cve" in command_lower or "vulnerability" in command_lower:
            return await self._handle_cve_search(command)
        
        # === Task Control ===
        if "pause" in command_lower:
            return await self._handle_pause_task(command)
        
        if "resume" in command_lower or "continue" in command_lower:
            return await self._handle_resume_task(command)
        
        if "status" in command_lower or "progress" in command_lower:
            return await self._handle_task_status(command)
        
        # === General Conversation ===
        return await self._handle_general_query(command)
    
    # ===== Desktop Actions =====
    
    async def _handle_open_browser(self, command: str) -> Dict:
        """Open browser with live commentary"""
        await self.speak("Ji boss! Browser khol raha hoon...")
        
        try:
            # Open browser if not already open
            if not self.browser.is_running:
                await self.browser.start()
            
            # Extract URL if mentioned
            if "google.com" in command.lower():
                url = "https://google.com"
            elif "youtube.com" in command.lower():
                url = "https://youtube.com"
            else:
                url = "https://google.com"
            
            await self.browser.navigate(url)
            await self.speak(f"Browser open ho gaya boss! {url} par hoon.")
            
            return {"success": True, "action": "browser_opened", "url": url}
        
        except Exception as e:
            await self.speak(f"Sorry boss, browser open karne mein problem aa gayi: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _handle_play_youtube(self, command: str) -> Dict:
        """Play YouTube with live commentary"""
        try:
            # Extract song/video name from command
            song_query = self._extract_song_query(command)
            
            await self.speak(f"Boss! '{song_query}' play kar raha hoon... ek second...")
            
            # Open YouTube search
            search_url = f"https://www.youtube.com/results?search_query={song_query.replace(' ', '+')}"
            
            if not self.browser.is_running:
                await self.browser.start()
            
            await self.browser.navigate(search_url)
            
            # Wait for search results
            await asyncio.sleep(2)
            
            # Click first video (using Playwright)
            try:
                await self.browser.page.click('a#video-title', timeout=5000)
                await self.speak(f"Enjoy boss! '{song_query}' chal raha hai!")
                
                return {
                    "success": True,
                    "action": "youtube_playing",
                    "query": song_query
                }
            except:
                # Fallback: open in new tab
                webbrowser.open(search_url)
                await self.speak("Browser mein YouTube khul gaya boss, first video click kar dijiye!")
                return {"success": True, "action": "youtube_opened", "query": song_query}
        
        except Exception as e:
            await self.speak(f"Sorry boss, YouTube problem aa rahi hai: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _extract_song_query(self, command: str) -> str:
        """Extract song name from voice command"""
        # Remove common phrases
        query = command.lower()
        for phrase in ["play", "youtube", "song", "music", "video", "search"]:
            query = query.replace(phrase, "")
        
        # Extract remaining text
        query = query.strip()
        
        # Default if empty
        if not query:
            query = "lofi hip hop"
        
        return query
    
    async def _handle_search(self, command: str) -> Dict:
        """Search Google with live commentary"""
        try:
            # Extract search query
            search_query = command.lower().replace("search", "").replace("google", "").strip()
            
            await self.speak(f"Boss! '{search_query}' search kar raha hoon...")
            
            search_url = f"https://www.google.com/search?q={search_query.replace(' ', '+')}"
            
            if not self.browser.is_running:
                await self.browser.start()
            
            await self.browser.navigate(search_url)
            await self.speak("Search results mil gaye boss!")
            
            return {"success": True, "action": "search", "query": search_query}
        
        except Exception as e:
            await self.speak(f"Search mein problem: {str(e)}")
            return {"success": False, "error": str(e)}
    
    # ===== Teaching Mode =====
    
    async def _handle_teaching(self, command: str) -> Dict:
        """Interactive teaching with live voice explanation"""
        try:
            # Extract topic from command
            topic = self._extract_teaching_topic(command)
            
            await self.speak(f"Boss! {topic} sikhata hoon... ek second...")
            
            # Open VS Code or text editor
            await self.speak("Pehle VS Code khol leta hoon...")
            try:
                subprocess.Popen(["code"])  # VS Code
                await asyncio.sleep(3)
            except:
                subprocess.Popen(["notepad.exe"])  # Fallback to Notepad
            
            # Generate teaching content with LLM
            teaching_prompt = f"""
            Explain {topic} to a beginner in simple Hindi-English mix.
            Include:
            1. Simple definition
            2. Example code
            3. Common mistakes
            
            Keep it short (5 minutes max).
            """
            
            explanation = await self.llm.generate(teaching_prompt)
            
            # Speak explanation in chunks (so user can follow along)
            paragraphs = explanation.split("\n\n")
            
            for i, para in enumerate(paragraphs):
                if not para.strip():
                    continue
                
                await self.speak(para)
                
                # Pause between sections
                if i < len(paragraphs) - 1:
                    await asyncio.sleep(2)
            
            await self.speak("Samajh aa gaya boss? Koi doubt ho to batao!")
            
            return {
                "success": True,
                "action": "teaching",
                "topic": topic,
                "explanation": explanation
            }
        
        except Exception as e:
            await self.speak(f"Teaching mein problem: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _extract_teaching_topic(self, command: str) -> str:
        """Extract teaching topic from command"""
        # Remove common phrases
        topic = command.lower()
        for phrase in ["teach", "me", "explain", "show", "how", "to"]:
            topic = topic.replace(phrase, "")
        
        topic = topic.strip()
        
        if not topic:
            topic = "Python basics"
        
        return topic
    
    async def _handle_debug_code(self, command: str) -> Dict:
        """Debug code with live voice explanation"""
        await self.speak("Boss! Code debugging kar raha hoon... file path batao ya paste karo...")
        
        # This would integrate with clipboard or file picker
        # For now, acknowledge the request
        return {
            "success": True,
            "action": "debug_ready",
            "message": "Debug mode activated - waiting for code"
        }
    
    # ===== Bug Bounty =====
    
    async def _handle_security_scan(self, command: str) -> Dict:
        """Security scan with LIVE voice updates during scanning"""
        try:
            # Extract target from command
            target = self._extract_target(command)
            
            await self.speak(f"Boss! {target} ko scan kar raha hoon... Live updates milte rahenge!")
            
            # Create background task
            task_id = f"scan_{datetime.now().timestamp()}"
            task = Task(
                id=task_id,
                name="Security Scan",
                description=f"Scanning {target}",
                status="running",
                progress=0.0,
                started_at=datetime.now()
            )
            
            self.active_tasks[task_id] = task
            
            # Run scan in background with live updates
            asyncio.create_task(self._run_security_scan_with_updates(task, target))
            
            return {
                "success": True,
                "action": "scan_started",
                "task_id": task_id,
                "target": target
            }
        
        except Exception as e:
            await self.speak(f"Scan start karne mein problem: {str(e)}")
            return {"success": False, "error": str(e)}
    
    async def _run_security_scan_with_updates(self, task: Task, target: str):
        """Run security scan with LIVE voice updates"""
        try:
            scanner = await get_nuclei_scanner()
            
            # Check installation
            task.progress = 0.1
            task.last_update = "Checking Nuclei installation..."
            await self.speak("Nuclei scanner check kar raha hoon...")
            
            if not await scanner.check_installation():
                task.status = "failed"
                task.last_update = "Nuclei not installed"
                await self.speak("Boss! Nuclei install nahi hai. Install kar lo pehle.")
                return
            
            # Start scan
            task.progress = 0.3
            task.last_update = "Starting vulnerability scan..."
            await self.speak("Scan shuru ho gaya! Templates load ho rahe hain...")
            
            # Run scan
            result = await scanner.scan_target(
                target=target,
                severity=["critical", "high", "medium"],
                rate_limit=150
            )
            
            task.progress = 0.8
            
            # Analyze results
            vuln_count = result.get("vulnerabilities_found", 0)
            
            if vuln_count > 0:
                task.last_update = f"Found {vuln_count} vulnerabilities!"
                await self.speak(f"Boss! {vuln_count} vulnerabilities mile hain! Critical check kar raha hoon...")
                
                critical = [v for v in result.get("vulnerabilities", []) if v.get("severity") == "critical"]
                
                if critical:
                    await self.speak(f"CRITICAL ALERT! {len(critical)} critical vulnerabilities mile hain boss!")
            else:
                await self.speak("Scan complete ho gaya boss, koi vulnerability nahi mili.")
            
            task.progress = 1.0
            task.status = "completed"
            task.last_update = "Scan completed"
            
        except Exception as e:
            task.status = "failed"
            task.last_update = f"Error: {str(e)}"
            await self.speak(f"Scan mein error aa gaya boss: {str(e)}")
    
    def _extract_target(self, command: str) -> str:
        """Extract target URL from command"""
        words = command.split()
        for word in words:
            if "." in word and not word.endswith("."):
                # Looks like a domain
                if not word.startswith("http"):
                    return f"https://{word}"
                return word
        
        return "example.com"
    
    async def _handle_cve_search(self, command: str) -> Dict:
        """Search CVE database with voice"""
        try:
            # Extract CVE query
            query = command.lower().replace("cve", "").replace("vulnerability", "").strip()
            
            await self.speak(f"Boss! CVE database mein '{query}' search kar raha hoon...")
            
            cve_db = await get_cve_database()
            results = await cve_db.search(query, max_results=5)
            
            if results:
                await self.speak(f"{len(results)} CVEs mile hain boss! Details dikha raha hoon...")
                
                # Speak top result
                top = results[0]
                severity = top.get("severity", "UNKNOWN")
                await self.speak(f"Top result: {top.get('id')} - Severity {severity}")
            else:
                await self.speak("Koi CVE nahi mila boss.")
            
            return {"success": True, "action": "cve_search", "results": results}
        
        except Exception as e:
            await self.speak(f"CVE search mein problem: {str(e)}")
            return {"success": False, "error": str(e)}
    
    # ===== Task Control =====
    
    async def _handle_pause_task(self, command: str) -> Dict:
        """Pause running task"""
        if not self.active_tasks:
            await self.speak("Boss, koi task running nahi hai!")
            return {"success": False, "message": "No tasks running"}
        
        # Pause all running tasks
        for task in self.active_tasks.values():
            if task.status == "running":
                task.status = "paused"
        
        await self.speak("All tasks pause kar diye boss!")
        return {"success": True, "action": "tasks_paused"}
    
    async def _handle_resume_task(self, command: str) -> Dict:
        """Resume paused task"""
        resumed = 0
        for task in self.active_tasks.values():
            if task.status == "paused":
                task.status = "running"
                resumed += 1
        
        if resumed > 0:
            await self.speak(f"{resumed} tasks resume kar diye boss!")
            return {"success": True, "action": "tasks_resumed", "count": resumed}
        else:
            await self.speak("Koi paused task nahi hai boss!")
            return {"success": False, "message": "No paused tasks"}
    
    async def _handle_task_status(self, command: str) -> Dict:
        """Report status of all tasks"""
        if not self.active_tasks:
            await self.speak("Boss, koi task running nahi hai!")
            return {"success": False, "message": "No tasks"}
        
        status_report = []
        for task in self.active_tasks.values():
            await self.speak(
                f"{task.name}: {task.status}, {int(task.progress * 100)} percent complete"
            )
            status_report.append(task.to_dict())
        
        return {"success": True, "action": "task_status", "tasks": status_report}
    
    # ===== General Conversation =====
    
    async def _handle_general_query(self, command: str) -> Dict:
        """Handle general conversation"""
        try:
            response = await self.llm.generate(command)
            await self.speak(response)
            
            return {"success": True, "action": "conversation", "response": response}
        
        except Exception as e:
            await self.speak(f"Sorry boss, samajh nahi aaya: {str(e)}")
            return {"success": False, "error": str(e)}
    
    # ===== Task Executor =====
    
    def _task_executor_loop(self):
        """Background task executor (runs in thread)"""
        logger.info("Task executor started")
        
        while self.task_executor_running:
            try:
                # Process queued tasks
                if not self.task_queue.empty():
                    task_func = self.task_queue.get()
                    asyncio.run(task_func())
            except Exception as e:
                logger.error(f"Task executor error: {e}")
    
    async def stop(self):
        """Stop the live assistant"""
        await self.speak("Ruk raha hoon boss! Goodbye!")
        
        self.task_executor_running = False
        await self.voice_pipeline.stop()
        await self.browser.stop()
        
        logger.info("Live Assistant stopped")


# === Singleton Instance ===

_live_assistant_instance: Optional[LiveVoiceAssistant] = None


async def get_live_assistant() -> LiveVoiceAssistant:
    """Get singleton live assistant instance"""
    global _live_assistant_instance
    
    if _live_assistant_instance is None:
        _live_assistant_instance = LiveVoiceAssistant()
        await _live_assistant_instance.start()
    
    return _live_assistant_instance
