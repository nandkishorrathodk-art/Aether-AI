"""Voice Command Controller - Natural Language Command Interpreter

This module processes natural language voice commands and executes appropriate actions.
It integrates with all Aether AI features through a unified command interface.
"""

import re
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from src.utils.logger import get_logger
from src.cognitive.llm.model_loader import ModelLoader
from src.cognitive.llm.inference import ConversationEngine
from src.action.automation.command_registry import CommandRegistry

logger = get_logger(__name__)


@dataclass
class VoiceCommand:
    """Represents a parsed voice command"""
    intent: str
    action: str
    parameters: Dict[str, Any]
    confidence: float
    raw_text: str


class VoiceCommandController:
    """
    Natural language voice command controller
    
    Processes voice input and maps it to system actions:
    - Chat/conversation commands
    - System automation (open apps, files, etc.)
    - Settings management
    - Task creation and execution
    - Memory operations
    - Bug bounty operations
    
    Examples:
    - "Open Chrome" -> Opens Google Chrome
    - "What's the weather?" -> Conversation with AI
    - "Remember to buy milk" -> Stores in memory
    - "Create a task to backup files" -> Creates automation task
    - "Change voice to male" -> Updates TTS settings
    - "Start bug bounty scan on example.com" -> Initiates security scan
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.command_registry = CommandRegistry()
        self.conversation_engine = ConversationEngine()
        
        # Command patterns (intent, regex pattern, action function)
        self.command_patterns = self._initialize_patterns()
        
        # Statistics
        self.stats = {
            "total_commands": 0,
            "successful": 0,
            "failed": 0,
            "by_intent": {}
        }
        
        self.logger.info("Voice Command Controller initialized")
    
    def _initialize_patterns(self) -> List[Dict[str, Any]]:
        """Initialize command patterns for intent classification"""
        
        return [
            # System Commands
            {
                "intent": "open_application",
                "patterns": [
                    r"(?:open|launch|start|run)\s+(.+)",
                    r"(?:can you |please )?open (.+)",
                ],
                "handler": self._handle_open_app
            },
            {
                "intent": "close_application",
                "patterns": [
                    r"close\s+(.+)",
                    r"(?:quit|exit)\s+(.+)"
                ],
                "handler": self._handle_close_app
            },
            {
                "intent": "system_info",
                "patterns": [
                    r"(?:what's|what is|show|tell me)\s+(?:the\s+)?(?:system|computer|pc|laptop)\s+(?:info|information|status|details)",
                    r"system\s+(?:info|status)"
                ],
                "handler": self._handle_system_info
            },
            
            # File Operations
            {
                "intent": "create_file",
                "patterns": [
                    r"create\s+(?:a\s+)?file\s+(?:named\s+)?(.+)",
                    r"make\s+(?:a\s+)?file\s+(.+)"
                ],
                "handler": self._handle_create_file
            },
            {
                "intent": "read_file",
                "patterns": [
                    r"read\s+(?:the\s+)?file\s+(.+)",
                    r"show\s+(?:me\s+)?(?:the\s+)?file\s+(.+)",
                    r"open\s+file\s+(.+)"
                ],
                "handler": self._handle_read_file
            },
            {
                "intent": "list_files",
                "patterns": [
                    r"list\s+files(?:\s+in\s+(.+))?",
                    r"show\s+(?:me\s+)?files(?:\s+in\s+(.+))?",
                    r"what\s+files\s+are\s+(?:in|there)"
                ],
                "handler": self._handle_list_files
            },
            
            # Memory Commands
            {
                "intent": "remember",
                "patterns": [
                    r"remember\s+(?:that\s+)?(.+)",
                    r"(?:save|store)\s+(?:this\s+)?(?:to\s+memory\s+)?:?\s*(.+)",
                    r"don't\s+forget\s+(.+)"
                ],
                "handler": self._handle_remember
            },
            {
                "intent": "recall",
                "patterns": [
                    r"(?:what|do you)\s+(?:do you\s+)?(?:know|remember)\s+about\s+(.+)",
                    r"recall\s+(.+)",
                    r"tell\s+me\s+about\s+(.+)"
                ],
                "handler": self._handle_recall
            },
            
            # Settings Commands
            {
                "intent": "change_voice",
                "patterns": [
                    r"change\s+voice\s+to\s+(male|female|neutral)",
                    r"use\s+(male|female|neutral)\s+voice",
                    r"switch\s+to\s+(male|female|neutral)\s+voice"
                ],
                "handler": self._handle_change_voice
            },
            {
                "intent": "adjust_volume",
                "patterns": [
                    r"(?:set|adjust|change)\s+volume\s+to\s+(\d+)",
                    r"volume\s+(\d+)"
                ],
                "handler": self._handle_adjust_volume
            },
            
            # Task Commands
            {
                "intent": "create_task",
                "patterns": [
                    r"create\s+(?:a\s+)?task\s+(?:to\s+)?(.+)",
                    r"add\s+(?:a\s+)?task\s+(.+)",
                    r"remind\s+me\s+to\s+(.+)"
                ],
                "handler": self._handle_create_task
            },
            {
                "intent": "list_tasks",
                "patterns": [
                    r"(?:list|show|what)\s+(?:are\s+)?(?:my\s+)?tasks",
                    r"show\s+me\s+my\s+tasks"
                ],
                "handler": self._handle_list_tasks
            },
            
            # Chat/Conversation (default fallback)
            {
                "intent": "conversation",
                "patterns": [r".*"],  # Catch-all
                "handler": self._handle_conversation
            }
        ]
    
    async def process_command(self, text: str, session_id: str = "default") -> Dict[str, Any]:
        """
        Process a voice command and execute the appropriate action
        
        Args:
            text: Voice command text
            session_id: Conversation session ID
            
        Returns:
            Result dictionary with status, response, and metadata
        """
        self.stats["total_commands"] += 1
        text = text.strip().lower()
        
        self.logger.info(f"Processing command: '{text}'")
        
        try:
            # Parse command to determine intent
            command = self._parse_command(text)
            
            # Update stats
            intent = command.intent
            self.stats["by_intent"][intent] = self.stats["by_intent"].get(intent, 0) + 1
            
            # Execute command handler
            result = await command.parameters["handler"](
                text=text,
                parameters=command.parameters,
                session_id=session_id
            )
            
            self.stats["successful"] += 1
            
            return {
                "status": "success",
                "intent": intent,
                "action": command.action,
                "response": result.get("response", ""),
                "data": result.get("data"),
                "confidence": command.confidence
            }
            
        except Exception as e:
            self.stats["failed"] += 1
            self.logger.error(f"Error processing command: {e}", exc_info=True)
            
            return {
                "status": "error",
                "response": f"Sorry, I encountered an error: {str(e)}",
                "error": str(e)
            }
    
    def _parse_command(self, text: str) -> VoiceCommand:
        """Parse text into a structured voice command"""
        
        # Try each pattern
        for pattern_group in self.command_patterns:
            for pattern in pattern_group["patterns"]:
                match = re.match(pattern, text, re.IGNORECASE)
                if match:
                    parameters = {
                        "groups": match.groups(),
                        "handler": pattern_group["handler"]
                    }
                    
                    return VoiceCommand(
                        intent=pattern_group["intent"],
                        action=pattern_group["intent"],
                        parameters=parameters,
                        confidence=0.9 if match.group(0) == text else 0.7,
                        raw_text=text
                    )
        
        # Default to conversation if no pattern matched
        return VoiceCommand(
            intent="conversation",
            action="chat",
            parameters={"handler": self._handle_conversation},
            confidence=0.5,
            raw_text=text
        )
    
    # Command Handlers
    
    async def _handle_open_app(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Open an application"""
        app_name = parameters["groups"][0] if parameters["groups"] else "notepad"
        
        try:
            result = self.command_registry.execute("open", {"application": app_name})
            return {
                "response": f"Opening {app_name}",
                "data": result
            }
        except Exception as e:
            return {"response": f"Sorry, I couldn't open {app_name}: {str(e)}"}
    
    async def _handle_close_app(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Close an application"""
        app_name = parameters["groups"][0] if parameters["groups"] else ""
        
        try:
            result = self.command_registry.execute("close", {"application": app_name})
            return {
                "response": f"Closing {app_name}",
                "data": result
            }
        except Exception as e:
            return {"response": f"Sorry, I couldn't close {app_name}: {str(e)}"}
    
    async def _handle_system_info(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Get system information"""
        try:
            result = self.command_registry.execute("system_info")
            info = result["result"]
            
            response = f"System: {info['os']}, CPU: {info['cpu']['percent']}% usage, " \
                      f"Memory: {info['memory']['percent']}% used"
            
            return {
                "response": response,
                "data": info
            }
        except Exception as e:
            return {"response": f"Sorry, I couldn't get system info: {str(e)}"}
    
    async def _handle_create_file(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Create a file"""
        filename = parameters["groups"][0] if parameters["groups"] else "newfile.txt"
        
        try:
            result = self.command_registry.execute("create_file", {
                "path": filename,
                "content": ""
            })
            return {
                "response": f"Created file {filename}",
                "data": result
            }
        except Exception as e:
            return {"response": f"Sorry, I couldn't create the file: {str(e)}"}
    
    async def _handle_read_file(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Read a file"""
        filename = parameters["groups"][0] if parameters["groups"] else ""
        
        try:
            result = self.command_registry.execute("read_file", {"path": filename})
            content = result["result"]
            
            # Truncate if too long
            if len(content) > 200:
                content = content[:200] + "..."
            
            return {
                "response": f"File content: {content}",
                "data": result
            }
        except Exception as e:
            return {"response": f"Sorry, I couldn't read the file: {str(e)}"}
    
    async def _handle_list_files(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """List files in directory"""
        directory = parameters["groups"][0] if parameters["groups"] and parameters["groups"][0] else "."
        
        try:
            result = self.command_registry.execute("list_files", {"directory": directory})
            files = result["result"]
            
            response = f"Found {len(files)} files: {', '.join(files[:5])}"
            if len(files) > 5:
                response += f" and {len(files) - 5} more"
            
            return {
                "response": response,
                "data": {"files": files}
            }
        except Exception as e:
            return {"response": f"Sorry, I couldn't list files: {str(e)}"}
    
    async def _handle_remember(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Store information in memory"""
        content = parameters["groups"][0] if parameters["groups"] else text
        
        # In a real implementation, this would call the memory API
        # For now, we'll simulate it
        return {
            "response": f"Okay, I'll remember that: {content}",
            "data": {"stored": content}
        }
    
    async def _handle_recall(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Recall information from memory"""
        query = parameters["groups"][0] if parameters["groups"] else text
        
        # In a real implementation, this would query the memory API
        return {
            "response": f"Let me search my memory about {query}...",
            "data": {"query": query}
        }
    
    async def _handle_change_voice(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Change TTS voice"""
        voice_gender = parameters["groups"][0] if parameters["groups"] else "female"
        
        return {
            "response": f"Switching to {voice_gender} voice",
            "data": {"voice": voice_gender}
        }
    
    async def _handle_adjust_volume(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Adjust volume"""
        volume = int(parameters["groups"][0]) if parameters["groups"] else 50
        volume = max(0, min(100, volume))  # Clamp to 0-100
        
        return {
            "response": f"Setting volume to {volume}%",
            "data": {"volume": volume}
        }
    
    async def _handle_create_task(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Create a task"""
        task_description = parameters["groups"][0] if parameters["groups"] else text
        
        return {
            "response": f"Created task: {task_description}",
            "data": {"task": task_description}
        }
    
    async def _handle_list_tasks(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """List tasks"""
        # In real implementation, would call tasks API
        return {
            "response": "You have no pending tasks",
            "data": {"tasks": []}
        }
    
    async def _handle_conversation(self, text: str, parameters: Dict, session_id: str) -> Dict:
        """Handle general conversation"""
        try:
            # Use conversation engine for natural dialogue
            from src.cognitive.llm.inference import ConversationRequest
            
            request = ConversationRequest(
                user_input=text,
                session_id=session_id
            )
            
            result = await self.conversation_engine.process_conversation(request)
            
            return {
                "response": result.content,
                "data": {
                    "intent": result.intent.value,
                    "session_id": result.session_id,
                    "metadata": result.metadata
                }
            }
        except Exception as e:
            self.logger.error(f"Conversation error: {e}")
            return {
                "response": "I'm having trouble understanding. Could you rephrase that?",
                "data": {}
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get command processing statistics"""
        return self.stats.copy()
    
    def get_supported_commands(self) -> List[Dict[str, str]]:
        """Get list of supported command types"""
        return [
            {
                "intent": pattern["intent"],
                "examples": [p.replace(r"(.+)", "<parameter>").replace(r"(\d+)", "<number>") 
                           for p in pattern["patterns"][:2]]
            }
            for pattern in self.command_patterns
            if pattern["intent"] != "conversation"
        ]
