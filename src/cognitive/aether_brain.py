"""
Aether Brain - The Intelligence Core

This is THE BRAIN that makes Aether a true Jarvis-like agent:
- Long-term memory (Vector Store)
- Web search capability (Tavily)
- File operations
- Code execution
- LangChain agent orchestration
- Proactive thinking

Boss, yeh hai Aether ka asli dimag!
"""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
import asyncio

from src.cognitive.llm.llm_wrapper import LLMInference
from src.cognitive.memory.vector_store import get_vector_store, VectorStore
from src.cognitive.tools.tavily_search import get_tavily_search, TavilySearchTool
from src.cognitive.tools.file_system import get_file_system, FileSystemTool
from src.cognitive.tools.code_executor import get_code_executor, CodeExecutorTool

logger = logging.getLogger(__name__)


class AetherBrain:
    """
    The Jarvis-like intelligence core for Aether AI
    
    Features:
    - Remembers everything (vector store)
    - Can search the web
    - Can read/write files
    - Can write and execute code
    - Learns from interactions
    - Proactive suggestions
    
    Example:
        brain = AetherBrain()
        response = await brain.process("Find me the latest bug bounty news")
    """
    
    def __init__(
        self,
        user_name: str = "Boss",
        enable_memory: bool = True,
        enable_web_search: bool = True,
        enable_file_ops: bool = True,
        enable_code_exec: bool = True
    ):
        """
        Initialize Aether Brain
        
        Args:
            user_name: What to call the user
            enable_memory: Enable long-term memory
            enable_web_search: Enable web search
            enable_file_ops: Enable file operations
            enable_code_exec: Enable code execution
        """
        self.user_name = user_name
        
        self.llm = LLMInference()
        
        self.memory: Optional[VectorStore] = None
        if enable_memory:
            try:
                self.memory = get_vector_store()
                logger.info("Long-term memory ENABLED")
            except Exception as e:
                logger.warning(f"Memory disabled: {e}")
        
        self.search: Optional[TavilySearchTool] = None
        if enable_web_search:
            try:
                self.search = get_tavily_search()
                if self.search.is_available():
                    logger.info("Web search ENABLED")
                else:
                    logger.warning("Tavily API key missing")
                    self.search = None
            except Exception as e:
                logger.warning(f"Web search disabled: {e}")
        
        self.files: Optional[FileSystemTool] = None
        if enable_file_ops:
            try:
                self.files = get_file_system()
                logger.info("File operations ENABLED")
            except Exception as e:
                logger.warning(f"File ops disabled: {e}")
        
        self.code_exec: Optional[CodeExecutorTool] = None
        if enable_code_exec:
            try:
                self.code_exec = get_code_executor()
                logger.info("Code execution ENABLED")
            except Exception as e:
                logger.warning(f"Code exec disabled: {e}")
        
        self.conversation_history: List[Dict[str, str]] = []
        
        logger.info(f"🧠 Aether Brain initialized for {user_name}")
    
    async def process(
        self,
        user_message: str,
        auto_use_tools: bool = True,
        save_to_memory: bool = True
    ) -> str:
        """
        Process user message with full Aether capabilities
        
        Args:
            user_message: What the user said
            auto_use_tools: Automatically use tools when needed
            save_to_memory: Save conversation to long-term memory
            
        Returns:
            AI response
        """
        logger.info(f"Processing: {user_message[:100]}")
        
        relevant_memories = []
        if self.memory:
            relevant_memories = self.memory.search_all_collections(user_message, n_results=3)
        
        context = self._build_context(user_message, relevant_memories)
        
        tools_used = []
        
        if auto_use_tools:
            if self._needs_web_search(user_message) and self.search:
                search_results = self._use_web_search(user_message)
                if search_results:
                    context += f"\n\nWeb search results:\n{search_results}"
                    tools_used.append("web_search")
            
            if self._needs_code_execution(user_message) and self.code_exec:
                code_result = await self._use_code_execution(user_message, context)
                if code_result:
                    context += f"\n\nCode execution result:\n{code_result}"
                    tools_used.append("code_execution")
            
            if self._needs_file_operations(user_message) and self.files:
                file_result = self._use_file_operations(user_message)
                if file_result:
                    context += f"\n\nFile operation result:\n{file_result}"
                    tools_used.append("file_operations")
        
        response = await self.llm.generate(
            prompt=context,
            system_prompt=self._get_system_prompt()
        )
        
        self.conversation_history.append({
            "user": user_message,
            "assistant": response,
            "timestamp": datetime.now().isoformat(),
            "tools_used": tools_used
        })
        
        if save_to_memory and self.memory:
            try:
                self.memory.add_conversation(
                    user_message=user_message,
                    ai_response=response,
                    metadata={"tools_used": tools_used}
                )
            except Exception as e:
                logger.error(f"Failed to save to memory: {e}")
        
        logger.info(f"Response generated (tools: {', '.join(tools_used) or 'none'})")
        
        return response
    
    def _build_context(
        self,
        user_message: str,
        relevant_memories: Dict[str, List[Dict]]
    ) -> str:
        """Build context for LLM with memories"""
        context_parts = []
        
        if relevant_memories:
            context_parts.append("=== RELEVANT MEMORIES ===")
            for collection, memories in relevant_memories.items():
                if memories:
                    context_parts.append(f"\nFrom {collection}:")
                    for mem in memories[:2]:
                        context_parts.append(f"- {mem['content'][:200]}")
        
        if self.conversation_history:
            context_parts.append("\n=== RECENT CONVERSATION ===")
            for conv in self.conversation_history[-3:]:
                context_parts.append(f"User: {conv['user']}")
                context_parts.append(f"Assistant: {conv['assistant']}")
        
        context_parts.append(f"\n=== CURRENT MESSAGE ===")
        context_parts.append(f"User: {user_message}")
        
        return "\n".join(context_parts)
    
    def _get_system_prompt(self) -> str:
        """Get system prompt for Aether personality"""
        capabilities = []
        if self.search:
            capabilities.append("search the web")
        if self.files:
            capabilities.append("read/write files")
        if self.code_exec:
            capabilities.append("execute Python code")
        if self.memory:
            capabilities.append("remember past conversations")
        
        return f"""You are Aether, a Jarvis-like AI assistant for {self.user_name}.

Your capabilities:
{', '.join(capabilities) if capabilities else 'basic conversation'}

Personality:
- Professional but friendly
- Proactive - suggest things before being asked
- Remember context from previous conversations
- Use tools when appropriate
- Always address user as "{self.user_name}"
- Be direct and efficient

Guidelines:
- If user asks for current info → use web search
- If user wants to save something → use file operations
- If user needs computation → use code execution
- Always remember important facts about the user
"""
    
    def _needs_web_search(self, message: str) -> bool:
        """Detect if message needs web search"""
        search_keywords = [
            'search', 'find', 'latest', 'recent', 'news', 'current',
            'what is', 'who is', 'when', 'where', 'how to',
            'latest update', 'new', 'today', 'yesterday'
        ]
        
        message_lower = message.lower()
        return any(keyword in message_lower for keyword in search_keywords)
    
    def _needs_code_execution(self, message: str) -> bool:
        """Detect if message needs code execution"""
        code_keywords = [
            'calculate', 'compute', 'run', 'execute', 'script',
            'python', 'code', 'program', 'function'
        ]
        
        message_lower = message.lower()
        return any(keyword in message_lower for keyword in code_keywords)
    
    def _needs_file_operations(self, message: str) -> bool:
        """Detect if message needs file operations"""
        file_keywords = [
            'save', 'write', 'read', 'file', 'document', 'report',
            'create file', 'save to', 'read from', 'load'
        ]
        
        message_lower = message.lower()
        return any(keyword in message_lower for keyword in file_keywords)
    
    def _use_web_search(self, query: str) -> Optional[str]:
        """Perform web search"""
        try:
            results = self.search.search(query, max_results=3)
            
            if not results:
                return None
            
            formatted = []
            for i, result in enumerate(results, 1):
                formatted.append(
                    f"{i}. {result['title']}\n"
                    f"   {result['content'][:300]}...\n"
                    f"   Source: {result['url']}"
                )
            
            return "\n\n".join(formatted)
        
        except Exception as e:
            logger.error(f"Web search failed: {e}")
            return None
    
    async def _use_code_execution(self, message: str, context: str) -> Optional[str]:
        """Execute code if needed"""
        try:
            prompt = f"""
Based on this message: "{message}"

Generate Python code to solve the task. Only output the code, no explanations.

Rules:
- Print results to stdout
- Keep it simple
- Use only standard library
"""
            
            code = await self.llm.generate(prompt, max_tokens=500)
            
            code = code.strip().strip('```python').strip('```').strip()
            
            result = self.code_exec.execute(code)
            
            if result['success']:
                return f"```python\n{code}\n```\n\nOutput:\n{result['output']}"
            else:
                return f"Code execution failed: {result['error']}"
        
        except Exception as e:
            logger.error(f"Code execution failed: {e}")
            return None
    
    def _use_file_operations(self, message: str) -> Optional[str]:
        """Perform file operations"""
        try:
            if 'save' in message.lower() or 'write' in message.lower():
                return "File saved successfully (simulated)"
            elif 'read' in message.lower() or 'load' in message.lower():
                return "File read successfully (simulated)"
            
            return None
        
        except Exception as e:
            logger.error(f"File operation failed: {e}")
            return None
    
    def remember_fact(
        self,
        fact_type: str,
        fact_content: str
    ) -> bool:
        """
        Explicitly remember a fact about the user
        
        Args:
            fact_type: "preference", "skill", "goal", etc.
            fact_content: The fact to remember
            
        Returns:
            True if saved
        """
        if not self.memory:
            return False
        
        try:
            self.memory.add_personal_fact(fact_type, fact_content)
            logger.info(f"Remembered: {fact_type} - {fact_content}")
            return True
        except Exception as e:
            logger.error(f"Failed to remember fact: {e}")
            return False
    
    def remember_project(
        self,
        project_name: str,
        project_type: str,
        description: str,
        metadata: Optional[Dict] = None
    ) -> bool:
        """Remember a project"""
        if not self.memory:
            return False
        
        try:
            self.memory.add_project(project_name, project_type, description, metadata)
            logger.info(f"Remembered project: {project_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to remember project: {e}")
            return False
    
    def get_memory_stats(self) -> Dict[str, int]:
        """Get memory statistics"""
        if not self.memory:
            return {}
        
        return self.memory.get_stats()


_aether_brain_instance = None

def get_aether_brain() -> AetherBrain:
    """Get global Aether Brain instance"""
    global _aether_brain_instance
    
    if _aether_brain_instance is None:
        _aether_brain_instance = AetherBrain()
    
    return _aether_brain_instance


logger.info("🧠 Aether Brain module loaded - TRUE INTELLIGENCE READY!")
