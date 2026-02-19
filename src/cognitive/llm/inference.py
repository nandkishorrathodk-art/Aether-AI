from typing import Dict, Optional, List, Any, AsyncGenerator
from enum import Enum
from dataclasses import dataclass
import re
import asyncio

from src.cognitive.llm.model_loader import model_loader
from src.cognitive.llm.prompt_engine import prompt_engine, PromptTemplate
from src.cognitive.llm.context_manager import ContextManager, session_manager
from src.cognitive.llm.providers.base import TaskType, AIResponse
from src.utils.logger import get_logger

# God Mode Features
from src.features.automation import DesktopAutomation
from src.features.browser import BrowserAutomation
from src.features.vision import VisionSystem
from src.features.creation import ImageGenerator

# Personality System
from src.personality.conversational_style import response_enhancer, ToneType
from src.personality.motivational_engine import motivational_engine, MoodLevel
from src.personality.humor_generator import humor_generator

logger = get_logger(__name__)


class IntentType(Enum):
    QUERY = "query"
    COMMAND = "command"
    CHAT = "chat"
    ANALYSIS = "analysis"
    CODE = "code"
    AUTOMATION = "automation"
    CREATIVE = "creative"
    SECURITY = "security"
    UNKNOWN = "unknown"


@dataclass
class ConversationRequest:
    user_input: str
    session_id: str = "default"
    intent: Optional[IntentType] = None
    context: Optional[Dict[str, Any]] = None
    stream: bool = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None


@dataclass
class ConversationResponse:
    content: str
    intent: IntentType
    session_id: str
    ai_response: AIResponse
    context_stats: Dict[str, Any]
    metadata: Dict[str, Any]


class IntentClassifier:
    def __init__(self):
        self.patterns = self._load_patterns()
        logger.info("Intent Classifier initialized")

    def _load_patterns(self) -> Dict[IntentType, List[str]]:
        return {
            IntentType.COMMAND: [
                r'\b(open|launch|start|run|execute|close|kill|stop)\b',
                r'\b(create|delete|move|copy|rename)\s+(file|folder|directory)',
                r'\b(search|find|locate)\s+.*\s+(in|on|at)',

                r'\b(look|see|view|analyze)\s+(screen|image|this)',
                r'\b(write|type|input|paste)\s+.*\s+(in|into|on)\b',
            ],
            IntentType.ANALYSIS: [
                r'\b(analyze|analyse|swot|assess|evaluate|review)\b',
                r'\b(data|statistics|stats|metrics|trends)\b',
                r'\b(compare|contrast|versus|vs)\b',
                r'\b(forecast|predict|project)\b',
            ],
            IntentType.CODE: [
                r'\b(write|code|program|script|function|class)\b',
                r'\b(debug|fix|refactor|optimize)\b',
                r'\b(python|javascript|java|c\+\+|rust|go)\b',
                r'\b(algorithm|implement|develop)\b',
            ],
            IntentType.AUTOMATION: [
                r'\b(automate|schedule|workflow|batch|pipeline)\b',
                r'\b(every|daily|weekly|monthly|hourly)\b',
                r'\b(when|if|trigger|on event)\b',
            ],
            IntentType.CREATIVE: [
                r'\b(write|create|generate|compose)\s+(story|poem|article|essay|blog)',
                r'\b(creative|imaginative|brainstorm|idea)\b',
            ],
            IntentType.SECURITY: [
                 r'\b(scan|hack|exploit|vulnerability|pentest|recon|nmap)\b',
                 r'\b(log|monitor|alert|threat|security|soc|incident)\b',
                 r'\b(check ip|investigate|analyze traffic)\b',
            ],
            IntentType.QUERY: [
                r'\b(what|when|where|who|why|how|which)\b',
                r'\b(tell me|show me|explain|describe|define)\b',
                r'\b(is|are|can|could|would|should)\b',
            ],
        }

    def classify(self, user_input: str) -> IntentType:
        user_input_lower = user_input.lower()

        scores = {intent: 0 for intent in IntentType}

        for intent, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, user_input_lower):
                    scores[intent] += 1

        max_score = max(scores.values())
        if max_score == 0:
            if len(user_input.split()) < 5 and not user_input.endswith('?'):
                return IntentType.CHAT
            return IntentType.QUERY

        top_intent = max(scores.items(), key=lambda x: x[1])[0]
        logger.info(f"Classified intent: {top_intent.value} (score={max_score})")
        return top_intent

    def classify_with_confidence(self, user_input: str) -> Dict[str, Any]:
        user_input_lower = user_input.lower()
        scores = {intent: 0 for intent in IntentType}

        for intent, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, user_input_lower):
                    scores[intent] += 1

        total_matches = sum(scores.values())
        if total_matches == 0:
            return {
                "intent": IntentType.CHAT if len(user_input.split()) < 5 else IntentType.QUERY,
                "confidence": 0.5,
                "scores": scores
            }

        top_intent = max(scores.items(), key=lambda x: x[1])[0]
        confidence = scores[top_intent] / total_matches

        return {
            "intent": top_intent,
            "confidence": confidence,
            "scores": scores
        }


class ResponseFormatter:
    @staticmethod
    def format_response(
        content: str,
        intent: IntentType,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        if intent == IntentType.ANALYSIS:
            return ResponseFormatter._format_analysis(content)
        elif intent == IntentType.CODE:
            return ResponseFormatter._format_code(content)
        elif intent == IntentType.COMMAND:
            return ResponseFormatter._format_command(content)
        else:
            return content

    @staticmethod
    def _format_analysis(content: str) -> str:
        if "**" not in content and "#" not in content:
            lines = content.split('\n')
            formatted = "**Analysis Result:**\n\n"
            formatted += '\n'.join(lines)
            return formatted
        return content

    @staticmethod
    def _format_code(content: str) -> str:
        if "```" not in content and any(keyword in content for keyword in ["def ", "class ", "function ", "const ", "let ", "var "]):
            return f"```\n{content}\n```"
        return content

    @staticmethod
    def _format_command(content: str) -> str:
        if "confirm" not in content.lower() and "execute" in content.lower():
            return f"⚠️ **Action Required:**\n\n{content}\n\n*Please confirm before execution.*"
        return content


class ConversationEngine:
    def __init__(self):
        self.intent_classifier = IntentClassifier()
        self.formatter = ResponseFormatter()
        logger.info("Conversation Engine initialized")

    async def process_conversation(
        self,
        request: ConversationRequest
    ) -> ConversationResponse:
        context_mgr = session_manager.get_or_create_session(request.session_id)

        intent = request.intent or self.intent_classifier.classify(request.user_input)

        task_type = self._map_intent_to_task_type(intent)
        system_prompt_type = self._map_intent_to_prompt_type(intent)

        system_prompt = prompt_engine.get_system_prompt(system_prompt_type)
        
        logger.info(f"🔍 Intent: {intent}, Prompt Type: {system_prompt_type}")
        logger.info(f"📝 System Prompt (first 200 chars): {system_prompt[:200]}...")

        conversation_history = context_mgr.get_history()

        context_mgr.add_message("user", request.user_input)

        try:
            ai_response = await model_loader.generate(
                prompt=request.user_input,
                task_type=task_type,
                system_prompt=system_prompt,
                conversation_history=conversation_history,
                temperature=request.temperature,
                max_tokens=request.max_tokens
            )

            # DEBUG: Log raw response
            logger.info(f"🛑 RAW AI CONTENT: '{ai_response.content}'")

            # Safeguard: Check for Echo / "You said:" pattern (Case Insensitive & Loose)
            content_clean = ai_response.content.strip().lower()
            user_input_clean = request.user_input.strip().lower()
            
            if "you said:" in content_clean or \
               user_input_clean in content_clean[:len(user_input_clean)+20] or \
               content_clean == user_input_clean:
               
                logger.warning(f"⚠️ DETECTED ECHO RESPONSE: '{ai_response.content}'")
                
                # Fallback mechanism
                fallback_response = "I heard you. How can I help with that?"
                
                # Update response content
                ai_response.content = fallback_response
                formatted_content = fallback_response
                enhanced_content = fallback_response
                
                # Correct the metadata in response
                response = ConversationResponse(
                    content=enhanced_content,
                    intent=intent,
                    session_id=request.session_id,
                    ai_response=ai_response,
                    context_stats=context_mgr.get_context_stats(),
                    metadata={
                        "task_type": task_type.value,
                        "system_prompt_type": system_prompt_type,
                        "original_content": "ECHO_DETECTED_AND_SUPPRESSED",
                        "personality_enhanced": False,
                        "safeguard_triggered": True
                    }
                )
                logger.info(f"Safeguard triggered. Returned fallback response.")
                return response

            # Execute Detected Actions (God Mode)
            await self._execute_detected_actions(ai_response.content)

            formatted_content = self.formatter.format_response(
                ai_response.content,
                intent
            )

            # Apply Personality Enhancement (v0.9.0)
            personality_context = {
                "intent": intent.value,
                "session_id": request.session_id,
            }
            enhanced_content = self._apply_personality_layer(
                formatted_content,
                intent,
                personality_context
            )

            context_mgr.add_message("assistant", ai_response.content)

            response = ConversationResponse(
                content=enhanced_content,
                intent=intent,
                session_id=request.session_id,
                ai_response=ai_response,
                context_stats=context_mgr.get_context_stats(),
                metadata={
                    "task_type": task_type.value,
                    "system_prompt_type": system_prompt_type,
                    "original_content": ai_response.content,
                    "personality_enhanced": True
                }
            )

            logger.info(f"Conversation processed: session={request.session_id}, intent={intent.value}")
            return response

        except Exception as e:
            logger.error(f"Error processing conversation: {e}")
            raise

    def _apply_personality_layer(
        self,
        content: str,
        intent: IntentType,
        context: Dict[str, Any]
    ) -> str:
        tone_mapping = {
            IntentType.CHAT: ToneType.FRIENDLY,
            IntentType.QUERY: ToneType.PROFESSIONAL,
            IntentType.COMMAND: ToneType.CASUAL,
            IntentType.ANALYSIS: ToneType.PROFESSIONAL,
            IntentType.CODE: ToneType.PROFESSIONAL,
            IntentType.AUTOMATION: ToneType.CASUAL,
            IntentType.CREATIVE: ToneType.FRIENDLY,
            IntentType.SECURITY: ToneType.PROFESSIONAL,
        }
        
        tone = tone_mapping.get(intent, ToneType.FRIENDLY)
        
        enhanced = response_enhancer.enhance_response(
            content,
            tone=tone,
            add_personality=True,
            context=context
        )
        
        enhanced = humor_generator.add_humor_to_response(enhanced, context.get("humor_context"))
        
        return enhanced

    async def _execute_detected_actions(self, text: str):
        """Execute actions embedded in text like `Action: [OPEN: notepad]`"""
        try:
            pattern = r"Action: \[([A-Z]+): (.*?)\]"
            matches = re.finditer(pattern, text)
            
            for match in matches:
                command = match.group(1).upper()
                args = match.group(2).strip()
                logger.info(f"⚡ Executing God Mode Action: {command} -> {args}")
                
                if command == "OPEN":
                    DesktopAutomation.open_app(args)
                elif command == "SEARCH":
                    BrowserAutomation.search(args)
                elif command == "TYPE":
                    DesktopAutomation.type_text(args)
                elif command == "PRESS":
                    DesktopAutomation.press_key(args)
                elif command == "CLICK":
                    if "," in args:
                        try:
                            x, y = map(int, args.split(','))
                            DesktopAutomation.click_at(x, y)
                        except ValueError:
                             # Fallback to text click if parsing fails
                             result = DesktopAutomation.click_text(args)
                             logger.info(result)
                    else:
                        # Click by Text (UI Automation)
                        result = DesktopAutomation.click_text(args)
                        logger.info(result)
                elif command == "LOOK":
                    # Vision analysis (can take time, so run in thread or await if possible)
                    # VisionSystem.analyze_screen uses sync requests
                    logger.info("Starting Vision Analysis...")
                    result = VisionSystem.analyze_screen(args)
                    logger.info(f"Vision Result: {result[:50]}...")
                    
                    # Speak Result immediately
                    try:
                        # Lazy import to avoid circular dependency
                        from src.pipeline.voice_pipeline import get_pipeline
                        pipeline = get_pipeline()
                        if pipeline:
                             pipeline.response_queue.put({
                                "text": f"I see: {result}",
                                "session_id": "vision"
                            })
                    except Exception as e:
                        logger.error(f"Failed to speak vision result: {e}")
                        
                elif command == "IMAGE":
                    logger.info("Starting Image Generation...")
                    url = ImageGenerator.generate_image(args)
                    if not url.startswith("Error"):
                        logger.info(f"Image Generated: {url}")
                        BrowserAutomation.open_url(url)
                    else:
                        logger.error(f"Image Gen Error: {url}")
                elif command == "SCAN":
                    # Security Scan
                    from src.features.security import security_module
                    logger.info(f"Starting Security Scan: {args}")
                    result = await security_module.run_scan(args, scan_type="quick")
                    
                    # Store result in context or speak it
                    # For now, simplistic output via TTS queue if possible or just log
                    logger.info(f"Scan Result: {result[:200]}...")
                     # Report back via conversation context (ideal) or log
                
                elif command == "ANALYZE":
                     # Log Analysis
                    from src.features.security import security_module
                    logger.info(f"Analyzing Logs: {args}")
                    result = await security_module.analyze_logs()
                    logger.info(f"Log Analysis: {result[:200]}...")
                
                elif command == "SETUP":
                    # Multi-step task execution
                    logger.info(f"⚡ Starting COMPLETE SETUP for: {args}")
                    
                    if "burp" in args.lower() or "burpsuite" in args.lower():
                        # BurpSuite complete setup
                        from src.action.tasks.burpsuite_tasks import setup_burpsuite_and_scan
                        
                        # Extract target URL if provided
                        target = None
                        if "http" in args:
                            url_match = re.search(r'https?://[^\s]+', args)
                            if url_match:
                                target = url_match.group(0)
                        
                        # Progress callback to speak updates
                        async def progress_callback(progress):
                            try:
                                from src.pipeline.voice_pipeline import get_pipeline
                                pipeline = get_pipeline()
                                if pipeline and progress.get('current_step_description'):
                                    pipeline.response_queue.put({
                                        "text": f"Step {progress['current_step']}/{progress['total_steps']}: {progress['current_step_description']}",
                                        "session_id": "task"
                                    })
                            except:
                                pass
                        
                        # Start the complete setup task
                        task_id = await setup_burpsuite_and_scan(target, progress_callback)
                        logger.info(f"✅ BurpSuite complete setup task started: {task_id}")

        except Exception as e:
            logger.error(f"God Mode Action Execution Failed: {e}")

    async def stream_conversation(
        self,
        request: ConversationRequest
    ) -> AsyncGenerator[str, None]:
        context_mgr = session_manager.get_or_create_session(request.session_id)

        intent = request.intent or self.intent_classifier.classify(request.user_input)
        task_type = self._map_intent_to_task_type(intent)
        system_prompt_type = self._map_intent_to_prompt_type(intent)
        system_prompt = prompt_engine.get_system_prompt(system_prompt_type)
        conversation_history = context_mgr.get_history()

        context_mgr.add_message("user", request.user_input)

        full_response = ""
        try:
            async for chunk in model_loader.stream_generate(
                prompt=request.user_input,
                task_type=task_type,
                system_prompt=system_prompt,
                conversation_history=conversation_history,
                temperature=request.temperature,
                max_tokens=request.max_tokens
            ):
                full_response += chunk
                yield chunk

            context_mgr.add_message("assistant", full_response)
            logger.info(f"Streamed conversation: session={request.session_id}, intent={intent.value}")

        except Exception as e:
            logger.error(f"Error streaming conversation: {e}")
            raise

    def _map_intent_to_task_type(self, intent: IntentType) -> TaskType:
        mapping = {
            IntentType.QUERY: TaskType.FAST,
            IntentType.COMMAND: TaskType.FAST,
            IntentType.CHAT: TaskType.FAST,
            IntentType.ANALYSIS: TaskType.ANALYSIS,
            IntentType.CODE: TaskType.CODE,
            IntentType.AUTOMATION: TaskType.CODE,
            IntentType.CREATIVE: TaskType.CREATIVE,
            IntentType.SECURITY: TaskType.REASONING,
            IntentType.UNKNOWN: TaskType.FAST,
        }
        return mapping.get(intent, TaskType.FAST)

    def _map_intent_to_prompt_type(self, intent: IntentType) -> str:
        mapping = {
            IntentType.QUERY: "conversation",
            IntentType.COMMAND: "automation",
            IntentType.CHAT: "conversation",
            IntentType.ANALYSIS: "analysis",
            IntentType.CODE: "code",
            IntentType.AUTOMATION: "automation",
            IntentType.CREATIVE: "conversation",
            IntentType.SECURITY: "security",
            IntentType.UNKNOWN: "default",
        }
        return mapping.get(intent, "default")

    def get_session_context(self, session_id: str) -> Optional[ContextManager]:
        return session_manager.get_session(session_id)

    def clear_session(self, session_id: str):
        session = session_manager.get_session(session_id)
        if session:
            session.clear_history()
            logger.info(f"Cleared session: {session_id}")

    def delete_session(self, session_id: str):
        session_manager.delete_session(session_id)

    def list_sessions(self) -> List[str]:
        return session_manager.list_sessions()

    def get_all_sessions_stats(self) -> Dict[str, Dict[str, Any]]:
        return session_manager.get_all_sessions_stats()


conversation_engine = ConversationEngine()
