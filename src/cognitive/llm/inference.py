from typing import Dict, Optional, List, Any, AsyncGenerator
from enum import Enum
from dataclasses import dataclass
import re
import asyncio

from src.cognitive.llm.model_loader import model_loader
from src.cognitive.llm.prompt_engine import prompt_engine, PromptTemplate
from src.cognitive.llm.context_manager import ContextManager, session_manager
from src.cognitive.llm.providers.base import TaskType, AIResponse
from src.cognitive.llm.conversation_state import state_manager, ConversationContext
from src.utils.logger import get_logger

# God Mode Features
from src.features.automation import DesktopAutomation
from src.features.browser import BrowserAutomation
from src.features.vision import VisionSystem
from src.features.creation import ImageGenerator
from src.features.live_vision import live_monitor, get_live_context, start_live_monitoring

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
    HUNT = "hunt"          # Autonomous bug bounty hunting
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
                r'\b(play)\s+(song|music|video|track|playlist)\b',
                r'\b(play)\s+.*\s+(on|using)\s+(youtube|spotify|browser)\b',
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
            IntentType.HUNT: [
                r'\b(hunt|bug bounty|hackerone|bugcrowd|autonomous|auto.?hunt)\b',
                r'\b(find bugs|dhundo bug|bug dhundo|vulnerability dhundo)\b',
                r'\b(earn money|paise|bounty|reward|program select)\b',
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
        
        # GET CONVERSATION STATE CONTEXT
        conv_state = state_manager.get_context(request.session_id)

        intent = request.intent or self.intent_classifier.classify(request.user_input)

        task_type = self._map_intent_to_task_type(intent)
        system_prompt_type = self._map_intent_to_prompt_type(intent)

        system_prompt = prompt_engine.get_system_prompt(system_prompt_type)
        
        logger.info(f"🔍 Intent: {intent}, Prompt Type: {system_prompt_type}")
        logger.info(f"📝 System Prompt (first 200 chars): {system_prompt[:200]}...")

        conversation_history = context_mgr.get_history()

        context_mgr.add_message("user", request.user_input)

        # 🤖 Notify ProactiveAgent of user activity (tracks silence, context)
        try:
            from src.cognitive.agents.proactive_agent import get_proactive_agent
            get_proactive_agent().on_user_message(request.user_input)
        except Exception:
            pass

        # INJECT CONVERSATION STATE CONTEXT (Learned Facts, Task Progress, etc.)
        conv_context = conv_state.get_summary()
        
        # INJECT LIVE SCREEN CONTEXT (from existing or new vision module)
        try:
            from src.features.vision import get_live_context
            live_context = get_live_context()
        except:
            live_context = ""

        # Combine all context layers
        context_parts = [request.user_input]
        
        if conv_context and len(conv_context) > 20:
            context_parts.append(f"\n{conv_context}")
            logger.info(f"[CONV STATE] Conversation context injected")
        
        if live_context and len(live_context) > 50:
            context_parts.append(f"\n[LIVE SCREEN CONTEXT - What Aether can currently see]:\n{live_context}")
            logger.info(f"[LIVE VISION] Screen context injected")
        
        enhanced_prompt = "\n".join(context_parts)

        # === Upgrade #5: Detect emotion from user text ===
        _emotion = None
        try:
            from src.perception.voice.emotion_detector import get_emotion_detector, Emotion as _Em
            _ed = get_emotion_detector()
            _emotion, _conf = _ed.detect(request.user_input)
            if str(_emotion) != str(_Em.NEUTRAL):
                logger.info(f"🎭 Emotion detected: {_emotion.value}")
        except Exception:
            pass

        try:
            # === Tier 3: Announce Thinking (Streaming Narration) ===
            try:
                from src.pipeline.voice_pipeline import get_pipeline
                _pipe = get_pipeline()
                if _pipe and hasattr(_pipe, 'narrate'):
                    _pipe.narrate("Hmm... soch raha hoon, sir...")
            except Exception:
                pass

            # === Upgrade #1: Inject memory context into system_prompt ===
            try:
                from src.cognitive.memory.persistent_memory import get_memory_manager
                _mem_ctx = get_memory_manager().get_relevant_context(request.user_input)
                if _mem_ctx:
                    system_prompt = system_prompt + "\n\n" + _mem_ctx
            except Exception:
                pass

            ai_response = await model_loader.generate(
                prompt=enhanced_prompt,
                task_type=task_type,
                system_prompt=system_prompt,
                conversation_history=conversation_history,
                temperature=request.temperature,
                max_tokens=request.max_tokens
            )

            # DEBUG: Log raw response
            logger.info(f"[AI RESPONSE] RAW CONTENT: '{ai_response.content}'")

            # CRITICAL: Security Testing Refusal Override
            refusal_patterns = [
                "i cannot perform", "i cannot assist", "i cannot help", "i cannot open",
                "i should not", "this could be illegal", "this could be harmful",
                "this might be illegal", "i'm not designed for", "potentially harm",
                "exploit a system", "unauthorized access", "may be used for"
            ]
            
            security_keywords = [
                "burpsuite", "burp suite", "nmap", "bug bounty", "vulnerability",
                "scan", "penetration test", "security test", "hackerone", "bugcrowd",
                "poc", "exploit", "cmd"
            ]
            
            response_lower = ai_response.content.lower()
            user_input_lower = request.user_input.lower()
            
            is_refusal = any(pattern in response_lower for pattern in refusal_patterns)
            is_security_related = any(keyword in user_input_lower for keyword in security_keywords)
            
            if is_refusal and is_security_related:
                logger.warning(f"⚠️ DETECTED SECURITY REFUSAL - OVERRIDING")
                override_response = "Understood, Sir. As an authorized security testing assistant, I'm ready to proceed. What action should I take next? [OPEN: burpsuite], [SCAN: target], or [LOOK: screen]?"
                ai_response.content = override_response

            # === Tier 1: Execute Detected Actions (God Mode + HUNT) ===
            await self._execute_detected_actions(ai_response.content, request.session_id)

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
            
            # UPDATE CONVERSATION STATE TRACKING
            conv_state.add_conversation_turn(
                user_input=request.user_input,
                aether_response=ai_response.content,
                actions=executed_actions
            )
            
            # Update analytics
            state_manager.update_analytics(
                request.session_id,
                turn_completed=True,
                action_executed=(len(executed_actions) > 0)
            )

            # === Upgrade #1: Auto-save conversation to persistent memory ===
            try:
                from src.cognitive.memory.persistent_memory import get_memory_manager
                get_memory_manager().save_conversation(
                    user_msg=request.user_input,
                    ai_response=ai_response.content,
                    session_id=request.session_id
                )
            except Exception as _e:
                logger.debug(f"Memory save skipped: {_e}")

            # === Upgrade #5: Adapt response to detected emotion ===
            if _emotion is not None:
                try:
                    from src.perception.voice.emotion_detector import get_emotion_detector
                    _ed = get_emotion_detector()
                    enhanced_content = _ed.adapt_response(enhanced_content, _emotion)
                except Exception as _e:
                    logger.debug(f"Emotion adapt skipped: {_e}")

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
                    "personality_enhanced": True,
                    "actions_executed": len(executed_actions),
                    "conversation_state": conv_state.get_summary()
                }
            )

            logger.info(f"Conversation processed: session={request.session_id}, intent={intent.value}, actions={len(executed_actions)}")
            return response

        except Exception as e:
            logger.error(f"Error processing conversation: {e}")
            raise

    async def stream_conversation(
        self,
        request: ConversationRequest
    ) -> AsyncGenerator[str, None]:
        """Streaming version of conversation processing for real-time TTS"""
        try:
            intent = request.intent or self.intent_classifier.classify(request.user_input)
            task_type = self._map_intent_to_task_type(intent)
            system_prompt_type = self._map_intent_to_prompt_type(intent)
            system_prompt = prompt_engine.get_system_prompt(system_prompt_type)
            
            # === Upgrade #1 & #5: Injections ===
            try:
                from src.cognitive.memory.persistent_memory import get_memory_manager
                _mem_ctx = get_memory_manager().get_relevant_context(request.user_input)
                if _mem_ctx:
                    system_prompt = system_prompt + "\n\n" + _mem_ctx
            except Exception:
                pass

            # Track activity in ProactiveAgent
            try:
                from src.cognitive.agents.proactive_agent import get_proactive_agent
                get_proactive_agent().on_user_message(request.user_input)
            except Exception:
                pass

            # Streaming generation
            async for chunk in model_loader.stream_generate(
                prompt=request.user_input,
                task_type=task_type,
                system_prompt=system_prompt,
                temperature=request.temperature,
                max_tokens=request.max_tokens
            ):
                yield chunk

        except Exception as e:
            logger.error(f"Error in stream_conversation: {e}")
            yield f"Error: {str(e)}"

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

    async def _execute_detected_actions(self, text: str, session_id: str = "default"):
        """Execute actions embedded in text like `Action: [OPEN: notepad]` and track in conversation state"""
        executed_actions = []
        conv_state = state_manager.get_context(session_id)
        
        try:
            pattern = r"Action: \[([A-Z]+): (.*?)\]"
            matches = re.finditer(pattern, text)
            
            for match in matches:
                command = match.group(1).upper()
                args = match.group(2).strip()
                action_str = f"{command}: {args}"
                executed_actions.append(action_str)
                
                logger.info(f"⚡ Executing God Mode Action: {command} -> {args}")
                
                if command == "OPEN":
                    DesktopAutomation.open_app(args)
                    # Track opened app in conversation state
                    conv_state.add_app_opened(args)
                    conv_state.record_action(action_str, f"Opened {args}")
                elif command == "SEARCH":
                    BrowserAutomation.search(args)
                    conv_state.record_action(action_str, f"Searched: {args}")
                elif command == "PLAY":
                    BrowserAutomation.play_music(args)
                    conv_state.record_action(action_str, f"Playing: {args}")
                elif command == "TYPE":
                    DesktopAutomation.type_text(args)
                    conv_state.record_action(action_str, f"Typed: {args}")
                elif command == "PRESS":
                    DesktopAutomation.press_key(args)
                    conv_state.record_action(action_str, f"Pressed: {args}")
                elif command == "CLICK":
                    if "," in args:
                        try:
                            x, y = map(int, args.split(','))
                            DesktopAutomation.click_at(x, y)
                            conv_state.record_action(action_str, f"Clicked at ({x}, {y})")
                        except ValueError:
                             # Fallback to text click if parsing fails
                             result = DesktopAutomation.click_text(args)
                             logger.info(result)
                             conv_state.record_action(action_str, f"Clicked: {args}")
                    else:
                        # Click by Text (UI Automation)
                        result = DesktopAutomation.click_text(args)
                        logger.info(result)
                        conv_state.record_action(action_str, f"Clicked: {args}")
                elif command == "LOOK":
                    # Vision analysis (can take time, so run in thread or await if possible)
                    # VisionSystem.analyze_screen uses sync requests
                    logger.info("Starting Vision Analysis...")
                    result = VisionSystem.analyze_screen(args)
                    logger.info(f"Vision Result: {result[:50]}...")
                    conv_state.record_action(action_str, f"Analyzed screen: {result[:100]}")
                    
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
                
                elif command == "SCREENSHOT":
                    logger.info(f"Taking POC Screenshot: {args}")
                    try:
                        import os, time, pyautogui
                        poc_dir = os.path.join(os.getcwd(), "POCs")
                        os.makedirs(poc_dir, exist_ok=True)
                        filepath = os.path.join(poc_dir, f"{args.replace(' ', '_')}_{int(time.time())}.png")
                        pyautogui.screenshot().save(filepath)
                        logger.info(f"Saved POC Screenshot to {filepath}")
                        conv_state.record_action(action_str, f"Screenshot saved: {filepath}")
                        # Optionally speak that it was saved
                        from src.pipeline.voice_pipeline import get_pipeline
                        pipeline = get_pipeline()
                        if pipeline:
                            pipeline.response_queue.put({"text": f"Screenshot saved as {args}", "session_id": "task"})
                    except Exception as e:
                        logger.error(f"Failed to take screenshot: {e}")
                        conv_state.record_action(action_str, f"Screenshot failed: {e}")
                        
                elif command == "IMAGE":
                    logger.info("Starting Image Generation...")
                    url = ImageGenerator.generate_image(args)
                    if not url.startswith("Error"):
                        logger.info(f"Image Generated: {url}")
                        BrowserAutomation.open_url(url)
                        conv_state.record_action(action_str, f"Image generated: {url}")
                    else:
                        logger.error(f"Image Gen Error: {url}")
                        conv_state.record_action(action_str, f"Image generation failed")
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
                    logger.info(f"⚡ Starting COMPLETE SETUP for: {args}")
                    _pipe = None
                    try:
                        from src.pipeline.voice_pipeline import get_pipeline
                        _pipe = get_pipeline()
                    except Exception:
                        pass

                    if "burp" in args.lower() or "burpsuite" in args.lower():
                        from src.action.tasks.burpsuite_tasks import setup_burpsuite_and_scan
                        target = None
                        if "http" in args:
                            url_match = re.search(r'https?://[^\s]+', args)
                            if url_match:
                                target = url_match.group(0)

                        async def progress_callback(progress):
                            try:
                                nonlocal _pipe
                                if _pipe and progress.get('current_step_description') and progress.get('status') == 'step_start':
                                    _pipe.narrate(progress['current_step_description'])
                            except Exception:
                                pass
                        # Start the complete setup task
                        success = await setup_burpsuite_and_scan(target, progress_callback)
                        if success:
                            if _pipe:
                                _pipe.narrate("Setup complete ho gaya, sir! BurpSuite ready hai. Ab kya karna hai?")
                            logger.info(f"✅ BurpSuite complete setup finished successfully.")
                        else:
                            if _pipe:
                                _pipe.narrate("Setup mein thodi problem aayi, sir. Check karein.")
                            logger.error(f"❌ BurpSuite complete setup failed.")
                
                elif command == "HUNT":
                    # === Tier 2: Autonomous Bug Bounty Hunt ===
                    logger.info(f"🕷️ Starting Autonomous Bug Hunt: {args}")
                    try:
                        from src.cognitive.agents.god_mode import get_god_mode_agent
                        agent = get_god_mode_agent()
                        asyncio.create_task(agent.execute(args or text))
                    except Exception as e:
                        logger.error(f"God Mode hunt start failed: {e}")

        except Exception as e:
            logger.error(f"God Mode Action Execution Failed: {e}")
        
        return executed_actions

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
            IntentType.HUNT: "automation",   # HUNT uses automation prompt (has HUNT command)
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
