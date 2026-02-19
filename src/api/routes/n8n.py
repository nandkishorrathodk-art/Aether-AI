from fastapi import APIRouter, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import httpx
import asyncio
from datetime import datetime
from src.utils.logger import get_logger
from src.cognitive.llm.conversation_engine import ConversationEngine
from src.autonomous.autonomous_brain import AutonomousBrain
from src.bugbounty.bug_bounty_engine import BugBountyEngine
from src.cognitive.llm.model_router import ModelRouter

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/n8n", tags=["n8n"])

conversation_engine = ConversationEngine()
autonomous_brain = AutonomousBrain()
bug_bounty_engine = BugBountyEngine()
model_router = ModelRouter()


class N8NWebhookRequest(BaseModel):
    workflow_id: str = Field(..., description="n8n workflow ID")
    action: str = Field(..., description="Action to perform")
    data: Dict[str, Any] = Field(default_factory=dict, description="Action data")
    callback_url: Optional[str] = Field(None, description="URL to send results back")
    async_mode: bool = Field(False, description="Run in background")


class N8NTriggerRequest(BaseModel):
    webhook_url: str = Field(..., description="n8n webhook URL to trigger")
    data: Dict[str, Any] = Field(default_factory=dict, description="Data to send")
    method: str = Field("POST", description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers")


class N8NResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    execution_id: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


async def execute_aether_action(action: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Aether AI action based on n8n request"""
    
    try:
        if action == "chat":
            message = data.get("message", "")
            session_id = data.get("session_id", "n8n-session")
            
            result = await conversation_engine.process_conversation(
                message=message,
                session_id=session_id,
                use_context=True
            )
            
            return {
                "response": result.get("content", ""),
                "intent": result.get("intent", ""),
                "session_id": session_id
            }
        
        elif action == "autonomous_scan":
            target = data.get("target", "")
            if not target:
                raise ValueError("Target URL required for autonomous scan")
            
            result = await autonomous_brain.start_autonomous_session(
                target_url=target,
                mode=data.get("mode", "balanced")
            )
            
            return {
                "session_id": result.get("session_id"),
                "status": "started",
                "target": target
            }
        
        elif action == "bug_bounty":
            program = data.get("program", "")
            if not program:
                raise ValueError("Program name required")
            
            result = await bug_bounty_engine.analyze_program(program)
            
            return {
                "program": program,
                "analysis": result
            }
        
        elif action == "generate_text":
            prompt = data.get("prompt", "")
            model = data.get("model", "auto")
            
            result = await model_router.generate(
                prompt=prompt,
                model=model,
                temperature=data.get("temperature", 0.7),
                max_tokens=data.get("max_tokens", 2048)
            )
            
            return {
                "text": result.get("content", ""),
                "model": result.get("model", ""),
                "tokens": result.get("usage", {})
            }
        
        elif action == "transcribe_audio":
            audio_url = data.get("audio_url", "")
            if not audio_url:
                raise ValueError("Audio URL required")
            
            async with httpx.AsyncClient() as client:
                audio_response = await client.get(audio_url)
                audio_data = audio_response.content
            
            from src.perception.voice.stt import SpeechToText
            stt = SpeechToText()
            
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
                f.write(audio_data)
                temp_path = f.name
            
            result = stt.transcribe_audio(temp_path)
            
            import os
            os.unlink(temp_path)
            
            return {
                "transcription": result.get("text", ""),
                "language": result.get("language", ""),
                "confidence": result.get("confidence", 0.0)
            }
        
        elif action == "synthesize_speech":
            text = data.get("text", "")
            if not text:
                raise ValueError("Text required for TTS")
            
            from src.perception.voice.tts import TextToSpeech
            tts = TextToSpeech()
            
            audio_data = tts.speak(
                text=text,
                voice=data.get("voice", "alloy"),
                speed=data.get("speed", 1.0)
            )
            
            return {
                "audio_base64": audio_data.get("audio_base64", ""),
                "format": audio_data.get("format", "mp3")
            }
        
        elif action == "analyze_image":
            image_url = data.get("image_url", "")
            prompt = data.get("prompt", "Analyze this image in detail")
            
            if not image_url:
                raise ValueError("Image URL required")
            
            async with httpx.AsyncClient() as client:
                response = await model_router.generate(
                    prompt=prompt,
                    model=data.get("model", "auto"),
                    images=[image_url],
                    temperature=data.get("temperature", 0.7)
                )
            
            return {
                "analysis": response.get("content", ""),
                "model": response.get("model", "")
            }
        
        elif action == "scrape_web":
            url = data.get("url", "")
            if not url:
                raise ValueError("URL required for scraping")
            
            from src.openclaw.openclaw import OpenClaw
            openclaw = OpenClaw()
            
            result = await openclaw.scrape(
                url=url,
                extract_type=data.get("extract_type", "all"),
                wait_for=data.get("wait_for", None)
            )
            
            return {
                "url": url,
                "title": result.get("title", ""),
                "content": result.get("content", ""),
                "links": result.get("links", []),
                "images": result.get("images", [])
            }
        
        elif action == "execute_code":
            code = data.get("code", "")
            language = data.get("language", "python")
            
            if not code:
                raise ValueError("Code required for execution")
            
            import subprocess
            import tempfile
            import os
            
            ext_map = {"python": ".py", "javascript": ".js", "bash": ".sh"}
            ext = ext_map.get(language, ".py")
            
            with tempfile.NamedTemporaryFile(mode='w', suffix=ext, delete=False) as f:
                f.write(code)
                temp_path = f.name
            
            try:
                if language == "python":
                    result = subprocess.run(
                        ["python", temp_path],
                        capture_output=True,
                        text=True,
                        timeout=data.get("timeout", 30)
                    )
                elif language == "javascript":
                    result = subprocess.run(
                        ["node", temp_path],
                        capture_output=True,
                        text=True,
                        timeout=data.get("timeout", 30)
                    )
                else:
                    raise ValueError(f"Unsupported language: {language}")
                
                return {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "return_code": result.returncode,
                    "language": language
                }
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
        
        else:
            raise ValueError(f"Unknown action: {action}")
    
    except Exception as e:
        logger.error(f"Error executing action '{action}': {e}")
        raise


async def send_callback(callback_url: str, data: Dict[str, Any]):
    """Send results back to n8n webhook"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(callback_url, json=data)
            response.raise_for_status()
            logger.info(f"Callback sent successfully to {callback_url}")
    except Exception as e:
        logger.error(f"Failed to send callback to {callback_url}: {e}")


@router.post("/webhook", response_model=N8NResponse)
async def n8n_webhook(
    request: N8NWebhookRequest,
    background_tasks: BackgroundTasks,
    x_n8n_workflow_id: Optional[str] = Header(None)
):
    """
    Webhook endpoint for n8n to trigger Aether AI actions
    
    Supported actions:
    - chat: Send message to conversation engine
    - autonomous_scan: Start autonomous security scan
    - bug_bounty: Analyze bug bounty program
    - generate_text: Generate text with LLM
    - transcribe_audio: Convert audio to text
    - synthesize_speech: Convert text to speech
    - analyze_image: Analyze images with vision AI (NEW v3.2)
    - scrape_web: Extract data from websites (NEW v3.2)
    - execute_code: Run Python/JavaScript code (NEW v3.2)
    """
    
    execution_id = f"n8n_{request.workflow_id}_{datetime.now().timestamp()}"
    
    logger.info(f"Received n8n webhook: workflow={request.workflow_id}, action={request.action}")
    
    if request.async_mode:
        async def async_execution():
            try:
                result = await execute_aether_action(request.action, request.data)
                
                if request.callback_url:
                    await send_callback(request.callback_url, {
                        "execution_id": execution_id,
                        "success": True,
                        "data": result
                    })
            except Exception as e:
                logger.error(f"Async execution failed: {e}")
                if request.callback_url:
                    await send_callback(request.callback_url, {
                        "execution_id": execution_id,
                        "success": False,
                        "error": str(e)
                    })
        
        background_tasks.add_task(async_execution)
        
        return N8NResponse(
            success=True,
            message="Task queued for background execution",
            execution_id=execution_id
        )
    
    else:
        try:
            result = await execute_aether_action(request.action, request.data)
            
            return N8NResponse(
                success=True,
                message=f"Action '{request.action}' completed successfully",
                data=result,
                execution_id=execution_id
            )
        
        except Exception as e:
            logger.error(f"Webhook execution failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))


@router.post("/trigger", response_model=N8NResponse)
async def trigger_n8n_workflow(request: N8NTriggerRequest):
    """
    Trigger an n8n workflow from Aether AI
    
    Use this to send data from Aether to n8n workflows
    """
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            if request.method.upper() == "POST":
                response = await client.post(
                    request.webhook_url,
                    json=request.data,
                    headers=request.headers
                )
            elif request.method.upper() == "GET":
                response = await client.get(
                    request.webhook_url,
                    params=request.data,
                    headers=request.headers
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {request.method}")
            
            response.raise_for_status()
            
            return N8NResponse(
                success=True,
                message=f"n8n workflow triggered successfully",
                data=response.json() if response.content else None
            )
    
    except httpx.HTTPError as e:
        logger.error(f"Failed to trigger n8n workflow: {e}")
        raise HTTPException(status_code=500, detail=f"n8n trigger failed: {str(e)}")


@router.get("/health")
async def n8n_health():
    """Health check endpoint for n8n"""
    return {
        "status": "healthy",
        "service": "aether-ai-n8n",
        "timestamp": datetime.now().isoformat()
    }


@router.get("/actions")
async def list_actions():
    """List all available Aether AI actions for n8n"""
    return {
        "actions": [
            {
                "name": "chat",
                "description": "Send message to conversation engine",
                "required_fields": ["message"],
                "optional_fields": ["session_id"]
            },
            {
                "name": "autonomous_scan",
                "description": "Start autonomous security scan",
                "required_fields": ["target"],
                "optional_fields": ["mode"]
            },
            {
                "name": "bug_bounty",
                "description": "Analyze bug bounty program",
                "required_fields": ["program"],
                "optional_fields": []
            },
            {
                "name": "generate_text",
                "description": "Generate text with LLM",
                "required_fields": ["prompt"],
                "optional_fields": ["model", "temperature", "max_tokens"]
            },
            {
                "name": "transcribe_audio",
                "description": "Convert audio to text",
                "required_fields": ["audio_url"],
                "optional_fields": []
            },
            {
                "name": "synthesize_speech",
                "description": "Convert text to speech",
                "required_fields": ["text"],
                "optional_fields": ["voice", "speed"]
            }
        ]
    }
