import strawberry
from typing import List, Optional
from datetime import datetime
from strawberry.types import Info


@strawberry.type
class Message:
    id: str
    content: str
    role: str
    timestamp: str


@strawberry.type
class ConversationResponse:
    content: str
    intent: str
    session_id: str
    timestamp: str
    tokens: Optional[int] = None


@strawberry.type
class Vulnerability:
    id: str
    title: str
    severity: str
    description: str
    url: str
    found_at: str


@strawberry.type
class ScanSession:
    session_id: str
    target: str
    status: str
    vulnerabilities_found: int
    started_at: str
    completed_at: Optional[str] = None


@strawberry.type
class ExecutionResult:
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    language: str
    success: bool


@strawberry.type
class Provider:
    name: str
    status: str
    models_count: int


@strawberry.type
class SystemStats:
    total_requests: int
    active_sessions: int
    cache_hit_rate: float
    uptime_seconds: int


@strawberry.input
class ChatInput:
    message: str
    session_id: Optional[str] = "default"
    model: Optional[str] = "auto"


@strawberry.input
class CodeExecutionInput:
    code: str
    language: str
    timeout: int = 30
    args: Optional[List[str]] = None


@strawberry.input
class ScanInput:
    target: str
    mode: str = "balanced"
    max_depth: int = 3


@strawberry.type
class Query:
    @strawberry.field
    async def chat_history(
        self,
        session_id: str = "default",
        limit: int = 10
    ) -> List[Message]:
        """Get chat history for session"""
        from src.cognitive.llm.conversation_engine import ConversationEngine
        
        engine = ConversationEngine()
        history = await engine.get_session_history(session_id, limit)
        
        return [
            Message(
                id=f"{session_id}_{i}",
                content=msg.get("content", ""),
                role=msg.get("role", "user"),
                timestamp=msg.get("timestamp", datetime.now().isoformat())
            )
            for i, msg in enumerate(history)
        ]
    
    @strawberry.field
    async def scan_sessions(self, limit: int = 10) -> List[ScanSession]:
        """Get recent scan sessions"""
        from src.autonomous.autonomous_brain import AutonomousBrain
        
        brain = AutonomousBrain()
        sessions = await brain.get_recent_sessions(limit)
        
        return [
            ScanSession(
                session_id=s["session_id"],
                target=s["target"],
                status=s["status"],
                vulnerabilities_found=len(s.get("vulnerabilities", [])),
                started_at=s["started_at"],
                completed_at=s.get("completed_at")
            )
            for s in sessions
        ]
    
    @strawberry.field
    async def scan_status(self, session_id: str) -> Optional[ScanSession]:
        """Get scan session status"""
        from src.autonomous.autonomous_brain import AutonomousBrain
        
        brain = AutonomousBrain()
        session = await brain.get_session(session_id)
        
        if not session:
            return None
        
        return ScanSession(
            session_id=session["session_id"],
            target=session["target"],
            status=session["status"],
            vulnerabilities_found=len(session.get("vulnerabilities", [])),
            started_at=session["started_at"],
            completed_at=session.get("completed_at")
        )
    
    @strawberry.field
    async def providers(self) -> List[Provider]:
        """Get available AI providers"""
        from src.cognitive.llm.model_router import ModelRouter
        
        router = ModelRouter()
        providers_info = await router.get_providers_status()
        
        return [
            Provider(
                name=p["name"],
                status=p["status"],
                models_count=len(p.get("models", []))
            )
            for p in providers_info
        ]
    
    @strawberry.field
    async def system_stats(self) -> SystemStats:
        """Get system statistics"""
        from src.api.middleware import get_request_stats
        import time
        
        stats = get_request_stats()
        
        return SystemStats(
            total_requests=stats.get("total_requests", 0),
            active_sessions=stats.get("active_sessions", 0),
            cache_hit_rate=stats.get("cache_hit_rate", 0.0),
            uptime_seconds=int(time.time() - stats.get("start_time", time.time()))
        )


@strawberry.type
class Mutation:
    @strawberry.mutation
    async def send_message(self, input: ChatInput) -> ConversationResponse:
        """Send message to AI"""
        from src.cognitive.llm.conversation_engine import ConversationEngine
        
        engine = ConversationEngine()
        result = await engine.process_conversation(
            message=input.message,
            session_id=input.session_id,
            model=input.model
        )
        
        return ConversationResponse(
            content=result["content"],
            intent=result.get("intent", "unknown"),
            session_id=input.session_id,
            timestamp=datetime.now().isoformat(),
            tokens=result.get("tokens")
        )
    
    @strawberry.mutation
    async def execute_code(self, input: CodeExecutionInput) -> ExecutionResult:
        """Execute code in multiple languages"""
        from src.execution.code_executor import get_executor
        
        executor = get_executor()
        result = await executor.execute(
            code=input.code,
            language=input.language,
            timeout=input.timeout,
            args=input.args
        )
        
        return ExecutionResult(
            stdout=result.get("stdout", ""),
            stderr=result.get("stderr", ""),
            return_code=result.get("return_code", -1),
            execution_time=result.get("execution_time", 0.0),
            language=input.language,
            success=result.get("success", False)
        )
    
    @strawberry.mutation
    async def start_scan(self, input: ScanInput) -> ScanSession:
        """Start autonomous security scan"""
        from src.autonomous.autonomous_brain import AutonomousBrain
        
        brain = AutonomousBrain()
        session = await brain.start_autonomous_session(
            target_url=input.target,
            mode=input.mode
        )
        
        return ScanSession(
            session_id=session["session_id"],
            target=input.target,
            status="started",
            vulnerabilities_found=0,
            started_at=datetime.now().isoformat()
        )
    
    @strawberry.mutation
    async def stop_scan(self, session_id: str) -> bool:
        """Stop autonomous scan"""
        from src.autonomous.autonomous_brain import AutonomousBrain
        
        brain = AutonomousBrain()
        return await brain.stop_session(session_id)
    
    @strawberry.mutation
    async def clear_cache(self) -> bool:
        """Clear Redis cache"""
        from src.cache.redis_cache import get_cache
        
        cache = get_cache()
        return cache.clear_all()


@strawberry.type
class Subscription:
    @strawberry.subscription
    async def scan_progress(self, session_id: str) -> ScanSession:
        """Subscribe to scan progress updates"""
        import asyncio
        from src.autonomous.autonomous_brain import AutonomousBrain
        
        brain = AutonomousBrain()
        
        while True:
            session = await brain.get_session(session_id)
            
            if not session:
                break
            
            yield ScanSession(
                session_id=session["session_id"],
                target=session["target"],
                status=session["status"],
                vulnerabilities_found=len(session.get("vulnerabilities", [])),
                started_at=session["started_at"],
                completed_at=session.get("completed_at")
            )
            
            if session["status"] in ["completed", "failed"]:
                break
            
            await asyncio.sleep(2)
    
    @strawberry.subscription
    async def llm_stream(self, prompt: str, model: str = "auto"):
        """Stream LLM responses"""
        from src.cognitive.llm.model_router import ModelRouter
        
        router = ModelRouter()
        
        async for chunk in router.stream_generate(prompt, model):
            yield chunk


# Create GraphQL schema
schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription
)
