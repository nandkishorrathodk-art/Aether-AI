from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, String, Integer, DateTime, JSON, Boolean, Text, Float
from datetime import datetime
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

Base = declarative_base()


class Conversation(Base):
    """Store chat conversations"""
    __tablename__ = "conversations"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(255), index=True, nullable=False)
    user_id = Column(String(255), index=True, nullable=False)
    message = Column(Text, nullable=False)
    role = Column(String(50), nullable=False)
    model = Column(String(100))
    tokens = Column(Integer)
    cost = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class ScanResult(Base):
    """Store autonomous scan results"""
    __tablename__ = "scan_results"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(255), unique=True, index=True, nullable=False)
    target = Column(String(500), nullable=False)
    status = Column(String(50), nullable=False)
    mode = Column(String(50))
    vulnerabilities = Column(JSON)
    metadata = Column(JSON)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime)


class Vulnerability(Base):
    """Store found vulnerabilities"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_session_id = Column(String(255), index=True, nullable=False)
    title = Column(String(500), nullable=False)
    severity = Column(String(50), index=True, nullable=False)
    description = Column(Text)
    url = Column(String(1000))
    evidence = Column(JSON)
    cvss_score = Column(Float)
    status = Column(String(50), default="new")
    found_at = Column(DateTime, default=datetime.utcnow, index=True)


class ExecutionLog(Base):
    """Store code execution logs"""
    __tablename__ = "execution_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), index=True, nullable=False)
    language = Column(String(50), nullable=False)
    code_hash = Column(String(64), index=True)
    success = Column(Boolean, nullable=False)
    execution_time = Column(Float)
    stdout = Column(Text)
    stderr = Column(Text)
    return_code = Column(Integer)
    executed_at = Column(DateTime, default=datetime.utcnow, index=True)


class APIUsage(Base):
    """Track API usage and costs"""
    __tablename__ = "api_usage"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(255), index=True, nullable=False)
    endpoint = Column(String(255), nullable=False)
    method = Column(String(10))
    provider = Column(String(100))
    model = Column(String(100))
    tokens_used = Column(Integer)
    cost = Column(Float)
    response_time = Column(Float)
    status_code = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class PostgresManager:
    """
    Ultra-fast PostgreSQL manager with async support
    Features:
    - Async operations
    - Connection pooling
    - Auto-reconnect
    - Query optimization
    """
    
    def __init__(
        self,
        database_url: str = "postgresql+asyncpg://aether:password@localhost:5432/aether_db"
    ):
        self.database_url = database_url
        self.engine = None
        self.session_maker = None
        self.enabled = False
        
        try:
            self._initialize()
        except Exception as e:
            logger.warning(f"PostgreSQL initialization failed: {e}")
    
    def _initialize(self):
        """Initialize database connection"""
        self.engine = create_async_engine(
            self.database_url,
            echo=False,
            pool_size=20,
            max_overflow=40,
            pool_pre_ping=True
        )
        
        self.session_maker = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        self.enabled = True
        logger.info("PostgreSQL manager initialized")
    
    async def create_tables(self):
        """Create all tables"""
        if not self.enabled:
            return
        
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("PostgreSQL tables created")
    
    async def get_session(self) -> AsyncSession:
        """Get database session"""
        return self.session_maker()
    
    # Conversation methods
    
    async def save_conversation(
        self,
        session_id: str,
        user_id: str,
        message: str,
        role: str,
        model: Optional[str] = None,
        tokens: Optional[int] = None,
        cost: Optional[float] = None
    ):
        """Save conversation message"""
        if not self.enabled:
            return
        
        async with await self.get_session() as session:
            conv = Conversation(
                session_id=session_id,
                user_id=user_id,
                message=message,
                role=role,
                model=model,
                tokens=tokens,
                cost=cost
            )
            session.add(conv)
            await session.commit()
    
    async def get_conversation_history(
        self,
        session_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get conversation history"""
        if not self.enabled:
            return []
        
        from sqlalchemy import select
        
        async with await self.get_session() as session:
            result = await session.execute(
                select(Conversation)
                .where(Conversation.session_id == session_id)
                .order_by(Conversation.created_at.desc())
                .limit(limit)
            )
            convs = result.scalars().all()
            
            return [
                {
                    "message": c.message,
                    "role": c.role,
                    "model": c.model,
                    "tokens": c.tokens,
                    "created_at": c.created_at.isoformat()
                }
                for c in reversed(convs)
            ]
    
    # Scan methods
    
    async def save_scan_result(
        self,
        session_id: str,
        target: str,
        status: str,
        mode: str,
        vulnerabilities: List[Dict],
        metadata: Dict
    ):
        """Save scan result"""
        if not self.enabled:
            return
        
        async with await self.get_session() as session:
            scan = ScanResult(
                session_id=session_id,
                target=target,
                status=status,
                mode=mode,
                vulnerabilities=vulnerabilities,
                metadata=metadata,
                completed_at=datetime.utcnow() if status == "completed" else None
            )
            session.add(scan)
            await session.commit()
    
    async def save_vulnerability(
        self,
        scan_session_id: str,
        title: str,
        severity: str,
        description: str,
        url: str,
        evidence: Dict,
        cvss_score: Optional[float] = None
    ):
        """Save vulnerability"""
        if not self.enabled:
            return
        
        async with await self.get_session() as session:
            vuln = Vulnerability(
                scan_session_id=scan_session_id,
                title=title,
                severity=severity,
                description=description,
                url=url,
                evidence=evidence,
                cvss_score=cvss_score
            )
            session.add(vuln)
            await session.commit()
    
    # Execution log methods
    
    async def log_execution(
        self,
        user_id: str,
        language: str,
        code_hash: str,
        success: bool,
        execution_time: float,
        stdout: str,
        stderr: str,
        return_code: int
    ):
        """Log code execution"""
        if not self.enabled:
            return
        
        async with await self.get_session() as session:
            log = ExecutionLog(
                user_id=user_id,
                language=language,
                code_hash=code_hash,
                success=success,
                execution_time=execution_time,
                stdout=stdout[:10000],  # Truncate long outputs
                stderr=stderr[:10000],
                return_code=return_code
            )
            session.add(log)
            await session.commit()
    
    # Analytics
    
    async def get_api_usage_stats(
        self,
        user_id: Optional[str] = None,
        days: int = 7
    ) -> Dict[str, Any]:
        """Get API usage statistics"""
        if not self.enabled:
            return {}
        
        from sqlalchemy import select, func
        from datetime import timedelta
        
        since = datetime.utcnow() - timedelta(days=days)
        
        async with await self.get_session() as session:
            query = select(
                func.count(APIUsage.id).label("total_requests"),
                func.sum(APIUsage.tokens_used).label("total_tokens"),
                func.sum(APIUsage.cost).label("total_cost"),
                func.avg(APIUsage.response_time).label("avg_response_time")
            ).where(APIUsage.created_at >= since)
            
            if user_id:
                query = query.where(APIUsage.user_id == user_id)
            
            result = await session.execute(query)
            row = result.first()
            
            return {
                "total_requests": row.total_requests or 0,
                "total_tokens": row.total_tokens or 0,
                "total_cost": float(row.total_cost or 0),
                "avg_response_time": float(row.avg_response_time or 0)
            }


# Singleton
_manager = None

def get_postgres() -> PostgresManager:
    global _manager
    if _manager is None:
        _manager = PostgresManager()
    return _manager
