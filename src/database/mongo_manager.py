from motor.motor_asyncio import AsyncIOMotorClient
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime
from bson import ObjectId

logger = logging.getLogger(__name__)


class MongoManager:
    """
    Ultra-fast MongoDB manager with async support
    Features:
    - Async operations
    - Connection pooling
    - Flexible schema
    - High performance
    Perfect for: Logs, sessions, cache, large documents
    """
    
    def __init__(
        self,
        connection_string: str = "mongodb://localhost:27017",
        database: str = "aether_db"
    ):
        self.connection_string = connection_string
        self.database_name = database
        self.client = None
        self.db = None
        self.enabled = False
        
        try:
            self._initialize()
        except Exception as e:
            logger.warning(f"MongoDB initialization failed: {e}")
    
    def _initialize(self):
        """Initialize MongoDB connection"""
        self.client = AsyncIOMotorClient(
            self.connection_string,
            serverSelectionTimeoutMS=2000
        )
        self.db = self.client[self.database_name]
        self.enabled = True
        logger.info(f"MongoDB manager initialized: {self.database_name}")
    
    # Collections
    
    @property
    def conversations(self):
        return self.db.conversations
    
    @property
    def scan_results(self):
        return self.db.scan_results
    
    @property
    def vulnerabilities(self):
        return self.db.vulnerabilities
    
    @property
    def execution_logs(self):
        return self.db.execution_logs
    
    @property
    def user_profiles(self):
        return self.db.user_profiles
    
    @property
    def api_logs(self):
        return self.db.api_logs
    
    # Conversation methods
    
    async def save_conversation_message(
        self,
        session_id: str,
        user_id: str,
        message: str,
        role: str,
        model: Optional[str] = None,
        tokens: Optional[int] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """Save conversation message"""
        if not self.enabled:
            return ""
        
        doc = {
            "session_id": session_id,
            "user_id": user_id,
            "message": message,
            "role": role,
            "model": model,
            "tokens": tokens,
            "metadata": metadata or {},
            "created_at": datetime.utcnow()
        }
        
        result = await self.conversations.insert_one(doc)
        return str(result.inserted_id)
    
    async def get_conversation_history(
        self,
        session_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get conversation history"""
        if not self.enabled:
            return []
        
        cursor = self.conversations.find(
            {"session_id": session_id}
        ).sort("created_at", -1).limit(limit)
        
        messages = await cursor.to_list(length=limit)
        
        return [
            {
                "message": msg["message"],
                "role": msg["role"],
                "model": msg.get("model"),
                "tokens": msg.get("tokens"),
                "created_at": msg["created_at"].isoformat()
            }
            for msg in reversed(messages)
        ]
    
    # Scan methods
    
    async def save_scan_session(
        self,
        session_id: str,
        target: str,
        mode: str,
        config: Dict,
        user_id: str = "default"
    ) -> str:
        """Create new scan session"""
        if not self.enabled:
            return ""
        
        doc = {
            "session_id": session_id,
            "target": target,
            "mode": mode,
            "config": config,
            "user_id": user_id,
            "status": "started",
            "vulnerabilities": [],
            "progress": 0,
            "started_at": datetime.utcnow(),
            "completed_at": None
        }
        
        result = await self.scan_results.insert_one(doc)
        return str(result.inserted_id)
    
    async def update_scan_progress(
        self,
        session_id: str,
        progress: int,
        status: str,
        metadata: Optional[Dict] = None
    ):
        """Update scan progress"""
        if not self.enabled:
            return
        
        update = {
            "$set": {
                "progress": progress,
                "status": status,
                "updated_at": datetime.utcnow()
            }
        }
        
        if metadata:
            update["$set"]["metadata"] = metadata
        
        if status == "completed":
            update["$set"]["completed_at"] = datetime.utcnow()
        
        await self.scan_results.update_one(
            {"session_id": session_id},
            update
        )
    
    async def add_vulnerability(
        self,
        session_id: str,
        vulnerability: Dict
    ):
        """Add vulnerability to scan"""
        if not self.enabled:
            return
        
        vuln_doc = {
            **vulnerability,
            "session_id": session_id,
            "found_at": datetime.utcnow()
        }
        
        # Insert into vulnerabilities collection
        await self.vulnerabilities.insert_one(vuln_doc)
        
        # Also add to scan's vulnerability array
        await self.scan_results.update_one(
            {"session_id": session_id},
            {"$push": {"vulnerabilities": vulnerability}}
        )
    
    async def get_scan_session(self, session_id: str) -> Optional[Dict]:
        """Get scan session"""
        if not self.enabled:
            return None
        
        doc = await self.scan_results.find_one({"session_id": session_id})
        
        if doc:
            doc["_id"] = str(doc["_id"])
            if doc.get("started_at"):
                doc["started_at"] = doc["started_at"].isoformat()
            if doc.get("completed_at"):
                doc["completed_at"] = doc["completed_at"].isoformat()
        
        return doc
    
    # Execution logs
    
    async def log_code_execution(
        self,
        user_id: str,
        language: str,
        code: str,
        result: Dict,
        metadata: Optional[Dict] = None
    ) -> str:
        """Log code execution"""
        if not self.enabled:
            return ""
        
        doc = {
            "user_id": user_id,
            "language": language,
            "code": code[:5000],  # Truncate long code
            "result": {
                "stdout": result.get("stdout", "")[:5000],
                "stderr": result.get("stderr", "")[:5000],
                "return_code": result.get("return_code"),
                "execution_time": result.get("execution_time"),
                "success": result.get("success")
            },
            "metadata": metadata or {},
            "executed_at": datetime.utcnow()
        }
        
        result = await self.execution_logs.insert_one(doc)
        return str(result.inserted_id)
    
    # User profiles
    
    async def save_user_profile(
        self,
        user_id: str,
        profile_data: Dict
    ):
        """Save/update user profile"""
        if not self.enabled:
            return
        
        await self.user_profiles.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    **profile_data,
                    "updated_at": datetime.utcnow()
                },
                "$setOnInsert": {
                    "created_at": datetime.utcnow()
                }
            },
            upsert=True
        )
    
    async def get_user_profile(self, user_id: str) -> Optional[Dict]:
        """Get user profile"""
        if not self.enabled:
            return None
        
        return await self.user_profiles.find_one({"user_id": user_id})
    
    # Analytics
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        if not self.enabled:
            return {"enabled": False}
        
        return {
            "enabled": True,
            "total_conversations": await self.conversations.count_documents({}),
            "total_scans": await self.scan_results.count_documents({}),
            "total_vulnerabilities": await self.vulnerabilities.count_documents({}),
            "total_executions": await self.execution_logs.count_documents({}),
            "active_scans": await self.scan_results.count_documents({"status": "running"})
        }
    
    async def create_indexes(self):
        """Create performance indexes"""
        if not self.enabled:
            return
        
        # Conversations indexes
        await self.conversations.create_index([("session_id", 1), ("created_at", -1)])
        await self.conversations.create_index("user_id")
        
        # Scan results indexes
        await self.scan_results.create_index("session_id", unique=True)
        await self.scan_results.create_index([("user_id", 1), ("started_at", -1)])
        await self.scan_results.create_index("status")
        
        # Vulnerabilities indexes
        await self.vulnerabilities.create_index([("session_id", 1), ("found_at", -1)])
        await self.vulnerabilities.create_index("severity")
        
        # Execution logs indexes
        await self.execution_logs.create_index([("user_id", 1), ("executed_at", -1)])
        await self.execution_logs.create_index("language")
        
        # User profiles indexes
        await self.user_profiles.create_index("user_id", unique=True)
        
        logger.info("MongoDB indexes created")
    
    async def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")


# Singleton
_manager = None

def get_mongo() -> MongoManager:
    global _manager
    if _manager is None:
        _manager = MongoManager()
    return _manager
