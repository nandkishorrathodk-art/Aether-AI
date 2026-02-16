import sqlite3
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import json
import logging

from src.config import settings
from src.cognitive.memory.vector_store import VectorStore

logger = logging.getLogger(__name__)


class ConversationHistory:
    def __init__(self, db_path: Optional[Path] = None, vector_store: Optional[VectorStore] = None):
        self.db_path = db_path or settings.conversation_history_db
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.vector_store = vector_store or VectorStore()
        self.conversation_collection = "conversation_memories"
        
        self._init_database()
        logger.info(f"ConversationHistory initialized at {self.db_path}")
    
    def _init_database(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    metadata TEXT,
                    embedding_id TEXT,
                    is_important BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_session_id ON conversations(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON conversations(created_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_is_important ON conversations(is_important)")
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    title TEXT,
                    summary TEXT,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_activity_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    message_count INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT 1
                )
            """)
            
            conn.commit()
            logger.debug("Database tables initialized")
    
    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: Optional[Dict] = None,
        auto_embed: bool = True
    ) -> int:
        embedding_id = None
        
        if auto_embed and len(content) > 20:
            is_important = self._is_important_message(content, metadata)
            
            if is_important:
                try:
                    embed_metadata = metadata.copy() if metadata else {}
                    embed_metadata.update({
                        "session_id": session_id,
                        "role": role,
                        "is_important": True
                    })
                    
                    embedding_id = self.vector_store.add_memory(
                        self.conversation_collection,
                        content,
                        embed_metadata
                    )
                except Exception as e:
                    logger.error(f"Failed to embed message: {e}")
        
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO conversations (session_id, role, content, metadata, embedding_id, is_important)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                role,
                content,
                json.dumps(metadata) if metadata else None,
                embedding_id,
                1 if embedding_id else 0
            ))
            
            message_id = cursor.lastrowid
            
            cursor.execute("""
                INSERT INTO sessions (session_id, last_activity_at, message_count)
                VALUES (?, CURRENT_TIMESTAMP, 1)
                ON CONFLICT(session_id) DO UPDATE SET
                    last_activity_at = CURRENT_TIMESTAMP,
                    message_count = message_count + 1
            """, (session_id,))
            
            conn.commit()
        
        logger.debug(f"Added message {message_id} to session {session_id}")
        return message_id
    
    def _is_important_message(self, content: str, metadata: Optional[Dict] = None) -> bool:
        if metadata and metadata.get("force_important"):
            return True
        
        important_keywords = [
            "remember", "important", "preference", "like", "dislike",
            "always", "never", "don't", "do not", "my", "i am",
            "favorite", "hate", "love", "task", "remind", "schedule"
        ]
        
        content_lower = content.lower()
        
        if any(keyword in content_lower for keyword in important_keywords):
            return True
        
        if len(content) > 100:
            return True
        
        return False
    
    def get_session_history(
        self,
        session_id: str,
        limit: Optional[int] = None,
        include_metadata: bool = False
    ) -> List[Dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT id, role, content, metadata, is_important, created_at
                FROM conversations
                WHERE session_id = ?
                ORDER BY created_at ASC
            """
            
            if limit:
                query += f" LIMIT {limit}"
            
            cursor.execute(query, (session_id,))
            rows = cursor.fetchall()
        
        messages = []
        for row in rows:
            message = {
                "id": row["id"],
                "role": row["role"],
                "content": row["content"],
                "is_important": bool(row["is_important"]),
                "created_at": row["created_at"]
            }
            
            if include_metadata and row["metadata"]:
                message["metadata"] = json.loads(row["metadata"])
            
            messages.append(message)
        
        return messages
    
    def get_recent_context(
        self,
        session_id: str,
        max_messages: int = 10
    ) -> List[Dict]:
        messages = self.get_session_history(session_id)
        
        if len(messages) <= max_messages:
            return [{"role": msg["role"], "content": msg["content"]} for msg in messages]
        
        return [
            {"role": msg["role"], "content": msg["content"]}
            for msg in messages[-max_messages:]
        ]
    
    def search_relevant_context(
        self,
        query: str,
        session_id: Optional[str] = None,
        n_results: int = 5
    ) -> List[Dict]:
        where_filter = {"session_id": session_id} if session_id else None
        
        results = self.vector_store.search_memories(
            self.conversation_collection,
            query,
            n_results=n_results,
            where=where_filter
        )
        
        return results.get("memories", [])
    
    def get_rag_context(
        self,
        session_id: str,
        current_query: str,
        max_recent: int = 5,
        max_relevant: int = 3
    ) -> Dict:
        recent_messages = self.get_recent_context(session_id, max_recent)
        
        relevant_memories = self.search_relevant_context(
            current_query,
            session_id=session_id,
            n_results=max_relevant
        )
        
        return {
            "recent_context": recent_messages,
            "relevant_context": relevant_memories,
            "context_summary": self._generate_context_summary(recent_messages, relevant_memories)
        }
    
    def _generate_context_summary(
        self,
        recent: List[Dict],
        relevant: List[Dict]
    ) -> str:
        summary_parts = []
        
        if recent:
            summary_parts.append(f"Recent conversation: {len(recent)} messages")
        
        if relevant:
            summary_parts.append(f"Relevant memories: {len(relevant)} found")
        
        return "; ".join(summary_parts) if summary_parts else "No context available"
    
    def update_session_info(
        self,
        session_id: str,
        title: Optional[str] = None,
        summary: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> bool:
        updates = []
        params = []
        
        if title:
            updates.append("title = ?")
            params.append(title)
        
        if summary:
            updates.append("summary = ?")
            params.append(summary)
        
        if user_id:
            updates.append("user_id = ?")
            params.append(user_id)
        
        if not updates:
            return False
        
        params.append(session_id)
        
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE sessions
                SET {', '.join(updates)}
                WHERE session_id = ?
            """, params)
            conn.commit()
            
            affected = cursor.rowcount
        
        logger.info(f"Updated session {session_id}: {affected} rows affected")
        return affected > 0
    
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM sessions WHERE session_id = ?
            """, (session_id,))
            
            row = cursor.fetchone()
        
        if row:
            return {
                "session_id": row["session_id"],
                "user_id": row["user_id"],
                "title": row["title"],
                "summary": row["summary"],
                "started_at": row["started_at"],
                "last_activity_at": row["last_activity_at"],
                "message_count": row["message_count"],
                "is_active": bool(row["is_active"])
            }
        
        return None
    
    def list_sessions(
        self,
        user_id: Optional[str] = None,
        active_only: bool = True,
        limit: int = 50
    ) -> List[Dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT * FROM sessions WHERE 1=1"
            params = []
            
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            
            if active_only:
                query += " AND is_active = 1"
            
            query += " ORDER BY last_activity_at DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
        
        return [dict(row) for row in rows]
    
    def delete_session(self, session_id: str) -> bool:
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM conversations WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            
            conn.commit()
            affected = cursor.rowcount
        
        logger.info(f"Deleted session {session_id}: {affected} session records removed")
        return affected > 0
    
    def delete_old_sessions(self, days: int = 30) -> int:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT session_id FROM sessions
                WHERE last_activity_at < ? AND is_active = 0
            """, (cutoff_date.isoformat(),))
            
            old_sessions = [row[0] for row in cursor.fetchall()]
            
            for session_id in old_sessions:
                cursor.execute("DELETE FROM conversations WHERE session_id = ?", (session_id,))
            
            cursor.execute("""
                DELETE FROM sessions
                WHERE last_activity_at < ? AND is_active = 0
            """, (cutoff_date.isoformat(),))
            
            conn.commit()
        
        logger.info(f"Deleted {len(old_sessions)} old sessions")
        return len(old_sessions)
    
    def get_statistics(self) -> Dict:
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM sessions")
            total_sessions = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM sessions WHERE is_active = 1")
            active_sessions = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM conversations")
            total_messages = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM conversations WHERE is_important = 1")
            important_messages = cursor.fetchone()[0]
        
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "total_messages": total_messages,
            "important_messages": important_messages,
            "embedded_messages": important_messages
        }
