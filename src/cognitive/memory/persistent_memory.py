"""
Persistent Memory Manager (Upgrade #1: Better Memory)

Wraps ChromaDB VectorStore with:
- Auto-save every conversation to persistent storage
- Smart fact extraction from conversations (user preferences, projects)
- SQLite fallback if ChromaDB unavailable
- Cross-session memory retrieval

Usage:
    mem = get_memory_manager()
    mem.remember("User prefers dark themes")
    facts = mem.recall("what does user prefer?")
"""

import json
import logging
import sqlite3
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Default storage path ──────────────────────────────────────────────────────
MEMORY_DIR = Path("data/memory")
SQLITE_PATH = MEMORY_DIR / "aether_memory.db"


class PersistentMemoryManager:
    """
    Unified long-term memory with ChromaDB + SQLite fallback.
    
    Collections:
    - facts       : User preferences, skills, goals
    - projects    : Active bug bounty / code projects  
    - sessions    : Summarised past sessions
    - bugs_found  : All vulnerabilities found
    """

    def __init__(self):
        MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        self._vector_store = None
        self._sqlite_conn = None
        self._init_storage()
        logger.info("🧠 Persistent Memory Manager initialized")

    # ── Init helpers ──────────────────────────────────────────────────────────
    def _init_storage(self):
        """Try ChromaDB first, fall back to SQLite"""
        try:
            from src.cognitive.memory.vector_store import get_vector_store
            self._vector_store = get_vector_store()
            logger.info("✅ Using ChromaDB for long-term memory")
        except Exception as e:
            logger.warning(f"ChromaDB unavailable ({e}), using SQLite fallback")
            self._init_sqlite()

    def _init_sqlite(self):
        """Initialize SQLite as memory fallback"""
        self._sqlite_conn = sqlite3.connect(str(SQLITE_PATH), check_same_thread=False)
        c = self._sqlite_conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS memories (
                id TEXT PRIMARY KEY,
                category TEXT,
                content TEXT,
                metadata TEXT,
                created_at TEXT
            )
        """)
        self._sqlite_conn.commit()
        logger.info(f"SQLite memory initialized at {SQLITE_PATH}")

    # ── Core API ──────────────────────────────────────────────────────────────
    def remember(self, content: str, category: str = "fact", metadata: Optional[Dict] = None):
        """
        Store any piece of information permanently.
        
        Args:
            content: What to remember
            category: "fact", "project", "bug", "session", "preference"
            metadata: Extra context dict
        """
        mem_id = f"{category}_{datetime.now().timestamp()}"
        meta = metadata or {}
        meta["category"] = category
        meta["timestamp"] = datetime.now().isoformat()

        if self._vector_store:
            try:
                if category in ("fact", "preference"):
                    self._vector_store.add_personal_fact(
                        fact_type=category,
                        fact_content=content,
                        metadata=meta
                    )
                elif category == "bug":
                    self._vector_store.add_memory(
                        collection_name="vulnerabilities",
                        text=content,
                        metadata=meta,
                        memory_id=mem_id
                    )
                else:
                    self._vector_store.add_memory(
                        collection_name="conversations",
                        text=content,
                        metadata=meta,
                        memory_id=mem_id
                    )
                logger.info(f"💾 Stored [{category}]: {content[:80]}")
                return mem_id
            except Exception as e:
                logger.error(f"ChromaDB store failed: {e}")

        # SQLite fallback
        if self._sqlite_conn:
            c = self._sqlite_conn.cursor()
            c.execute(
                "INSERT OR REPLACE INTO memories VALUES (?,?,?,?,?)",
                (mem_id, category, content, json.dumps(meta), meta["timestamp"])
            )
            self._sqlite_conn.commit()
            return mem_id

        return None

    def recall(self, query: str, category: Optional[str] = None, limit: int = 5) -> List[Dict]:
        """
        Semantically search memories.
        
        Args:
            query: What to search for
            category: Optional filter by category
            limit: Max results
            
        Returns:
            List of matching memory dicts
        """
        results = []

        if self._vector_store:
            try:
                where = {"category": category} if category else None
                raw = self._vector_store.search_memories(
                    collection_name="conversations",
                    query=query,
                    n_results=limit,
                    where=where
                )
                for i, doc in enumerate(raw.get("documents", [[]])[0]):
                    results.append({
                        "content": doc,
                        "metadata": raw.get("metadatas", [[]])[0][i] if raw.get("metadatas") else {}
                    })
                return results
            except Exception as e:
                logger.error(f"ChromaDB recall failed: {e}")

        # SQLite fallback
        if self._sqlite_conn:
            c = self._sqlite_conn.cursor()
            if category:
                rows = c.execute(
                    "SELECT content, metadata FROM memories WHERE category=? LIMIT ?",
                    (category, limit)
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT content, metadata FROM memories LIMIT ?",
                    (limit,)
                ).fetchall()
            for row in rows:
                results.append({"content": row[0], "metadata": json.loads(row[1])})

        return results

    def save_conversation(self, user_msg: str, ai_response: str, session_id: str = "default"):
        """Auto-save every conversation exchange"""
        if self._vector_store:
            try:
                self._vector_store.add_conversation(
                    user_message=user_msg,
                    ai_response=ai_response,
                    metadata={"session_id": session_id}
                )
                return
            except Exception as e:
                logger.error(f"Conversation save failed: {e}")

        # SQLite fallback
        content = f"User: {user_msg}\nAether: {ai_response}"
        self.remember(content, category="session", metadata={"session_id": session_id})

    def get_relevant_context(self, query: str) -> str:
        """
        Get formatted memory context for LLM injection.
        Returns a string to prepend to the system prompt.
        """
        memories = self.recall(query, limit=4)
        if not memories:
            return ""

        lines = ["[MEMORY CONTEXT - relevant past interactions]:"]
        for mem in memories:
            lines.append(f"- {mem['content'][:200]}")
        return "\n".join(lines)

    def remember_bug(self, target: str, vuln_type: str, description: str):
        """Shortcut to save a found vulnerability"""
        content = f"Bug found on {target}: {vuln_type} - {description}"
        self.remember(content, category="bug", metadata={
            "target": target,
            "type": vuln_type
        })

    def remember_user_preference(self, preference: str):
        """Shortcut to save user preference"""
        self.remember(preference, category="preference")


# ── Global singleton ──────────────────────────────────────────────────────────
_memory_manager: Optional[PersistentMemoryManager] = None


def get_memory_manager() -> PersistentMemoryManager:
    global _memory_manager
    if _memory_manager is None:
        _memory_manager = PersistentMemoryManager()
    return _memory_manager


logger.info("🧠 Persistent Memory Manager module loaded")
