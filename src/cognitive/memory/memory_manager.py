"""
Memory Manager - Unified interface for all memory operations

Provides a simple API for storing and retrieving memories
across different memory types (conversations, facts, etc.)
"""

import logging
from typing import List, Dict, Optional, Any
from src.cognitive.memory.vector_store import get_vector_store

logger = logging.getLogger(__name__)


class MemoryManager:
    """
    Unified memory management interface
    
    Wraps VectorStore to provide simple remember/recall/forget API
    """
    
    def __init__(self):
        """Initialize memory manager"""
        self.vector_store = get_vector_store()
        logger.info("MemoryManager initialized")
    
    def remember(
        self,
        text: str,
        memory_type: str = "user",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Store a memory
        
        Args:
            text: Content to remember
            memory_type: Type of memory (user, conversation, fact, task)
            metadata: Additional metadata
            
        Returns:
            Memory ID
        """
        try:
            return self.vector_store.add_personal_fact(
                fact=text,
                category=memory_type,
                metadata=metadata or {}
            )
        except Exception as e:
            logger.error(f"Failed to remember: {e}")
            raise
    
    def recall(
        self,
        query: str,
        memory_type: Optional[str] = None,
        n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Recall memories based on query
        
        Args:
            query: Search query
            memory_type: Filter by type (optional)
            n_results: Number of results to return
            
        Returns:
            List of matching memories
        """
        try:
            collection_map = {
                "user": "personal_facts",
                "conversation": "conversations",
                "fact": "personal_facts",
                "task": "projects",
                "code": "code_patterns",
                "vulnerability": "vulnerabilities"
            }
            
            collection_name = collection_map.get(memory_type, "personal_facts") if memory_type else "personal_facts"
            
            return self.vector_store.search_memories(
                query=query,
                collection_name=collection_name,
                n_results=n_results
            )
        except Exception as e:
            logger.error(f"Failed to recall: {e}")
            raise
    
    def forget(
        self,
        memory_id: str,
        memory_type: str = "user"
    ) -> bool:
        """
        Delete a memory
        
        Args:
            memory_id: ID of memory to delete
            memory_type: Type of memory
            
        Returns:
            Success status
        """
        try:
            collection_map = {
                "user": "personal_facts",
                "conversation": "conversations",
                "fact": "personal_facts",
                "task": "projects",
                "code": "code_patterns",
                "vulnerability": "vulnerabilities"
            }
            
            collection_name = collection_map.get(memory_type, "personal_facts")
            
            self.vector_store.delete_memory(
                memory_id=memory_id,
                collection_name=collection_name
            )
            return True
        except Exception as e:
            logger.error(f"Failed to forget: {e}")
            raise
    
    def clear_all(self, memory_type: Optional[str] = None) -> bool:
        """
        Clear all memories or specific type
        
        Args:
            memory_type: Type to clear (None = all)
            
        Returns:
            Success status
        """
        try:
            if memory_type:
                collection_map = {
                    "user": "personal_facts",
                    "conversation": "conversations",
                    "fact": "personal_facts",
                    "task": "projects",
                    "code": "code_patterns",
                    "vulnerability": "vulnerabilities"
                }
                collection_name = collection_map.get(memory_type, "personal_facts")
                collection = self.vector_store.collections.get(collection_name)
                if collection:
                    collection.delete()
                return True
            else:
                for collection in self.vector_store.collections.values():
                    try:
                        collection.delete()
                    except:
                        pass
                return True
        except Exception as e:
            logger.error(f"Failed to clear memories: {e}")
            raise
