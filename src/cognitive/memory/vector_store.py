"""
Vector Store - Long-term Memory System

ChromaDB-powered vector storage for Jarvis-like memory:
- Remembers conversations, projects, code patterns
- Enables semantic search across all memories
- Supports multiple collections (conversations, projects, code, bugs)

Boss, ab Aether ko sab yaad rahega!
"""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
import json
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class VectorStore:
    """
    Long-term memory using ChromaDB vector database
    
    Collections:
    - conversations: Chat history with embeddings
    - projects: Bug bounty projects, coding projects
    - code_patterns: Coding style, preferences, snippets
    - vulnerabilities: Found bugs, exploitation techniques
    """
    
    def __init__(
        self,
        persist_directory: Optional[str] = None,
        embedding_model: str = "all-MiniLM-L6-v2"
    ):
        """
        Initialize vector store
        
        Args:
            persist_directory: Where to store the database (default: data/memory/chroma)
            embedding_model: Sentence transformer model for embeddings
        """
        if persist_directory is None:
            persist_directory = str(Path("data/memory/chroma").absolute())
        
        os.makedirs(persist_directory, exist_ok=True)
        
        self.client = chromadb.Client(Settings(
            chroma_db_impl="duckdb+parquet",
            persist_directory=persist_directory
        ))
        
        self.embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=embedding_model
        )
        
        self.collections = {}
        self._initialize_collections()
        
        logger.info(f"VectorStore initialized - Memory path: {persist_directory}")
    
    def _initialize_collections(self):
        """Initialize all memory collections"""
        collection_configs = {
            "conversations": "User conversations and interactions",
            "projects": "Bug bounty and coding projects",
            "code_patterns": "Coding style, preferences, and snippets",
            "vulnerabilities": "Discovered vulnerabilities and techniques",
            "personal_facts": "User preferences, habits, and personal info"
        }
        
        for name, description in collection_configs.items():
            try:
                self.collections[name] = self.client.get_or_create_collection(
                    name=name,
                    embedding_function=self.embedding_function,
                    metadata={"description": description}
                )
                logger.info(f"Collection '{name}' ready")
            except Exception as e:
                logger.error(f"Failed to create collection '{name}': {e}")
    
    def add_conversation(
        self,
        user_message: str,
        ai_response: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Store conversation in memory
        
        Args:
            user_message: What user said
            ai_response: What AI responded
            metadata: Additional context (timestamp, session_id, etc.)
            
        Returns:
            Memory ID
        """
        timestamp = datetime.now().isoformat()
        
        combined_text = f"User: {user_message}\nAether: {ai_response}"
        
        meta = {
            "timestamp": timestamp,
            "user_message": user_message,
            "ai_response": ai_response,
            **(metadata or {})
        }
        
        memory_id = f"conv_{timestamp.replace(':', '-').replace('.', '-')}"
        
        self.collections["conversations"].add(
            documents=[combined_text],
            metadatas=[meta],
            ids=[memory_id]
        )
        
        logger.info(f"Conversation stored: {memory_id}")
        return memory_id
    
    def add_project(
        self,
        project_name: str,
        project_type: str,
        description: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Store project information
        
        Args:
            project_name: Name of project
            project_type: "bug_bounty", "coding", "research", etc.
            description: Project details
            metadata: Additional data (stack, findings, etc.)
            
        Returns:
            Memory ID
        """
        timestamp = datetime.now().isoformat()
        
        meta = {
            "timestamp": timestamp,
            "project_name": project_name,
            "project_type": project_type,
            **(metadata or {})
        }
        
        memory_id = f"proj_{project_name.lower().replace(' ', '_')}_{timestamp[:10]}"
        
        self.collections["projects"].add(
            documents=[description],
            metadatas=[meta],
            ids=[memory_id]
        )
        
        logger.info(f"Project stored: {project_name}")
        return memory_id
    
    def add_code_pattern(
        self,
        pattern_name: str,
        code_snippet: str,
        language: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Store coding pattern/preference
        
        Args:
            pattern_name: Name/description of pattern
            code_snippet: The code itself
            language: Programming language
            metadata: Additional context
            
        Returns:
            Memory ID
        """
        timestamp = datetime.now().isoformat()
        
        meta = {
            "timestamp": timestamp,
            "pattern_name": pattern_name,
            "language": language,
            **(metadata or {})
        }
        
        memory_id = f"code_{pattern_name.lower().replace(' ', '_')}_{timestamp[:10]}"
        
        self.collections["code_patterns"].add(
            documents=[f"{pattern_name}\n\n{code_snippet}"],
            metadatas=[meta],
            ids=[memory_id]
        )
        
        logger.info(f"Code pattern stored: {pattern_name}")
        return memory_id
    
    def add_vulnerability(
        self,
        vuln_type: str,
        target: str,
        description: str,
        exploitation_technique: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Store vulnerability finding
        
        Args:
            vuln_type: Type of vulnerability (IDOR, XSS, SQLi, etc.)
            target: Target domain/application
            description: Detailed description
            exploitation_technique: How it was exploited
            metadata: Additional data (severity, payout, etc.)
            
        Returns:
            Memory ID
        """
        timestamp = datetime.now().isoformat()
        
        meta = {
            "timestamp": timestamp,
            "vuln_type": vuln_type,
            "target": target,
            "exploitation_technique": exploitation_technique,
            **(metadata or {})
        }
        
        memory_id = f"vuln_{vuln_type.lower()}_{target.replace('.', '_')}_{timestamp[:10]}"
        
        full_text = f"""
Vulnerability: {vuln_type}
Target: {target}
Description: {description}
Exploitation: {exploitation_technique}
"""
        
        self.collections["vulnerabilities"].add(
            documents=[full_text],
            metadatas=[meta],
            ids=[memory_id]
        )
        
        logger.info(f"Vulnerability stored: {vuln_type} on {target}")
        return memory_id
    
    def add_personal_fact(
        self,
        fact_type: str,
        fact_content: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Store personal fact about user
        
        Args:
            fact_type: "preference", "habit", "skill", "goal", etc.
            fact_content: The actual fact
            metadata: Additional context
            
        Returns:
            Memory ID
        """
        timestamp = datetime.now().isoformat()
        
        meta = {
            "timestamp": timestamp,
            "fact_type": fact_type,
            **(metadata or {})
        }
        
        memory_id = f"fact_{fact_type}_{timestamp[:10]}"
        
        self.collections["personal_facts"].add(
            documents=[fact_content],
            metadatas=[meta],
            ids=[memory_id]
        )
        
        logger.info(f"Personal fact stored: {fact_type}")
        return memory_id
    
    def search_memories(
        self,
        query: str,
        collection_name: str = "conversations",
        n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Search memories using semantic similarity
        
        Args:
            query: Search query
            collection_name: Which collection to search
            n_results: Number of results to return
            
        Returns:
            List of matching memories with metadata
        """
        if collection_name not in self.collections:
            logger.error(f"Collection '{collection_name}' not found")
            return []
        
        try:
            results = self.collections[collection_name].query(
                query_texts=[query],
                n_results=n_results
            )
            
            memories = []
            for i in range(len(results['ids'][0])):
                memories.append({
                    "id": results['ids'][0][i],
                    "content": results['documents'][0][i],
                    "metadata": results['metadatas'][0][i],
                    "distance": results['distances'][0][i] if 'distances' in results else None
                })
            
            logger.info(f"Found {len(memories)} memories for query: {query[:50]}")
            return memories
        
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    def search_all_collections(
        self,
        query: str,
        n_results: int = 3
    ) -> Dict[str, List[Dict]]:
        """
        Search across all collections
        
        Args:
            query: Search query
            n_results: Results per collection
            
        Returns:
            Dict of collection_name -> memories
        """
        all_results = {}
        
        for collection_name in self.collections.keys():
            results = self.search_memories(query, collection_name, n_results)
            if results:
                all_results[collection_name] = results
        
        return all_results
    
    def get_recent_memories(
        self,
        collection_name: str = "conversations",
        n_results: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get most recent memories from a collection
        
        Args:
            collection_name: Which collection
            n_results: Number of results
            
        Returns:
            List of recent memories (sorted by timestamp)
        """
        try:
            collection = self.collections[collection_name]
            
            all_data = collection.get()
            
            if not all_data['ids']:
                return []
            
            memories = []
            for i in range(len(all_data['ids'])):
                memories.append({
                    "id": all_data['ids'][i],
                    "content": all_data['documents'][i],
                    "metadata": all_data['metadatas'][i]
                })
            
            memories.sort(
                key=lambda x: x['metadata'].get('timestamp', ''),
                reverse=True
            )
            
            return memories[:n_results]
        
        except Exception as e:
            logger.error(f"Failed to get recent memories: {e}")
            return []
    
    def delete_memory(self, memory_id: str, collection_name: str) -> bool:
        """Delete a specific memory"""
        try:
            self.collections[collection_name].delete(ids=[memory_id])
            logger.info(f"Deleted memory: {memory_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete memory: {e}")
            return False
    
    def get_stats(self) -> Dict[str, int]:
        """Get memory statistics"""
        stats = {}
        
        for name, collection in self.collections.items():
            try:
                count = collection.count()
                stats[name] = count
            except:
                stats[name] = 0
        
        return stats
    
    def persist(self):
        """Persist all changes to disk"""
        try:
            self.client.persist()
            logger.info("Vector store persisted to disk")
        except Exception as e:
            logger.error(f"Failed to persist: {e}")


_vector_store_instance = None

def get_vector_store() -> VectorStore:
    """Get global vector store instance"""
    global _vector_store_instance
    
    if _vector_store_instance is None:
        _vector_store_instance = VectorStore()
    
    return _vector_store_instance


logger.info("Vector Store module loaded - Long-term memory ready!")
