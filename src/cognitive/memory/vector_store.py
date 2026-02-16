import os
os.environ["ANONYMIZED_TELEMETRY"] = "False"
os.environ["CHROMA_TELEMETRY_IMPL"] = "None"

import sys
from unittest.mock import MagicMock
sys.modules['posthog'] = MagicMock()

import chromadb
from chromadb.config import Settings as ChromaSettings
from chromadb.utils import embedding_functions
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import logging
from pathlib import Path

from src.config import settings

logger = logging.getLogger(__name__)


class VectorStore:
    def __init__(self, persist_directory: Optional[Path] = None):
        self.persist_directory = persist_directory or settings.chromadb_path
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        
        try:
            self.client = chromadb.PersistentClient(
                path=str(self.persist_directory),
                settings=ChromaSettings(
                    anonymized_telemetry=False,
                    allow_reset=True
                )
            )
            
            self._embedding_function = None
            self.collections = {}
            logger.info(f"VectorStore initialized at {self.persist_directory}")
        except Exception as e:
            logger.error(f"Failed to initialize VectorStore: {e}")
            raise
    
    @property
    def embedding_function(self):
        if self._embedding_function is None:
            self._embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            )
        return self._embedding_function
    
    def get_or_create_collection(self, collection_name: str) -> chromadb.Collection:
        if collection_name not in self.collections:
            self.collections[collection_name] = self.client.get_or_create_collection(
                name=collection_name,
                embedding_function=self.embedding_function,
                metadata={"created_at": datetime.utcnow().isoformat()}
            )
            logger.info(f"Collection '{collection_name}' ready")
        return self.collections[collection_name]
    
    def add_memory(
        self,
        collection_name: str,
        text: str,
        metadata: Optional[Dict] = None,
        memory_id: Optional[str] = None
    ) -> str:
        collection = self.get_or_create_collection(collection_name)
        
        if memory_id is None:
            memory_id = f"{collection_name}_{datetime.utcnow().timestamp()}"
        
        if metadata is None:
            metadata = {}
        
        metadata.update({
            "timestamp": datetime.utcnow().isoformat(),
            "source": collection_name
        })
        
        collection.add(
            documents=[text],
            metadatas=[metadata],
            ids=[memory_id]
        )
        
        logger.debug(f"Added memory '{memory_id}' to '{collection_name}'")
        return memory_id
    
    def add_memories_batch(
        self,
        collection_name: str,
        texts: List[str],
        metadatas: Optional[List[Dict]] = None,
        ids: Optional[List[str]] = None
    ) -> List[str]:
        collection = self.get_or_create_collection(collection_name)
        
        if ids is None:
            timestamp = datetime.utcnow().timestamp()
            ids = [f"{collection_name}_{timestamp}_{i}" for i in range(len(texts))]
        
        if metadatas is None:
            metadatas = [{} for _ in texts]
        
        current_time = datetime.utcnow().isoformat()
        for metadata in metadatas:
            metadata.update({
                "timestamp": current_time,
                "source": collection_name
            })
        
        collection.add(
            documents=texts,
            metadatas=metadatas,
            ids=ids
        )
        
        logger.info(f"Added {len(texts)} memories to '{collection_name}'")
        return ids
    
    def search_memories(
        self,
        collection_name: str,
        query: str,
        n_results: int = 5,
        where: Optional[Dict] = None,
        where_document: Optional[Dict] = None
    ) -> Dict:
        collection = self.get_or_create_collection(collection_name)
        
        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where,
            where_document=where_document
        )
        
        formatted_results = {
            "memories": [],
            "count": len(results["ids"][0]) if results["ids"] else 0
        }
        
        if results["ids"] and results["ids"][0]:
            for i in range(len(results["ids"][0])):
                formatted_results["memories"].append({
                    "id": results["ids"][0][i],
                    "text": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results["distances"] else None
                })
        
        logger.debug(f"Found {formatted_results['count']} memories for query in '{collection_name}'")
        return formatted_results
    
    def get_memory(self, collection_name: str, memory_id: str) -> Optional[Dict]:
        collection = self.get_or_create_collection(collection_name)
        
        try:
            result = collection.get(ids=[memory_id])
            if result["ids"]:
                return {
                    "id": result["ids"][0],
                    "text": result["documents"][0],
                    "metadata": result["metadatas"][0] if result["metadatas"] else {}
                }
        except Exception as e:
            logger.error(f"Error retrieving memory '{memory_id}': {e}")
        
        return None
    
    def update_memory(
        self,
        collection_name: str,
        memory_id: str,
        text: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        collection = self.get_or_create_collection(collection_name)
        
        try:
            existing = self.get_memory(collection_name, memory_id)
            if not existing:
                logger.warning(f"Memory '{memory_id}' not found in '{collection_name}'")
                return False
            
            update_text = text if text is not None else existing["text"]
            update_metadata = existing["metadata"].copy()
            if metadata:
                update_metadata.update(metadata)
            update_metadata["updated_at"] = datetime.utcnow().isoformat()
            
            collection.update(
                ids=[memory_id],
                documents=[update_text],
                metadatas=[update_metadata]
            )
            
            logger.info(f"Updated memory '{memory_id}' in '{collection_name}'")
            return True
        except Exception as e:
            logger.error(f"Error updating memory '{memory_id}': {e}")
            return False
    
    def delete_memory(self, collection_name: str, memory_id: str) -> bool:
        collection = self.get_or_create_collection(collection_name)
        
        try:
            collection.delete(ids=[memory_id])
            logger.info(f"Deleted memory '{memory_id}' from '{collection_name}'")
            return True
        except Exception as e:
            logger.error(f"Error deleting memory '{memory_id}': {e}")
            return False
    
    def delete_collection(self, collection_name: str) -> bool:
        try:
            self.client.delete_collection(name=collection_name)
            if collection_name in self.collections:
                del self.collections[collection_name]
            logger.info(f"Deleted collection '{collection_name}'")
            return True
        except Exception as e:
            logger.error(f"Error deleting collection '{collection_name}': {e}")
            return False
    
    def get_collection_stats(self, collection_name: str) -> Dict:
        collection = self.get_or_create_collection(collection_name)
        
        count = collection.count()
        metadata = collection.metadata
        
        return {
            "name": collection_name,
            "count": count,
            "metadata": metadata
        }
    
    def list_collections(self) -> List[str]:
        collections = self.client.list_collections()
        return [col.name for col in collections]
    
    def reset(self):
        self.client.reset()
        self.collections = {}
        logger.warning("VectorStore reset - all collections deleted")


class MemoryManager:
    def __init__(self):
        self.vector_store = VectorStore()
        self.user_memories = "user_memories"
        self.conversation_memories = "conversation_memories"
        self.fact_memories = "fact_memories"
        self.task_memories = "task_memories"
        
        logger.info("MemoryManager initialized")
    
    def remember(self, text: str, memory_type: str = "user", metadata: Optional[Dict] = None) -> str:
        collection_map = {
            "user": self.user_memories,
            "conversation": self.conversation_memories,
            "fact": self.fact_memories,
            "task": self.task_memories
        }
        
        collection = collection_map.get(memory_type, self.user_memories)
        
        if metadata is None:
            metadata = {}
        metadata["memory_type"] = memory_type
        
        return self.vector_store.add_memory(collection, text, metadata)
    
    def recall(
        self,
        query: str,
        memory_type: Optional[str] = None,
        n_results: int = 5
    ) -> List[Dict]:
        if memory_type:
            collection_map = {
                "user": self.user_memories,
                "conversation": self.conversation_memories,
                "fact": self.fact_memories,
                "task": self.task_memories
            }
            collections = [collection_map.get(memory_type, self.user_memories)]
        else:
            collections = [
                self.user_memories,
                self.conversation_memories,
                self.fact_memories,
                self.task_memories
            ]
        
        all_memories = []
        for collection in collections:
            results = self.vector_store.search_memories(collection, query, n_results)
            all_memories.extend(results["memories"])
        
        all_memories.sort(key=lambda x: x.get("distance", float("inf")))
        
        return all_memories[:n_results]
    
    def forget(self, memory_id: str, memory_type: str = "user") -> bool:
        collection_map = {
            "user": self.user_memories,
            "conversation": self.conversation_memories,
            "fact": self.fact_memories,
            "task": self.task_memories
        }
        
        collection = collection_map.get(memory_type, self.user_memories)
        return self.vector_store.delete_memory(collection, memory_id)
    
    def get_stats(self) -> Dict:
        return {
            "user_memories": self.vector_store.get_collection_stats(self.user_memories),
            "conversation_memories": self.vector_store.get_collection_stats(self.conversation_memories),
            "fact_memories": self.vector_store.get_collection_stats(self.fact_memories),
            "task_memories": self.vector_store.get_collection_stats(self.task_memories)
        }
