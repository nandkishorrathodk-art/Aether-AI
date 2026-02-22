from loguru import logger
import os
import uuid
from typing import List, Dict, Any
# Note: In Phase 3 we introduce the actual qdrant_client, but mock execution if server is down.

try:
    from qdrant_client import AsyncQdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
    HAS_QDRANT = True
except ImportError:
    HAS_QDRANT = False

class QdrantClientWrapper:
    """
    Wrapper for Qdrant database operations.
    Handles graceful degradation if Qdrant is not running locally during Phase 3 dev.
    """
    def __init__(self):
        self.connected = False
        self.url = os.getenv("QDRANT_URL", "http://localhost:6333")
        self.client = None
        
        # In-memory mock storage for tests
        self._mock_storage = {}

    async def connect(self):
        logger.info(f"Attempting to connect to Qdrant at {self.url}...")
        if HAS_QDRANT:
            try:
                self.client = AsyncQdrantClient(url=self.url)
                # Attempt to get collections to verify connection
                await self.client.get_collections()
                self.connected = True
                logger.info("Successfully connected to Qdrant instance.")
            except Exception as e:
                logger.warning(f"Failed to connect to real Qdrant server: {e}. Falling back to mock memory.")
                self.connected = False
        else:
            logger.warning("qdrant-client not installed. Falling back to mock memory.")
            self.connected = False
            
        return True # We return True even on fallback so the app starts

    async def disconnect(self):
        if self.connected and self.client:
            await self.client.close()
        self.connected = False
        logger.info("Disconnected from Qdrant.")

    async def upsert(self, collection_name: str, item_id: str, vector: List[float], payload: Dict[str, Any]) -> bool:
        if self.connected:
            try:
                # Ensure collection exists
                collections = await self.client.get_collections()
                if not any(c.name == collection_name for c in collections.collections):
                    await self.client.create_collection(
                        collection_name=collection_name,
                        vectors_config=VectorParams(size=len(vector), distance=Distance.COSINE),
                    )
                
                # Upsert
                await self.client.upsert(
                    collection_name=collection_name,
                    points=[PointStruct(id=item_id, vector=vector, payload=payload)]
                )
                return True
            except Exception as e:
                logger.error(f"Qdrant upsert failed: {e}")
                return False
        else:
            # Mock behavior
            if collection_name not in self._mock_storage:
                self._mock_storage[collection_name] = {}
            self._mock_storage[collection_name][item_id] = {"vector": vector, "payload": payload}
            return True

    async def search(self, collection_name: str, query_vector: List[float], limit: int = 3) -> List[Dict[str, Any]]:
        if self.connected:
            try:
                results = await self.client.search(
                    collection_name=collection_name,
                    query_vector=query_vector,
                    limit=limit
                )
                return [{"id": r.id, "score": r.score, "payload": r.payload} for r in results]
            except Exception as e:
                logger.error(f"Qdrant search failed: {e}")
                return []
        else:
            # Mock behavior - just return everything we have up to the limit
            if collection_name in self._mock_storage:
                items = list(self._mock_storage[collection_name].values())
                return [{"id": "mock_id", "score": 1.0, "payload": item["payload"]} for item in items[:limit]]
            return []

vector_db = QdrantClientWrapper()
