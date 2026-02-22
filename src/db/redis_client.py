from loguru import logger
import os
import redis.asyncio as redis

# Placeholder for Phase 1
class RedisManager:
    def __init__(self):
        self.connected = False
        self.url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.client = None

    async def connect(self):
        try:
            logger.info(f"Connecting to Redis at {self.url}...")
            self.client = redis.from_url(self.url)
            # await self.client.ping() # uncomment when redis is running
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            return False

    async def disconnect(self):
        if self.client:
            await self.client.aclose()
        self.connected = False
        logger.info("Disconnected from Redis.")

redis_client = RedisManager()
